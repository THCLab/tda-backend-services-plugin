# Acapy
from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    RequestContext,
    HandlerException,
)
from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.holder.base import HolderError, BaseHolder
from aries_cloudagent.aathcf.credentials import verify_proof

# Exceptions
from aries_cloudagent.storage.error import StorageNotFoundError


# Internal
from .message_types import *
from .models import ServiceIssueRecord
from ..models import ServiceRecord

# External
from collections import OrderedDict
import logging
import json

from aries_cloudagent.pdstorage_thcf.api import *
from aries_cloudagent.aathcf.utils import debug_handler

LOGGER = logging.getLogger(__name__)
SERVICE_USER_DATA_TABLE = "service_user_data_table"


async def application_handler(context, msg, connection_id):
    wallet: BaseWallet = await context.inject(BaseWallet)
    consent = msg.consent_credential
    consent = json.loads(consent, object_pairs_hook=OrderedDict)

    try:
        service: ServiceRecord = await ServiceRecord.retrieve_by_id(
            context, msg.service_id
        )
    except StorageNotFoundError as err:
        LOGGER.warn("%s", err)
        return ServiceIssueRecord.ISSUE_SERVICE_NOT_FOUND, None

    """

    Verify consent against these three vars from service requirements

    """
    data_dri = service.consent_dri
    cred_content = consent["credentialSubject"]
    is_malformed = cred_content["dri"] != data_dri

    if is_malformed:
        LOGGER.error(
            f"Ismalformed? {is_malformed} Incoming consent"
            f"credential doesn't match with service consent credential"
            f"Conditions: data dri {cred_content['dri'] != data_dri} "
        )
        return ServiceIssueRecord.ISSUE_REJECTED

    if not await verify_proof(wallet, consent):
        LOGGER.error(f"Credential failed the verification process {consent}")
        return ServiceIssueRecord.ISSUE_REJECTED

    print("msg.service_user_data:", msg.service_user_data)
    user_data_dri = await pds_save(
        context, msg.service_user_data, oca_schema_dri=service.service_schema_dri
    )
    assert user_data_dri == msg.service_user_data_dri, (
        user_data_dri,
        msg.service_user_data_dri,
    )

    issue = ServiceIssueRecord(
        state=ServiceIssueRecord.ISSUE_PENDING,
        author=ServiceIssueRecord.AUTHOR_OTHER,
        connection_id=connection_id,
        exchange_id=msg.exchange_id,
        service_id=msg.service_id,
        service_consent_match_id=msg.service_consent_match_id,
        service_user_data_dri=user_data_dri,
        label=service.label,
        their_public_did=msg.public_did,
    )

    await issue.user_consent_credential_pds_set(context, consent)
    await issue.save(context)
    return None, issue


async def application_response_handler(context, msg, connection_id):
    issue: ServiceIssueRecord = (
        await ServiceIssueRecord.retrieve_by_exchange_id_and_connection_id(
            context,
            msg.exchange_id,
            connection_id,
        )
    )

    credential = json.loads(msg.credential, object_pairs_hook=OrderedDict)

    promised_oca_dri = issue.service_schema_dri
    promised_data_dri = issue.service_user_data_dri
    promised_conset_match = issue.service_consent_match_id

    subject = credential["credentialSubject"]

    is_malformed = (
        subject["oca_schema_dri"] != promised_oca_dri
        or subject["oca_data_dri"] != promised_data_dri
        or subject["service_consent_match_id"] != promised_conset_match
    )

    if is_malformed:
        raise HandlerException(
            f"Incoming credential is malformed! \n"
            f"is_malformed ? {is_malformed} \n"
            f"promised_data_dri: {promised_data_dri} promised_conset_match: {promised_conset_match} \n"
            f"malformed credential {credential} \n"
        )

    try:
        holder: BaseHolder = await context.inject(BaseHolder)
        credential_id = await holder.store_credential(
            credential_definition={},
            credential_data=credential,
            credential_request_metadata={},
        )
    except HolderError as err:
        raise HandlerException(err.roll_up)

    issue.state = ServiceIssueRecord.ISSUE_CREDENTIAL_RECEIVED
    issue.credential_id = credential_id
    await issue.save(context)

    return credential_id


async def send_confirmation(context, responder, exchange_id, state=None):
    LOGGER.info("send confirmation %s", state)
    confirmation = Confirmation(
        exchange_id=exchange_id,
        state=state,
    )

    confirmation.assign_thread_from(context.message)
    await responder.send_reply(confirmation)


class ApplicationHandler(BaseHandler):
    """
    Handles the service application, saves it to storage and notifies the
    controller that a service application came.
    """

    async def handle(self, context: RequestContext, responder: BaseResponder):
        debug_handler(self._logger.debug, context, Application)
        err, issue = await application_handler(
            context, context.message, responder.connection_id
        )
        if not err:
            await responder.send_webhook(
                "services/application",
                {
                    "issue": issue.serialize(),
                    "issue_id": issue._id,
                },
            )
            err = ServiceIssueRecord.ISSUE_PENDING

        await send_confirmation(
            context,
            responder,
            context.message.exchange_id,
            err,
        )


class ApplicationResponseHandler(BaseHandler):
    """
    Handles the message with issued credential for given service.
    So makes sure the credential is correct and saves it
    """

    async def handle(self, context: RequestContext, responder: BaseResponder):
        debug_handler(self._logger.debug, context, ApplicationResponse)
        credential_id = await application_response_handler(
            context, context.message, responder.connection_id
        )
        await responder.send_webhook(
            "verifiable-services/credential-received",
            {
                "credential_id": credential_id,
                "connection_id": responder.connection_id,
            },
        )


class ConfirmationHandler(BaseHandler):
    """
    Handles the state updates in service exchange

    TODO: ProblemReport ? Maybe there is a better way to handle this.
    """

    async def handle(self, context: RequestContext, responder: BaseResponder):
        debug_handler(self._logger.debug, context, Confirmation)
        record: ServiceIssueRecord = (
            await ServiceIssueRecord.retrieve_by_exchange_id_and_connection_id(
                context,
                context.message.exchange_id,
                context.connection_record.connection_id,
            )
        )

        record.state = context.message.state
        record_id = await record.save(context, reason="Updated issue state")

        await responder.send_webhook(
            "verifiable-services/issue-state-update",
            {"state": record.state, "issue_id": record_id, "issue": record.serialize()},
        )
