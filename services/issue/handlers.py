# Acapy
from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    RequestContext,
    HandlerException,
)
from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.verifier.base import BaseVerifier
from aries_cloudagent.holder.base import HolderError, BaseHolder
from aries_cloudagent.aathcf.credentials import (
    verify_proof,
)

# Exceptions
from aries_cloudagent.storage.error import StorageDuplicateError, StorageNotFoundError
from aries_cloudagent.protocols.problem_report.v1_0.message import ProblemReport


# Internal
from ..util import generate_model_schema
from .message_types import *
from .models import ServiceIssueRecord
from ..models import ServiceRecord

# External
from asyncio import shield
from marshmallow import fields, Schema
from collections import OrderedDict
import logging
import hashlib
import uuid
import json

from aries_cloudagent.pdstorage_thcf.api import *
from aries_cloudagent.aathcf.utils import debug_handler
from ..util import verify_usage_policy

LOGGER = logging.getLogger(__name__)
SERVICE_USER_DATA_TABLE = "service_user_data_table"


async def send_confirmation(context, responder, exchange_id, state=None):
    """
    Create and send a Confirmation message,
    this updates the state of service exchange.
    """

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
        wallet: BaseWallet = await context.inject(BaseWallet)

        consent = context.message.consent_credential
        consent = json.loads(consent, object_pairs_hook=OrderedDict)

        try:
            service: ServiceRecord = (
                await ServiceRecord.retrieve_by_id_fully_serialized(
                    context, context.message.service_id
                )
            )
        except StorageNotFoundError as err:
            LOGGER.warn(err)
            await send_confirmation(
                context,
                responder,
                context.message.exchange_id,
                ServiceIssueRecord.ISSUE_SERVICE_NOT_FOUND,
            )
            return

        """

        Verify consent against these three vars from service requirements

        """
        namespace = service["consent_schema"]["oca_schema_namespace"]
        oca_dri = service["consent_schema"]["oca_schema_dri"]
        data_dri = service["consent_schema"]["oca_data_dri"]
        cred_content = consent["credentialSubject"]

        is_malformed = (
            cred_content["oca_data_dri"] != data_dri
            or cred_content["oca_schema_namespace"] != namespace
            or cred_content["oca_schema_dri"] != oca_dri
        )

        """
        Verify usage policy
        """

        # usage_policy_message = await verify_usage_policy(
        #     service["consent_schema"]["usage_policy"],
        #     consent["credentialSubject"]["usage_policy"],
        # )
        # if usage_policy_message.find("policies match") == -1:
        #     LOGGER.error("Policies dont match! %s", usage_policy_message)
        #     is_malformed = true

        """

        """

        if is_malformed:
            await send_confirmation(
                context,
                responder,
                context.message.exchange_id,
                ServiceIssueRecord.ISSUE_REJECTED,
            )
            raise HandlerException(
                f"Ismalformed? {is_malformed} Incoming consent"
                f"credential doesn't match with service consent credential"
                f"Conditions: data dri {cred_content['oca_data_dri'] != data_dri} "
                f"namespace {cred_content['oca_schema_namespace'] != namespace} "
                f"oca_dri {cred_content['oca_schema_dri'] != oca_dri}"
            )

        if not await verify_proof(wallet, consent):
            await send_confirmation(
                context,
                responder,
                context.message.exchange_id,
                ServiceIssueRecord.ISSUE_REJECTED,
            )
            raise HandlerException(
                f"Credential failed the verification process {consent}"
            )

        """

        Pack save confirm

        """

        metadata = {"oca_schema_dri": oca_dri, "table": SERVICE_USER_DATA_TABLE}
        user_data_dri = await save_string(
            context, context.message.service_user_data, json.dumps(metadata)
        )
        assert user_data_dri == context.message.service_user_data_dri

        issue = ServiceIssueRecord(
            state=ServiceIssueRecord.ISSUE_PENDING,
            author=ServiceIssueRecord.AUTHOR_OTHER,
            connection_id=context.connection_record.connection_id,
            exchange_id=context.message.exchange_id,
            service_id=context.message.service_id,
            service_consent_match_id=context.message.service_consent_match_id,
            service_user_data_dri=user_data_dri,
            service_schema=service["service_schema"],
            service_consent_schema=service["consent_schema"],
            user_consent_credential=consent,
            label=service["label"],
            their_public_did=context.message.public_did,
        )

        issue_id = await issue.save(context)

        await send_confirmation(
            context,
            responder,
            context.message.exchange_id,
            ServiceIssueRecord.ISSUE_PENDING,
        )

        await responder.send_webhook(
            "verifiable-services/incoming-pending-application",
            {
                "issue": issue.serialize(),
                "issue_id": issue_id,
            },
        )


class ApplicationResponseHandler(BaseHandler):
    """
    Handles the message with issued credential for given service.
    So makes sure the credential is correct and saves it
    """

    async def handle(self, context: RequestContext, responder: BaseResponder):
        debug_handler(self._logger.debug, context, ApplicationResponse)

        issue: ServiceIssueRecord = (
            await ServiceIssueRecord.retrieve_by_exchange_id_and_connection_id(
                context,
                context.message.exchange_id,
                context.connection_record.connection_id,
            )
        )

        cred_str = context.message.credential
        credential = json.loads(cred_str, object_pairs_hook=OrderedDict)

        """

        Check if we got(credential) what was *promised* by the service provider 

        """

        promised_oca_dri = issue.service_schema["oca_schema_dri"]
        promised_namespace = issue.service_schema["oca_schema_namespace"]
        promised_data_dri = issue.service_user_data_dri
        promised_conset_match = issue.service_consent_match_id

        subject = credential["credentialSubject"]

        is_malformed = (
            subject["oca_schema_dri"] != promised_oca_dri
            or subject["oca_schema_namespace"] != promised_namespace
            or subject["oca_data_dri"] != promised_data_dri
            or subject["service_consent_match_id"] != promised_conset_match
        )

        if is_malformed:
            raise HandlerException(
                f"Incoming credential is malformed! \n"
                f"is_malformed ? {is_malformed} \n"
                f"promised_oca_dri: {promised_oca_dri} promised_namespace: {promised_namespace} \n"
                f"promised_data_dri: {promised_data_dri} promised_conset_match: {promised_conset_match} \n"
                f"malformed credential {credential} \n"
            )

        """

        Check the proof and save

        """

        try:
            holder: BaseHolder = await context.inject(BaseHolder)
            credential_id = await holder.store_credential(
                credential_definition={},
                credential_data=credential,
                credential_request_metadata={},
            )
            self._logger.info("Stored Credential ID %s", credential_id)
        except HolderError as err:
            raise HandlerException(err.roll_up)

        issue.state = ServiceIssueRecord.ISSUE_CREDENTIAL_RECEIVED
        issue.credential_id = credential_id
        await issue.save(context)

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
