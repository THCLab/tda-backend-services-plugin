# Acapy
from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    RequestContext,
    HandlerException,
)
from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.verifier.base import BaseVerifier
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

LOGGER = logging.getLogger(__name__)


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
            service: ServiceRecord = await ServiceRecord.retrieve_by_id(
                context, context.message.service_id
            )
        except StorageNotFoundError:
            await send_confirmation(
                context,
                responder,
                context.message.exchange_id,
                ServiceIssueRecord.ISSUE_SERVICE_NOT_FOUND,
            )
            return

        """
        TODO: 
        Check DATA DRI ! Wild memes are happening
        """

        """

        Verify consent against these three vars from service requirements

        """
        namespace = service.consent_schema["oca_schema_namespace"]
        oca_dri = service.consent_schema["oca_schema_dri"]
        data_dri = service.consent_schema["data_dri"]
        cred_content = consent["credentialSubject"]

        LOGGER.info(
            f"Conditions:{cred_content['data_dri'] != data_dri}"
            f"{cred_content['oca_schema_namespace'] != namespace}"
            f"{cred_content['oca_schema_dri'] != oca_dri}"
            f"{cred_content['service_consent_match_id']}"
        )

        is_malformed = (
            cred_content["data_dri"] != data_dri
            or cred_content["oca_schema_namespace"] != namespace
            or cred_content["oca_schema_dri"] != oca_dri
        )

        if is_malformed:
            await send_confirmation(
                context,
                responder,
                context.message.exchange_id,
                ServiceIssueRecord.ISSUE_REJECTED,
            )
            assert (
                0
            ), f"Ismalformed? {is_malformed} Incoming consent credential doesn't match with service consent credential"

        if not await verify_proof(wallet, consent):
            await send_confirmation(
                context,
                responder,
                context.message.exchange_id,
                ServiceIssueRecord.ISSUE_REJECTED,
            )
            assert 0, "Credential failed the verification process"

        """

        Pack save confirm

        """

        issue = ServiceIssueRecord(
            state=ServiceIssueRecord.ISSUE_PENDING,
            author=ServiceIssueRecord.AUTHOR_OTHER,
            connection_id=context.connection_record.connection_id,
            exchange_id=context.message.exchange_id,
            service_id=context.message.service_id,
            service_consent_match_id=context.message.service_consent_match_id,
            issuer_data_dri_cache=context.message.data_dri,
            service_schema=service.service_schema,
            consent_schema=service.consent_schema,
            consent_credential=consent,
            label=service.label,
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
        TODO: 
        Check DATA DRI ! Wild memes are happening
        """

        """

        Check if we got(credential) what was *promised* by the service provider 

        """

        promised_oca_dri = issue.service_schema["oca_schema_dri"]
        promised_namespace = issue.service_schema["oca_schema_namespace"]
        promised_data_dri = issue.payload_dri
        promised_conset_match = issue.service_consent_match_id

        subject = credential["credentialSubject"]
        print(
            "SUBJECT",
            subject["oca_schema_dri"],
            subject["oca_schema_namespace"],
            subject["data_dri"],
            subject["service_consent_match_id"],
        )

        subject = credential["credentialSubject"]
        print(
            "Promised",
            promised_oca_dri,
            promised_namespace,
            promised_data_dri,
            promised_conset_match,
        )

        if subject["oca_schema_dri"] is not promised_oca_dri:
            raise HandlerException("promised_oca_dri")
        if subject["oca_schema_namespace"] is not promised_namespace:
            raise HandlerException("promised_namespace")
        if subject["data_dri"] is not promised_data_dri:
            raise HandlerException("promised_data_dri")
        if subject["service_consent_match_id"] is not promised_conset_match:
            raise HandlerException("promised_conset_match")

        is_cred_okay = (
            subject["oca_schema_dri"] is promised_oca_dri
            and subject["oca_schema_namespace"] is promised_namespace
            and subject["data_dri"] is promised_data_dri
            and subject["service_consent_match_id"] is promised_conset_match
        )

        if not is_cred_okay:
            raise HandlerException(
                f"Incoming credential is malformed! \n"
                f"is_cred_okay ? {is_cred_okay} \n"
                f"promised_oca_dri: {promised_oca_dri} promised_namespace: {promised_namespace} \n"
                f"promised_data_dri: {promised_data_dri} promised_conset_match: {promised_conset_match} \n"
                f"malformed credential {credential} \n"
            )

        """

        Check the proof and save

        """

        try:
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
            {"credential_id": credential_id, "connection_id": responder.connection_id},
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


class GetIssueHandler(BaseHandler):
    async def handle(self, context: RequestContext, responder: BaseResponder):
        debug_handler(self._logger.debug, context, GetIssue)
        record: ServiceIssueRecord = (
            await ServiceIssueRecord.retrieve_by_exchange_id_and_connection_id(
                context,
                context.message.exchange_id,
                context.connection_record.connection_id,
            )
        )

        payload = await load_string(context, record.payload_dri)
        LOGGER.info("GetIssueHandler payload = load_string %s", payload)

        response = GetIssueResponse(
            label=record.label,
            payload=payload,
            service_schema=json.dumps(record.service_schema),
            consent_schema=json.dumps(record.consent_schema),
            exchange_id=record.exchange_id,
        )

        response.assign_thread_from(context.message)
        await responder.send_reply(response)


class GetIssueResponseHandler(BaseHandler):
    async def handle(self, context: RequestContext, responder: BaseResponder):
        debug_handler(self._logger.debug, context, GetIssueResponse)
        issue: ServiceIssueRecord = (
            await ServiceIssueRecord.retrieve_by_exchange_id_and_connection_id(
                context,
                context.message.exchange_id,
                context.connection_record.connection_id,
            )
        )

        payload_dri = await save_string(context, context.message.payload)
        LOGGER.info("GetIssueResponseHandler payload_dri %s", payload_dri)

        if issue.label is None:
            issue.label = context.message.label
        if issue.payload_dri is None:
            issue.payload_dri = payload_dri
        if issue.service_schema is None:
            issue.service_schema = json.loads(context.message.service_schema)
        if issue.consent_schema is None:
            issue.consent_schema = json.loads(context.message.consent_schema)

        issue_id = await issue.save(context)

        await responder.send_webhook(
            "verifiable-services/get-issue",
            {"issue_id": issue_id, "issue": issue.serialize()},
        )


# is_cred_okay ? False
# agent1.localhost_1   | promised_oca_dri: string promised_namespace: string
# agent1.localhost_1   | promised_data_dri: zQmSnRDrp3sNzsB194RaKwqKWmFS7mbT8oiF7qMWUCoNGgQ promised_conset_match: 11aaf801-a959-427e-8b03-cca1a3ccedc9
# OrderedDict([('context', ['https://www.w3.org/2018/credentials/v1',
# 'https://www.schema.org']), ('type', ['VerifiableCredential']), ('issuer', '7NmT78qAJDQCSqPkDjpDWK'),
# ('issuanceDate', '2020-11-27 08:45:32.344226Z'), ('credentialSubject', OrderedDict([('oca_schema_dri', 'string'),
# ('oca_schema_namespace', 'string'), ('data_dri', 'zQmSnRDrp3sNzsB194RaKwqKWmFS7mbT8oiF7qMWUCoNGgQ'),
#  ('service_consent_match_id', '11aaf801-a959-427e-8b03-cca1a3ccedc9'), ('id', 'Jij4NtGLMH1YeuEfpSUbWS')])),
#  ('proof', OrderedDict([('jws', 'wkyB83_BSa8ytCuKJ9zKYFhl3aaRr8HHjUxppjHz-ZlEQRsNM5zAk1Qfx9EyYHn1WmpXl2vZDr0Nujlm10oVDg'),
#  ('type', 'Ed25519Signature2018'), ('created', '2020-11-27 08:45:32.365386Z'), ('proofPurpose', 'assertionMethod'),
# ('verificationMethod', 'CXr3inEAWqrSjDE7txxgEkgFoR1MgPw7ixEFfq8b9w58')]))