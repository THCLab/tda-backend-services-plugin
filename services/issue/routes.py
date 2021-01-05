from aries_cloudagent.connections.models.connection_record import ConnectionRecord
from aries_cloudagent.messaging.valid import UUIDFour
from aries_cloudagent.storage.error import *

from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.issuer.base import BaseIssuer, IssuerError
from aries_cloudagent.holder.base import BaseHolder, HolderError
from aries_cloudagent.wallet.base import BaseWallet

from aiohttp import web
from aiohttp_apispec import docs, request_schema, match_info_schema

from marshmallow import fields, Schema
import logging
import hashlib
import json
from typing import Sequence
from asyncio import shield

from .models import *
from .message_types import *
from ..models import *
from ..consents.models.given_consent import ConsentGivenRecord
from ..discovery.message_types import DiscoveryServiceSchema
from aries_cloudagent.pdstorage_thcf.api import *
from aries_cloudagent.protocols.issue_credential.v1_1.messages.credential_request import (
    CredentialRequest,
)
from aries_cloudagent.protocols.issue_credential.v1_1.utils import (
    create_credential,
    retrieve_connection,
)
from ..util import *

LOGGER = logging.getLogger(__name__)
MY_SERVICE_DATA_TABLE = "my_service_data_table"


class ApplySchema(Schema):
    connection_id = fields.Str(required=True)
    user_data = fields.Str(required=True)
    service = fields.Nested(DiscoveryServiceSchema())


async def get_public_did(context):
    wallet: BaseWallet = await context.inject(BaseWallet)
    public_did = await wallet.get_public_did()
    public_did = public_did[0]

    if public_did == None:
        raise web.HTTPBadRequest(reason="This operation requires a public DID!")

    return public_did


@docs(
    tags=["Verifiable Services"],
    summary="Apply to a service that connected agent provides",
)
@request_schema(ApplySchema())
async def apply(request: web.BaseRequest):
    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    params = await request.json()
    connection_id = params["connection_id"]
    service_user_data = params["user_data"]
    service_id = params["service"]["service_id"]

    # service consent and service to check for correctness
    service_consent_schema = params["service"]["consent_schema"]
    service_schema = params["service"]["service_schema"]
    service_label = params["service"]["label"]

    connection = await retrieve_connection(context, connection_id)
    issuer: BaseIssuer = await context.inject(BaseIssuer)

    service_consent_match_id = str(uuid.uuid4())

    """

    Pop the usage policy of service provider and bring our policy to
    credential

    """
    service_consent_copy = service_consent_schema.copy()
    service_consent_copy.pop("oca_data", None)
    usage_policy = await pds_get_usage_policy_if_active_pds_supports_it(context)
    credential_values = {"service_consent_match_id": service_consent_match_id}
    credential_values["usage_policy"] = usage_policy

    credential_values.update(service_consent_copy)

    credential = await create_credential(
        context,
        {"credential_values": credential_values},
        exception=web.HTTPError,
    )

    metadata = {
        "oca_schema_dri": service_schema["oca_schema_dri"],
        "table": MY_SERVICE_DATA_TABLE,
    }
    service_user_data_dri = await save_string(
        context, service_user_data, json.dumps(metadata)
    )

    print("service_consent_schema: ", service_consent_schema)
    record = ServiceIssueRecord(
        connection_id=connection_id,
        state=ServiceIssueRecord.ISSUE_WAITING_FOR_RESPONSE,
        author=ServiceIssueRecord.AUTHOR_SELF,
        label=service_label,
        service_consent_schema=service_consent_schema,
        service_id=service_id,
        service_schema=service_schema,
        service_user_data_dri=service_user_data_dri,
        service_consent_match_id=service_consent_match_id,
    )

    await record.save(context)

    """ 
    service_user_data_dri - is here so that in the future it would be easier
    to not send the service_user_data, because from what I understand we only
    want to send that to the other party under certain conditions

    dri is used only to make sure DRI's are the same 
    when I store the data in other's agent PDS

    """
    public_did = await get_public_did(context)

    request = Application(
        service_id=record.service_id,
        exchange_id=record.exchange_id,
        service_user_data=service_user_data,
        service_user_data_dri=service_user_data_dri,
        service_consent_match_id=service_consent_match_id,
        consent_credential=credential,
        public_did=public_did,
    )
    await outbound_handler(request, connection_id=connection_id)

    """

    Record the given credential

    """

    consent_given_record = ConsentGivenRecord(
        connection_id=connection_id,
        credential=credential,
    )

    await consent_given_record.save(context)

    return web.json_response(
        {"success": "application_sent", "exchange_id": record.exchange_id}
    )


async def send_confirmation(outbound_handler, connection_id, exchange_id, state):
    confirmation = Confirmation(exchange_id=exchange_id, state=state)
    await outbound_handler(confirmation, connection_id=connection_id)


class ProcessApplicationSchema(Schema):
    issue_id = fields.Str(required=True)
    decision = fields.Str(required=True)


@docs(
    tags=["Verifiable Services"],
    summary="Decide whether application should be accepted or rejected",
    description="""
    issue_id - first you need to call get_issue_self and search for 
    issues with "pending" state, those should return you issue_id

    decision:
    "accept"
    "reject" 
    """,
)
@request_schema(ProcessApplicationSchema())
async def process_application(request: web.BaseRequest):
    outbound_handler = request.app["outbound_message_router"]
    context = request.app["request_context"]
    params = await request.json()
    issue_id = params["issue_id"]

    issue: ServiceIssueRecord = await retrieve_service_issue(context, issue_id)
    exchange_id = issue.exchange_id
    connection_id = issue.connection_id

    service: ServiceRecord = await retrieve_service(context, issue.service_id)
    connection: ConnectionRecord = await retrieve_connection(context, connection_id)

    """

    Users can decide to reject the application

    """

    if (
        params["decision"] == "reject"
        or issue.state == ServiceIssueRecord.ISSUE_REJECTED
    ):
        issue.state = ServiceIssueRecord.ISSUE_REJECTED
        await issue.save(context, reason="Issue reject saved")
        await send_confirmation(
            outbound_handler, connection_id, exchange_id, issue.state
        )
        return web.json_response(issue.serialize())

    """

    Create a service credential with values from the applicant

    """

    credential = await create_credential(
        context,
        {
            "credential_values": {
                "oca_schema_dri": service.service_schema["oca_schema_dri"],
                "oca_schema_namespace": service.service_schema["oca_schema_namespace"],
                "oca_data_dri": issue.service_user_data_dri,
                "service_consent_match_id": issue.service_consent_match_id,
            }
        },
        their_public_did=issue.their_public_did,
        exception=web.HTTPError,
    )

    issue.state = ServiceIssueRecord.ISSUE_ACCEPTED
    await issue.save(context, reason="Accepted service issue, credential offer created")

    resp = ApplicationResponse(credential=credential, exchange_id=exchange_id)
    await outbound_handler(resp, connection_id=connection_id)
    return web.json_response(
        {
            "issue_id": issue._id,
            "connection_id": connection_id,
        }
    )


class GetIssueFilteredSchema(Schema):
    connection_id = fields.Str(required=False)
    exchange_id = fields.Str(required=False)
    service_id = fields.Str(required=False)
    label = fields.Str(required=False)
    author = fields.Str(required=False)
    state = fields.Str(required=False)


async def serialize_and_verify_service_issue(context, issue):
    record: dict = issue.serialize()

    """
    Serialize additional fields which are not serializable
    by default (information that is in PDS)
    """

    service = await ServiceRecord.retrieve_by_id_fully_serialized(
        context, issue.service_id
    )
    consent_data = service["consent_schema"]

    if consent_data.get("usage_policy") is not None:
        if issue.author == ServiceIssueRecord.AUTHOR_OTHER:
            record["usage_policies_match"] = await verify_usage_policy(
                issue.user_consent_credential["credentialSubject"]["usage_policy"],
                consent_data["usage_policy"],
            )

    service_user_data = await load_string(context, issue.service_user_data_dri)
    record.update(
        {
            "issue_id": issue._id,
            "label": issue.label,
            "service_user_data": service_user_data,
            "service_schema": json.dumps(issue.service_schema),
            "consent_schema": json.dumps(consent_data),
        }
    )

    return record


@docs(
    tags=["Verifiable Services"],
    summary="Search for issue by a specified tag",
    description="""
    You don't need to fill any of this, all the filters are optional
    make sure to delete ones you dont use

    STATES: 
    "pending" - not processed yet (not rejected or accepted)
    "no response" - agent didn't respond at all yet
    "rejected"
    "accepted"

    AUTHORS:
    "self"
    "other"

    """,
)
@request_schema(GetIssueFilteredSchema())
async def get_issue_self(request: web.BaseRequest):
    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]
    params = await request.json()

    try:
        query = await ServiceIssueRecord.query(context, tag_filter=params)
    except StorageError as err:
        raise web.HTTPInternalServerError(err)

    result = []
    for i in query:
        record = await serialize_and_verify_service_issue(context, i)
        result.append(record)

    return web.json_response(result)


class GetIssueByIdSchema(Schema):
    issue_id = fields.Str(required=True)


@docs(
    tags=["Verifiable Services"],
    summary="Search for issue by id",
)
@match_info_schema(GetIssueByIdSchema())
async def get_issue_by_id(request: web.BaseRequest):
    context = request.app["request_context"]
    issue_id = request.match_info["issue_id"]

    try:
        query: ServiceIssueRecord = await ServiceIssueRecord.retrieve_by_id(
            context, issue_id
        )
    except StorageError as err:
        raise web.HTTPInternalServerError(err)

    record = await serialize_and_verify_service_issue(context, query)

    return web.json_response(record)


async def DEBUGapply_status(request: web.BaseRequest):
    context = request.app["request_context"]
    params = await request.json()

    query = await ServiceIssueRecord.query(context, tag_filter=params)

    query = [i.serialize() for i in query]

    return web.json_response(query)


async def DEBUGget_credential_data(request: web.BaseRequest):
    context = request.app["request_context"]
    data_dri = request.match_info["data_dri"]

    query: ServiceIssueRecord = await ServiceIssueRecord.retrieve_by_id(
        context, data_dri
    )

    return web.json_response({"credential_data": query.payload})
