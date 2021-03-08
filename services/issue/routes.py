from aries_cloudagent.connections.models.connection_record import ConnectionRecord
from aries_cloudagent.storage.error import *

from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.issuer.base import BaseIssuer, IssuerError
from aries_cloudagent.wallet.base import BaseWallet

from aiohttp import web
from aiohttp_apispec import docs, request_schema, match_info_schema, querystring_schema

from marshmallow import fields, Schema
import logging
import json

from .models import *
from .message_types import *
from ..models import *
from ..consents.routes import ConsentGiven
from ..discovery.message_types import DiscoveryServiceSchema
from aries_cloudagent.pdstorage_thcf.api import *
from aries_cloudagent.protocols.issue_credential.v1_1.utils import (
    retrieve_connection,
)
from ..util import *
import aries_cloudagent.generated_models as Model


LOGGER = logging.getLogger(__name__)


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

    try:
        issuer: BaseIssuer = await context.inject(BaseIssuer)
        credential = await issuer.create_credential_ex(
            credential_values=credential_values,
        )
    except IssuerError as err:
        raise web.HTTPInternalServerError(
            reason=f"Error occured while creating a credential {err.roll_up}"
        )

    service_user_data_dri = await pds_save(
        context,
        service_user_data,
        oca_schema_dri=service_schema["oca_schema_dri"],
    )

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

    consent_give_oca_schema_dri_stub = "consent_given"
    consent_given = ConsentGiven(credential, connection_id)
    await pds_save_model(context, consent_given, consent_give_oca_schema_dri_stub)

    return web.json_response({"success": True, "exchange_id": record.exchange_id})


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
        return web.json_response(
            {
                "success": True,
                "issue_id": issue._id,
                "connection_id": connection_id,
            }
        )

    """

    Create a service credential with values from the applicant

    """
    try:
        issuer: BaseIssuer = await context.inject(BaseIssuer)
        credential = await issuer.create_credential_ex(
            credential_values={
                "oca_schema_dri": service.service_schema["oca_schema_dri"],
                "oca_schema_namespace": service.service_schema["oca_schema_namespace"],
                "oca_data_dri": issue.service_user_data_dri,
                "service_consent_match_id": issue.service_consent_match_id,
            },
            subject_public_did=issue.their_public_did,
        )
    except IssuerError as err:
        raise web.HTTPInternalServerError(
            reason=f"Error occured while creating a credential {err.roll_up}"
        )

    issue.state = ServiceIssueRecord.ISSUE_ACCEPTED
    await issue.issuer_credential_pds_set(context, credential)
    await issue.save(context, reason="Accepted service issue, credential offer created")
    resp = ApplicationResponse(credential=credential, exchange_id=exchange_id)
    await outbound_handler(resp, connection_id=connection_id)
    return web.json_response(
        {
            "success": True,
            "issue_id": issue._id,
            "connection_id": connection_id,
        }
    )


@docs(tags=["Services"], summary="Add a verifiable service")
@request_schema(Model.BaseService)
async def add_service(request: web.BaseRequest):
    context = request.app["request_context"]
    body = await request.json()
    consent_id = body.get("consent_dri")
    if __debug__:
        assert consent_id is not None

    try:
        await pds_load_model(context, consent_id, DefinedConsent)
    except PDSError as err:
        return web.json_response(status=404, text="Consent not found - " + err.roll_up)

    service_record = ServiceRecord(
        label=body["label"],
        service_schema_dri=body["service_schema_dri"],
        consent_dri=consent_id,
    )

    uuid = await service_record.save(context)

    result = service_record.serialize()
    result["service_uuid"] = uuid

    return web.json_response(result, status=201)


@docs(
    tags=["Services"],
    summary="Retrieve all defined services",
)
async def get_services(request: web.BaseRequest):
    context = request.app["request_context"]

    try:
        result = await ServiceRecord.query_fully_serialized(context, skip_invalid=False)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(err.roll_up)

    return web.json_response(result)


@docs(
    tags=["Services"],
    summary="Retrieve all defined services",
)
async def get_service(request: web.BaseRequest):
    context = request.app["request_context"]
    service_uuid = request.match_info["service_uuid"]

    try:
        result = await ServiceRecord.retrieve_by_id_fully_serialized(
            context, service_uuid
        )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(err.roll_up)

    result["service_uuid"] = service_uuid
    return web.json_response(result)


services_routes = [
    # web.get(
    #     "/connections/{connection_uuid}/services",
    #     get_services,
    #     allow_head=False,
    # ),
    web.get(
        "/services",
        get_services,
        allow_head=False,
    ),
    web.get(
        "/services/{service_uuid}",
        get_service,
        allow_head=False,
    ),
    web.post(
        "/services/add",
        add_service,
    ),
    web.post("/verifiable-services/apply", apply),
    web.post(
        "/verifiable-services/process-application",
        process_application,
    ),
]
