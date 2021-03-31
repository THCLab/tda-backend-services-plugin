from aiohttp_apispec.decorators import response
from ..discovery.handlers import cache_requested_services
from aries_cloudagent.connections.models.connection_record import ConnectionRecord
from aries_cloudagent.storage.error import *

from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.issuer.base import BaseIssuer, IssuerError
from aries_cloudagent.wallet.base import BaseWallet

from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema

from marshmallow import fields, Schema
import logging
import json

from .models import *
from .message_types import *
from ..models import *
from ..consents.routes import ConsentGiven, add_consent
from ..discovery.message_types import Discovery, DiscoveryServiceSchema
from aries_cloudagent.pdstorage_thcf.api import *
from aries_cloudagent.protocols.issue_credential.v1_1.utils import (
    retrieve_connection,
)
from ..util import *
import aries_cloudagent.generated_models as Model
from aries_cloudagent.aathcf.utils import (
    build_context,
    build_request_stub,
    validate_endpoint_output,
    call_endpoint_validate,
)
from aries_cloudagent.config.global_variables import CONSENT_GIVEN_DRI


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


async def seek_other_agent_service(storage, connection_id, service_id):
    search = storage.search_records("service_list", {"connection_id": connection_id})
    await search.open()

    try:
        records = await search.fetch_single()
    except StorageNotFoundError:
        raise web.HTTPNotFound(
            reason="Service, pointed by connection_uuid, not found",
        )
    await search.close()

    records = json.loads(records.value)

    seek = None  # seek record
    for i in records:
        if i["service_uuid"] == service_id:
            seek = i

    if seek is None:
        raise web.HTTPNotFound(
            reason="Service, pointed by connection_uuid and service_uuid, not found",
        )
    return seek


async def apply(context, connection_id, service_id, service_user_data):
    await retrieve_connection(context, connection_id)
    issuer: BaseIssuer = await context.inject(BaseIssuer)
    storage: BaseStorage = await context.inject(BaseStorage)
    service_consent_match_id = str(uuid.uuid4())
    seek = await seek_other_agent_service(storage, connection_id, service_id)

    service_consent_copy = seek["consent_schema"].copy()
    service_consent_copy.pop("oca_data", None)
    credential_values = {"service_consent_match_id": service_consent_match_id}
    credential_values.update(service_consent_copy)

    usage_policy = await pds_get_usage_policy_if_active_pds_supports_it(context)
    if usage_policy:
        credential_values["usage_policy"] = usage_policy

    try:
        issuer: BaseIssuer = await context.inject(BaseIssuer)
        credential = await issuer.create_credential_ex(
            credential_values=credential_values,
        )
    except IssuerError as err:
        raise web.HTTPInternalServerError(
            reason=f"Error occured while creating a credential [{err.roll_up}]"
        )

    service_user_data_dri = await pds_save(
        context,
        service_user_data,
        oca_schema_dri=seek["service_schema_dri"],
    )

    seek["consent_schema"]["consent_schema_dri"] = seek["consent_dri"]
    record = ServiceIssueRecord(
        connection_id=connection_id,
        state=ServiceIssueRecord.ISSUE_WAITING_FOR_RESPONSE,
        author=ServiceIssueRecord.AUTHOR_SELF,
        label=seek["label"],
        service_consent_schema=seek["consent_schema"],
        service_id=service_id,
        service_schema={
            "oca_schema_dri": seek["service_schema_dri"],
            "consent_dri": seek["consent_dri"],
        },
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

    consent_given = ConsentGiven(
        credential, connection_id, oca_schema_dri=CONSENT_GIVEN_DRI
    )
    await consent_given.save(context)

    return request, record


@docs(
    tags=["Verifiable Services"],
    summary="Apply to a service that connected agent provides",
)
@response_schema(Model.MineApplication)
@request_schema(Model.NewApplication)
async def apply_endpoint(request: web.BaseRequest):
    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    params = await request.json()
    connection_id = params["connection_uuid"]
    user_data = params["user_data"]
    service_id = params["service_uuid"]

    request, record = await apply(context, connection_id, service_id, user_data)
    await outbound_handler(request, connection_id=connection_id)

    record.service_consent_schema.pop("usage_policy", None)
    result = {
        "connection_uuid": record.connection_id,
        "appliance_uuid": record._id,
        "service_uuid": record.service_id,
        "consent": record.service_consent_schema,
        "service": record.service_schema,
        "service_user_data": user_data,
    }
    return web.json_response(result)


async def send_confirmation(outbound_handler, connection_id, exchange_id, state):
    confirmation = Confirmation(exchange_id=exchange_id, state=state)
    await outbound_handler(confirmation, connection_id=connection_id)


async def test_apply():
    context = await build_context("local")
    consent = await add_consent(context, "asd", {"test_apply": "a"}, "test_consent_dri")
    service = await add_service(context, "test_", "test_apply", consent.dri)
    connect = await add_connection(context)
    services = await service.query_fully_serialized(context)

    await cache_requested_services(context, connect._id, json.dumps(services))
    await create_public_did(context)

    user_data = {"user_data": "cool_data"}
    apply_res = await call_endpoint_validate(
        apply_endpoint,
        build_request_stub(
            context,
            {
                "user_data": user_data,
                "service_uuid": service._id,
                "connection_uuid": connect._id,
            },
        ),
    )
    apply_res = json.loads(apply_res.body)
    assert apply_res["connection_uuid"] == connect._id
    assert apply_res["service_uuid"] == service._id
    assert apply_res["service_user_data"] == user_data


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
async def process_application_endpoint(request: web.BaseRequest):
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
        print("\n\nCREDENTIAL", credential)
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


async def add_service(context, label, service_schema_dri, consent_dri):
    try:
        await DefinedConsent.load(context, consent_dri)
    except PDSError as err:
        return web.json_response(status=404, text="Consent not found - " + err.roll_up)

    service_record = ServiceRecord(
        label=label,
        service_schema_dri=service_schema_dri,
        consent_dri=consent_dri,
    )

    await service_record.save(context)
    return service_record


async def add_connection(context):
    result = ConnectionRecord()
    result.state = result.STATE_ACTIVE
    await result.save(context)
    return result


async def create_public_did(context):
    wallet: BaseWallet = await context.inject(BaseWallet)
    await wallet.create_public_did()


@docs(tags=["Services"], summary="Add a verifiable service")
@request_schema(Model.BaseService)
@response_schema(Model.Service, code=201)
async def add_service_endpoint(request: web.BaseRequest):
    context = request.app["request_context"]
    body = await request.json()
    consent_id = body.get("consent_dri")
    LOGGER.info("add_service_endpoint endpoint, body: %s", body)
    rec = await add_service(
        context, body["label"], body["service_schema_dri"], consent_id
    )

    result = rec.serialize()
    result["service_uuid"] = rec._id

    return web.json_response(result, status=201)


async def test_add_service_endpoint():
    context = await build_context("local")
    consent = await add_consent(context, "asd", {}, "test_consent_dri")
    await call_endpoint_validate(
        add_service_endpoint,
        build_request_stub(
            context,
            {
                "consent_dri": consent.dri,
                "label": "TestService",
                "service_schema_dri": "12345",
            },
        ),
    )


async def main():
    await test_apply()
    await test_add_service_endpoint()


run_standalone_async(__name__, main)


@docs(
    tags=["Services"],
    summary="Retrieve all defined services",
)
async def get_services_endpoint(request: web.BaseRequest):
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
async def get_service_endpoint(request: web.BaseRequest):
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


@docs(
    tags=["Services"],
    summary="Request a service list from other agent",
    description="Reading the list requires webhook handling",
)
async def request_services_endpoint(request: web.BaseRequest):
    context = request.app["request_context"]
    connection_id = request.match_info["connection_uuid"]
    outbound_handler = request.app["outbound_message_router"]

    try:
        connection = await ConnectionRecord.retrieve_by_id(context, connection_id)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err)

    if connection.is_ready:
        request = Discovery()
        await outbound_handler(request, connection_id=connection_id)

        return web.json_response(
            "Response will come async, via websocket. Response will contain ArrayOfServices model."
        )

    raise web.HTTPServiceUnavailable(reason="Connection with agent not ready")


services_routes = [
    web.get(
        "/connections/{connection_uuid}/services",
        request_services_endpoint,
        allow_head=False,
    ),
    web.get(
        "/services",
        get_services_endpoint,
        allow_head=False,
    ),
    web.get(
        "/services/{service_uuid}",
        get_service_endpoint,
        allow_head=False,
    ),
    web.post(
        "/services/add",
        add_service_endpoint,
    ),
    web.post("/services/apply", apply_endpoint),
    web.post(
        "/verifiable-services/process-application",
        process_application_endpoint,
    ),
]
