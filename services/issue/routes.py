from ..issue.handlers import application_handler, application_response_handler
from aiohttp_apispec.decorators import response
from ..discovery.handlers import cache_requested_services
from aries_cloudagent.connections.models.connection_record import ConnectionRecord
from aries_cloudagent.storage.error import *

from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.issuer.base import BaseIssuer, IssuerError
from aries_cloudagent.wallet.base import BaseWallet

from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema, match_info_schema

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

# appliance_uuid == ServiceIssueRecord._id


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
    credential_values = {
        "service_consent_match_id": service_consent_match_id,
        "oca_schema_dri": seek["consent_schema"]["oca_schema_dri"],
        "dri": seek["consent_schema"]["dri"],
        "label": seek["consent_schema"]["label"],
    }

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

    print("service_user_data:", service_user_data)
    service_user_data_dri = await pds_save(
        context,
        json.dumps(service_user_data),
        oca_schema_dri=seek["service_schema_dri"],
    )

    record = ServiceIssueRecord(
        connection_id=connection_id,
        state=ServiceIssueRecord.ISSUE_PENDING,
        author=ServiceIssueRecord.AUTHOR_SELF,
        label=seek["label"],
        service_consent_schema={
            "oca_schema_dri": seek["consent_schema"]["oca_schema_dri"],
            "oca_data": seek["consent_schema"]["oca_data"],
        },
        service_id=service_id,
        service_schema_dri=seek["service_schema_dri"],
        service_user_data_dri=service_user_data_dri,
        service_consent_match_id=service_consent_match_id,
    )
    await record.save(context)

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
    tags=["Services"],
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
    return web.json_response(
        {
            "connection_uuid": record.connection_id,
            "appliance_uuid": record._id,
            "service_uuid": record.service_id,
            "consent": record.service_consent_schema,
            "service": {"oca_schema_dri": record.service_schema_dri},
            "service_user_data": user_data,
        }
    )


async def send_confirmation(outbound_handler, connection_id, exchange_id, state):
    confirmation = Confirmation(exchange_id=exchange_id, state=state)
    await outbound_handler(confirmation, connection_id=connection_id)


async def process_application(context, issue_id, accept: bool):
    issue: ServiceIssueRecord = await retrieve_service_issue(context, issue_id)
    service: ServiceRecord = await retrieve_service(context, issue.service_id)
    await retrieve_connection(context, issue.connection_id)

    if accept == False or issue.state == ServiceIssueRecord.ISSUE_REJECTED:
        issue.state = ServiceIssueRecord.ISSUE_REJECTED
        await issue.save(context, reason="Issue reject saved")
        return issue.state, None, issue

    try:
        issuer: BaseIssuer = await context.inject(BaseIssuer)
        credential = await issuer.create_credential_ex(
            credential_values={
                "oca_schema_dri": service.service_schema_dri,
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
    resp = ApplicationResponse(credential=credential, exchange_id=issue.exchange_id)
    return None, resp, issue


async def _process_application_endpoint(request):
    outbound_handler = request.app["outbound_message_router"]
    context = request.app["request_context"]
    apply_id = request.match_info["appliance_uuid"]
    err, msg, issue = await process_application(context, apply_id, True)

    if err:
        await send_confirmation(
            outbound_handler, issue.connection_id, issue.exchange_id, err
        )
    else:
        await outbound_handler(msg, connection_id=issue.connection_id)

    service = await ServiceRecord.retrieve_by_id(context, issue.service_id)
    consent = await DefinedConsent.load(context, service.consent_dri)

    return web.json_response(
        {
            "connection_uuid": issue.connection_id,
            "appliance_uuid": issue._id,
            "service_uuid": issue.service_id,
            "consent": consent.serialize(),
            "service": {"oca_schema_dri": service.service_schema_dri},
        }
    )


@response_schema(Model.Application)
@match_info_schema(Model.ApplicationsApplianceUuidAcceptInput.Put.Path)
@docs(tags=["Services"])
async def application_accept_endpoint(request: web.BaseRequest):
    result = await _process_application_endpoint(request)
    return result


@response_schema(Model.Application)
@match_info_schema(Model.ApplicationsApplianceUuidRejectInput.Put.Path)
@docs(tags=["Services"])
async def application_reject_endpoint(request: web.BaseRequest):
    result = await _process_application_endpoint(request)
    return result


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
    ctx = request.app["request_context"]
    body = await request.json()
    consent_id = body.get("consent_dri")
    service = await add_service(
        ctx, body["label"], body["service_schema_dri"], consent_id
    )

    result = service.serialize()
    result["service_uuid"] = service._id
    return web.json_response(result, status=201)


async def test_setup_application_handler():
    import random

    context, conn_applicant, service = await test_setup_for_apply()
    conn_service_provider = await add_connection(context)
    user_data = {"user_data": "cool_data" + str(random.randint(0, 11111))}
    message, record = await apply(context, conn_applicant._id, service._id, user_data)
    request, record = await application_handler(
        context, message, conn_service_provider._id
    )
    return context, request, record, conn_applicant


async def test_full_process():
    context, request, record, conn_applicant = await test_setup_application_handler()
    err, msg, record = await process_application(context, record._id, True)
    resp = await application_response_handler(context, msg, conn_applicant._id)
    return context


async def test_process_application():
    async def test_process_application_endpoint(function):
        (
            context,
            request,
            record,
            conn_applicant,
        ) = await test_setup_application_handler()
        web_request = build_request_stub(
            context, match_info={"appliance_uuid": record._id}
        )
        await call_endpoint_validate(function, web_request)

    await test_process_application_endpoint(application_accept_endpoint)
    await test_process_application_endpoint(application_reject_endpoint)


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


async def test_setup_for_apply():
    context = await build_context("local")
    consent = await add_consent(context, "asd", {"test_apply": "a"}, "test_consent_dri")
    service = await add_service(context, "test_", "test_apply", consent.dri)
    connect = await add_connection(context)
    services = await service.query_fully_serialized(context)

    await cache_requested_services(context, connect._id, json.dumps(services))
    await create_public_did(context)
    return context, connect, service


async def test_apply():
    context, connect, service = await test_setup_for_apply()
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


async def serialize_as_applications(context, records, mine=False):
    result = []
    for count, i in enumerate(records):
        service = await ServiceRecord.retrieve_by_id(context, i.service_id)
        consent_data = await pds_load(context, service.consent_dri, with_meta=True)
        if consent_data["content"].get("usage_policy") == None:
            consent_data["content"].pop("usage_policy", None)

        result.append(
            {
                "consent": {
                    "oca_data": consent_data["content"],
                    "oca_schema_dri": consent_data["oca_schema_dri"],
                },
                "connection_uuid": i.connection_id,
                "appliance_uuid": i._id,
                "service_uuid": i.service_id,
                "service": {"oca_schema_dri": service.service_schema_dri},
            }
        )
        if mine:
            service_user_data = await pds_load(context, i.service_user_data_dri)
            result[count]["service_user_data"] = service_user_data

    return result


@docs(
    tags=["Services"],
    summary="Queries for all pending applications that others applied to",
)
@response_schema(Model.ArrayOfApplications)
async def other_applications_endpoint(request: web.BaseRequest):
    context = request.app["request_context"]
    records = await ServiceIssueRecord.query(
        context,
        {
            "state": ServiceIssueRecord.ISSUE_PENDING,
            "author": ServiceIssueRecord.AUTHOR_OTHER,
        },
    )
    result = await serialize_as_applications(context, records)
    return web.json_response(result)


@docs(
    tags=["Services"],
    summary="Queries for all pending applications that I have applied to",
)
@response_schema(Model.ArrayOfMineApplications)
async def mine_applications_endpoint(request: web.BaseRequest):
    context = request.app["request_context"]
    records = await ServiceIssueRecord.query(
        context,
        {
            "state": ServiceIssueRecord.ISSUE_PENDING,
            "author": ServiceIssueRecord.AUTHOR_SELF,
        },
    )
    result = await serialize_as_applications(context, records, True)
    return web.json_response(result)


async def test_get_service_issues():
    context, connectA, service = await test_setup_for_apply()
    connectB = await add_connection(context)
    message, record = await apply(
        context, connectA.connection_id, service._id, {"user": "data"}
    )
    request, record = await application_handler(
        context, message, connectB.connection_id
    )

    await call_endpoint_validate(
        other_applications_endpoint, build_request_stub(context)
    )
    await call_endpoint_validate(
        mine_applications_endpoint, build_request_stub(context)
    )


async def main():
    await test_apply()
    await test_add_service_endpoint()
    await test_process_application()
    await test_full_process()
    await test_get_service_issues()


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
        raise web.HTTPNotFound(reason=err.roll_up)

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
    web.put("/applications/{appliance_uuid}/accept", application_accept_endpoint),
    web.post("/applications/{appliance_uuid}/reject", application_reject_endpoint),
]
