from aries_cloudagent.holder.routes import documents_given_get
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
from ..consents.routes import add_consent
from ..discovery.message_types import Discovery, DiscoveryServiceSchema
from aries_cloudagent.pdstorage_thcf.api import *
from aries_cloudagent.protocols.issue_credential.v1_1.utils import (
    retrieve_connection,
)
from ..util import *
import aries_cloudagent.generated_models as Model
from aries_cloudagent.aathcf.utils import (
    add_connection,
    build_context,
    build_request_stub,
    create_public_did,
    validate_endpoint_output,
    call_endpoint_validate,
)
import aries_cloudagent.config.global_variables as globals


LOGGER = logging.getLogger(__name__)

# appliance_id == ServiceIssueRecord._id


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
            reason="Service, pointed by connection_id, not found",
        )
    await search.close()

    records = json.loads(records.value)

    seek = None  # seek record
    for i in records:
        if i["service_id"] == service_id:
            seek = i

    if seek is None:
        raise web.HTTPNotFound(
            reason="Service, pointed by connection_id and service_id, not found",
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

    service_user_data = json.dumps(service_user_data)
    service_user_data_dri = await pds_save(
        context,
        service_user_data,
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

    await pds_save(
        context,
        {"connection_id": connection_id, "credential": credential},
        oca_schema_dri=globals.CONSENT_GIVEN_DRI,
    )

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
    connection_id = params["connection_id"]
    user_data = params["user_data"]
    service_id = params["service_id"]

    request, record = await apply(context, connection_id, service_id, user_data)
    await outbound_handler(request, connection_id=connection_id)

    record.service_consent_schema.pop("usage_policy", None)
    return web.json_response(
        {
            "connection_id": record.connection_id,
            "appliance_id": record._id,
            "service_id": record.service_id,
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
    apply_id = request.match_info["appliance_id"]
    err, msg, issue = await process_application(context, apply_id, True)

    if err:
        await send_confirmation(
            outbound_handler, issue.connection_id, issue.exchange_id, err
        )
    else:
        await outbound_handler(msg, connection_id=issue.connection_id)

    service = await ServiceRecord.retrieve_by_id(context, issue.service_id)
    consent = await pds_load(context, service.consent_dri, with_meta_embed=True)

    return web.json_response(
        {
            "connection_id": issue.connection_id,
            "appliance_id": issue._id,
            "service_id": issue.service_id,
            "consent": consent,
            "service": {"oca_schema_dri": service.service_schema_dri},
        }
    )


@response_schema(Model.Application)
@match_info_schema(Model.ApplicationsApplianceIdAcceptInput.Put.Path)
@docs(tags=["Services"])
async def application_accept_endpoint(request: web.BaseRequest):
    result = await _process_application_endpoint(request)
    return result


@response_schema(Model.Application)
@match_info_schema(Model.ApplicationsApplianceIdRejectInput.Put.Path)
@docs(tags=["Services"])
async def application_reject_endpoint(request: web.BaseRequest):
    result = await _process_application_endpoint(request)
    return result


async def add_service(context, label, service_schema_dri, consent_dri):
    try:
        await pds_load(context, consent_dri)
    except PDSError as err:
        return web.json_response(status=404, text="Consent not found - " + err.roll_up)

    service_record = ServiceRecord(
        label=label,
        service_schema_dri=service_schema_dri,
        consent_dri=consent_dri,
    )

    await service_record.save(context)
    return service_record


@docs(tags=["Services"], summary="Add a verifiable service")
@request_schema(Model.BaseService)
@response_schema(Model.Service, code=201)
async def add_service_endpoint(request: web.BaseRequest):
    ctx = request.app["request_context"]
    body = await request.json()
    if __debug__:
        assert body.get("consent_dri") != ""
    service = await add_service(
        ctx, body["label"], body["service_schema_dri"], body.get("consent_dri")
    )

    result = service.serialize()
    result["service_id"] = service._id
    return web.json_response(result, status=201)


async def serialize_as_applications(context, records, mine=False):
    result = []
    for count, i in enumerate(records):
        if mine:
            service_schema_dri = i.service_schema_dri
            consent_data = i.service_consent_schema
        else:
            service = await ServiceRecord.retrieve_by_id(context, i.service_id)
            service_schema_dri = service.service_schema_dri
            consent_data = await pds_load(context, service.consent_dri, with_meta=True)
            consent_data["content"]["oca_schema_dri"] = consent_data["oca_schema_dri"]
            consent_data = consent_data["content"]

        if consent_data.get("usage_policy") == None:
            consent_data.pop("usage_policy", None)

        result.append(
            {
                "consent": {
                    "oca_data": consent_data["oca_data"],
                    "oca_schema_dri": consent_data["oca_schema_dri"],
                },
                "connection_id": i.connection_id,
                "appliance_id": i._id,
                "service_id": i.service_id,
                "service": {"oca_schema_dri": service_schema_dri},
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


async def test_setup_application_handler(pds="local"):
    import random

    context, conn_applicant, service = await test_setup_for_apply(pds)
    conn_service_provider = await add_connection(context)
    user_data = {"user_data": "cool_data" + str(random.randint(0, 11111))}
    message, record = await apply(context, conn_applicant._id, service._id, user_data)
    request, record = await application_handler(
        context, message, conn_service_provider._id
    )
    return context, request, record, conn_applicant, conn_service_provider


async def test_full_process(pds="local"):
    (
        context,
        request,
        record,
        conn_applicant,
        conn_service_provider,
    ) = await test_setup_application_handler(pds)
    err, msg, record = await process_application(context, record._id, True)
    resp = await application_response_handler(context, msg, conn_applicant._id)
    return context, request, record, conn_applicant, conn_service_provider


async def test_process_application():
    async def test_process_application_endpoint(function):
        (
            context,
            request,
            record,
            conn_applicant,
            conn_service_provider,
        ) = await test_setup_application_handler()
        web_request = build_request_stub(
            context, match_info={"appliance_id": record._id}
        )
        await call_endpoint_validate(function, web_request)

    await test_process_application_endpoint(application_accept_endpoint)
    await test_process_application_endpoint(application_reject_endpoint)


async def test_add_service_endpoint():
    context = await build_context("local")
    consent = await add_consent(context, "asd", {})
    await call_endpoint_validate(
        add_service_endpoint,
        build_request_stub(
            context,
            {
                "consent_dri": consent["dri"],
                "label": "TestService",
                "service_schema_dri": "12345",
            },
        ),
    )


async def test_setup_for_apply(pds="local"):
    context = await build_context(pds)
    consent = await add_consent(context, "asd", {"test_apply": "a"})
    service = await add_service(context, "test_", "test_apply", consent["dri"])
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
                "service_id": service._id,
                "connection_id": connect._id,
            },
        ),
    )
    apply_res = json.loads(apply_res.body)
    assert apply_res["connection_id"] == connect._id
    assert apply_res["service_id"] == service._id
    assert apply_res["service_user_data"] == user_data


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


async def test_request_presentation():
    import aries_cloudagent.protocols.present_proof.v1_1.routes as present
    from aries_cloudagent.protocols.present_proof.v1_1.handlers.request_proof import (
        handle_proof_request,
    )
    from aries_cloudagent.holder.routes import documents_mine_get

    (
        context,
        request,
        record,
        conn_applicant,
        conn_service_provider,
    ) = await test_full_process("own_your_data_data_vault")
    # result = await pds_load(
    #     context, "zQmePJdMBUWbuBM3UUULoEw9b7hRrjutcRvVxBnRKBTzMoA", with_meta_embed=True
    # )
    # print(result)
    documents = await documents_mine_get(context)
    oca_schema_dri = None
    dri = None
    for i in documents:
        osdri = i["content"]["credentialSubject"].get("oca_schema_dri")
        if osdri:
            oca_schema_dri = osdri
            dri = i["dri"]
            break

    result = await call_endpoint_validate(
        present.request_presentation_route,
        build_request_stub(
            context,
            {"oca_schema_dri": oca_schema_dri, "connection_id": conn_applicant._id},
        ),
    )

    message, exchange_record = await present.request_presentation(
        context, conn_applicant._id, oca_schema_dri
    )
    record_id = await handle_proof_request(context, conn_applicant._id, message)
    pmessage, ppresentation, pexchange = await present.present_proof(
        context, record_id, dri
    )
    print(pmessage)


async def main():
    # await test_apply()
    # await test_add_service_endpoint()
    # await test_process_application()
    # await test_full_process()
    # await test_get_service_issues()
    await test_request_presentation()


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
    service_id = request.match_info["service_id"]

    try:
        result = await ServiceRecord.retrieve_by_id_fully_serialized(
            context, service_id
        )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up)

    result["service_id"] = service_id
    return web.json_response(result)


@docs(
    tags=["Services"],
    summary="Request a service list from other agent",
    description="Reading the list requires webhook handling",
)
async def request_services_endpoint(request: web.BaseRequest):
    context = request.app["request_context"]
    connection_id = request.match_info["connection_id"]
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
        "/connections/{connection_id}/services",
        request_services_endpoint,
        allow_head=False,
    ),
    web.get("/services", get_services_endpoint, allow_head=False),
    web.get("/services/{service_id}", get_service_endpoint, allow_head=False),
    web.post("/services/add", add_service_endpoint),
    web.get("/applications/mine", mine_applications_endpoint, allow_head=False),
    web.get("/applications/others", other_applications_endpoint, allow_head=False),
    web.post("/services/apply", apply_endpoint),
    web.put("/applications/{appliance_id}/accept", application_accept_endpoint),
    web.post("/applications/{appliance_id}/reject", application_reject_endpoint),
]
