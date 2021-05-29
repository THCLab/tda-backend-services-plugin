from aiohttp import web
from aiohttp_apispec import docs, request_schema
from aiohttp_apispec.decorators import response
from aiohttp_apispec.decorators.response import response_schema
from aries_cloudagent.aathcf.credentials import validate_schema
import aries_cloudagent.config.global_variables as globals
from aries_cloudagent.aathcf.utils import (
    build_context,
    call_endpoint_validate,
    run_standalone_async,
    build_request_stub,
)
from aries_cloudagent.pdstorage_thcf.api import (
    pds_get_usage_policy_if_active_pds_supports_it,
    pds_load,
    pds_query_by_oca_schema_dri,
    PDSError,
    pds_save,
)
import aries_cloudagent.generated_models as Model
import logging
from aries_cloudagent.pdstorage_thcf.error import PDSRecordNotFoundError

from marshmallow import fields, Schema


LOGGER = logging.getLogger(__name__)


class PDSConsent(Schema):
    label = fields.Str(required=True)
    oca_data = fields.Dict(required=True)
    oca_schema_dri = fields.Str(required=False)
    usage_policy = fields.Str(required=False)
    dri = fields.Str(required=False)


async def add_consent(context, label, oca_data):
    model = {"label": label, "oca_data": oca_data}
    pds_usage_policy = await pds_get_usage_policy_if_active_pds_supports_it(context)
    if pds_usage_policy:
        model.update({"usage_policy": pds_usage_policy})
    errors = validate_schema(PDSConsent, model)
    if errors:
        raise PDSError(errors)
    dri = await pds_save(context, model, oca_schema_dri=globals.CONSENT_DRI)
    model["oca_schema_dri"] = globals.CONSENT_DRI
    model["dri"] = dri
    return model


async def get_consent(context, id):
    try:
        record = await pds_load(context, id, with_meta_embed=True)
    except PDSRecordNotFoundError:
        raise web.HTTPNotFound(reason="record not found")
    errors = validate_schema(PDSConsent, record)
    if errors:
        raise web.HTTPUnprocessableEntity(reason=errors)
    return record


async def retrieve_from_pds(context, oca_schema_dri):
    try:
        result = await pds_query_by_oca_schema_dri(context, oca_schema_dri)
    except PDSError as err:
        raise web.HTTPInternalServerError(reason=err.roll_up)
    return result


@request_schema(Model.Consent)
@response_schema(Model.Consent)
@docs(
    tags=["Consents"],
    summary="Add consent definition",
)
async def post_consent_route(request: web.BaseRequest):
    context = request.app["request_context"]
    body = await request.json()
    result = await add_consent(context, body["label"], body["oca_data"])

    result.pop("usage_policy", None)

    return web.json_response(result)


@response_schema(Model.ArrayOfConsents)
@docs(tags=["Consents"], summary="Get all consent definitions")
async def get_consents_route(request: web.BaseRequest):
    context = request.app["request_context"]
    records = await retrieve_from_pds(context, globals.CONSENT_DRI)
    result = []
    for i in records[0]["payload"]:
        i["content"]["oca_schema_dri"] = globals.CONSENT_DRI
        result.append(i["content"])
    return web.json_response(result)


@response_schema(Model.Consent)
@docs(tags=["Consents"], summary="Get consent by ID")
async def get_consents_by_id_route(request: web.BaseRequest):
    context = request.app["request_context"]
    consent_id = request.match_info.get("consent_id")
    result = await get_consent(context, consent_id)
    return web.json_response(result)


@docs(
    tags=["Documents"],
    summary="Get all the consents I have given to other people",
)
@response_schema(Model.ArrayOfDocuments)
async def get_consents_given_route(request: web.BaseRequest):
    context = request.app["request_context"]
    result = await retrieve_from_pds(context, globals.CONSENT_GIVEN_DRI)
    return web.json_response(result)


# TODO: WHAT IS CONSENT MINE???
@docs(
    tags=["Documents"],
    summary="Get all my consent credentials",
)
@response_schema(Model.ArrayOfDocuments)
async def get_consents_mine_route(request: web.BaseRequest):
    context = request.app["request_context"]
    result = await retrieve_from_pds(context, globals.CONSENT_MINE_DRI)
    return web.json_response(result)


consent_routes = [
    web.post("/consents", post_consent_route),
    web.get("/consents", get_consents_route, allow_head=False),
    web.get("/consents/{consent_id}", get_consents_by_id_route, allow_head=False),
    web.get(
        "/documents/given-consents",
        get_consents_given_route,
        allow_head=False,
    ),
    web.get(
        "/documents/mine-consents",
        get_consents_mine_route,
        allow_head=False,
    ),
]


async def test_get_consent_by_id():
    context = await build_context()
    try:
        consent = await get_consent(context, "1234")
        assert not "invalid codepath"
    except web.HTTPNotFound:
        print("Success: not found")


async def test_consent():
    context = await build_context()
    request = build_request_stub(
        context,
        {
            "oca_schema_dri": "consent_dri",
            "label": "TestConsentLabel",
            "oca_data": {
                "additionalProp1": "string1",
                "additionalProp2": "string",
                "additionalProp3": "string",
            },
        },
    )

    import json

    result = await call_endpoint_validate(post_consent_route, request)
    result = json.loads(result.body)
    await call_endpoint_validate(
        get_consents_by_id_route,
        build_request_stub(context, match_info={"consent_id": result["dri"]}),
    )


async def test_get_consents():
    context = await build_context()
    result = await retrieve_from_pds(context, globals.CONSENT_DRI)
    assert len(result) > 0
    await call_endpoint_validate(get_consents_route, build_request_stub(context))


async def tests():
    await test_consent()
    await test_get_consent_by_id()
    await test_get_consents()


run_standalone_async(__name__, tests)