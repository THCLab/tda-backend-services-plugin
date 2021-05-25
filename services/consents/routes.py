from aiohttp import web
from aiohttp_apispec import docs, request_schema
from aries_cloudagent.aathcf.utils import (
    build_context,
    run_standalone_async,
    build_request_stub,
)
from aries_cloudagent.pdstorage_thcf.api import (
    pds_get_usage_policy_if_active_pds_supports_it,
    pds_load,
    pds_query_model_by_oca_schema_dri,
    PDSError,
    pds_save,
)
import aries_cloudagent.generated_models as Model
import logging


LOGGER = logging.getLogger(__name__)


async def add_consent(context, label, oca_data, oca_schema_dri):
    model = {"label": label, "oca_data": oca_data}
    pds_usage_policy = await pds_get_usage_policy_if_active_pds_supports_it(context)
    if pds_usage_policy:
        model.update({"usage_policy": pds_usage_policy})
    dri = await pds_save(context, model, oca_schema_dri=oca_schema_dri)
    record = await pds_load(context, dri, with_meta_embed=True)
    record["dri"] = dri
    return record


async def retrieve_from_pds(context, oca_schema_dri):
    try:
        result = await pds_query_model_by_oca_schema_dri(context, oca_schema_dri)
    except PDSError as err:
        raise web.HTTPInternalServerError(reason=err.roll_up)
    return result


@request_schema(Model.Consent)
@docs(
    tags=["Consents"],
    summary="Add consent definition",
)
async def post_consent_api(request: web.BaseRequest):
    context = request.app["request_context"]
    body = await request.json()
    LOGGER.info("post_consent_api, body: %s", body)
    result = await add_consent(
        context, body["label"], body["oca_data"], body["oca_schema_dri"]
    )
    result.pop("usage_policy", None)

    return web.json_response(result)


@docs(tags=["Consents"], summary="Get all consent definitions")
async def get_consents_api(request: web.BaseRequest):
    consent_oca_schema_dri = "consent_dri"
    context = request.app["request_context"]
    result = await retrieve_from_pds(context, consent_oca_schema_dri)
    for i in result:
        i["oca_schema_dri"] = consent_oca_schema_dri
    return web.json_response(result)


@docs(
    tags=["Documents"],
    summary="Get all the consents I have given to other people",
)
async def get_consents_given_api(request: web.BaseRequest):
    context = request.app["request_context"]
    result = await retrieve_from_pds(context, "consent_given")
    return web.json_response(result)


@docs(
    tags=["Documents"],
    summary="Get all my consent credentials",
)
async def get_consents_mine_api(request: web.BaseRequest):
    context = request.app["request_context"]
    result = await retrieve_from_pds(context, "consent_mine")
    return web.json_response(result)


consent_routes = [
    web.post("/consents", post_consent_api),
    web.get("/consents", get_consents_api, allow_head=False),
    web.get(
        "/documents/given-consents",
        get_consents_given_api,
        allow_head=False,
    ),
    web.get(
        "/documents/mine-consents",
        get_consents_mine_api,
        allow_head=False,
    ),
]


async def test_consent():
    context = await build_context("local")
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

    result = await post_consent_api(request)
    print(result.body)


run_standalone_async(__name__, test_consent)