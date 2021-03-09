from aiohttp import web
from aiohttp_apispec import docs, request_schema, querystring_schema
from marshmallow import fields, Schema
from aries_cloudagent.pdstorage_thcf.api import *
import aries_cloudagent.generated_models as Model


class DefinedConsent:
    def __init__(self, label, usage_policy, oca_data):
        self.label = label
        self.usage_policy = usage_policy
        self.oca_data = oca_data


class ConsentGiven:
    def __init__(self, credential, connection_id):
        self.credential = credential
        self.connection_id = connection_id


@request_schema(Model.Consent)
@docs(
    tags=["Consents"],
    summary="Add consent definition",
)
async def post_consent(request: web.BaseRequest):
    context = request.app["request_context"]
    body = await request.json()

    pds_usage_policy = await pds_get_usage_policy_if_active_pds_supports_it(context)
    model = DefinedConsent(body["label"], pds_usage_policy, body["oca_data"])
    dri = await pds_save_model(context, model, oca_schema_dri=body["oca_schema_dri"])
    fetch = await pds_load_model(context, dri, DefinedConsent)
    result = fetch.__dict__
    result["dri"] = dri
    result["oca_schema_dri"] = body["oca_schema_dri"]

    return web.json_response(result)


async def retrieve_from_pds(request, oca_schema_dri):
    context = request.app["request_context"]
    try:
        result = await pds_query_model_by_oca_schema_dri(context, oca_schema_dri)
    except PDSError as err:
        raise web.HTTPInternalServerError(reason=err.roll_up)
    return result


@docs(tags=["Consents"], summary="Get all consent definitions")
async def get_consents(request: web.BaseRequest):
    consent_oca_schema_dri = "consent_dri"
    result = await retrieve_from_pds(request, consent_oca_schema_dri)
    for i in result:
        i["oca_schema_dri"] = consent_oca_schema_dri
    return web.json_response(result)


@docs(
    tags=["Documents"],
    summary="Get all the consents I have given to other people",
)
async def get_consents_given(request: web.BaseRequest):
    result = await retrieve_from_pds(request, "consent_given")
    return web.json_response(result)


@docs(
    tags=["Documents"],
    summary="Get all my consent credentials",
)
async def get_consents_mine(request: web.BaseRequest):
    result = await retrieve_from_pds(request, "consent_mine")
    return web.json_response(result)


consent_routes = [
    web.post("/consents", post_consent),
    web.get("/consents", get_consents, allow_head=False),
    web.get(
        "/documents/given-consents",
        get_consents_given,
        allow_head=False,
    ),
    web.get(
        "/documents/mine-consents",
        get_consents_mine,
        allow_head=False,
    ),
]