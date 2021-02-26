from os import stat
from aiohttp import web
from aiohttp_apispec import docs, request_schema, querystring_schema
from aries_cloudagent.config.base import ConfigError
from marshmallow import fields, Schema
from aries_cloudagent.pdstorage_thcf.api import *
from aries_cloudagent.storage.error import StorageError
from .models.defined_consent import *
from .models.given_consent import ConsentGivenRecord
import aries_cloudagent.generated_models as Model

CONSENTS_TABLE = "consents"


class AddConsentSchema(Schema):
    label = fields.Str(required=True)
    oca_data = fields.Dict(required=True)
    oca_schema_dri = fields.Str(required=True)
    oca_schema_namespace = fields.Str(required=True)


@request_schema(Model.Consent)
@docs(
    tags=["Consents"],
    summary="Add consent definition",
)
async def post_consent(request: web.BaseRequest):
    context = request.app["request_context"]
    body = await request.json()

    oca_data_dri = await pds_save(context, body["oca_data"], body["oca_schema_dri"])

    pds_usage_policy = await pds_get_usage_policy_if_active_pds_supports_it(context)
    pds_name = await pds_active_get_full_name(context)

    record = DefinedConsentRecord(
        label=body["label"],
        oca_schema_dri=body["oca_schema_dri"],
        oca_data_dri=oca_data_dri,
        pds_name=str(pds_name),
        usage_policy=pds_usage_policy,
    )

    result = record.serialize()
    result["consent_uuid"] = await record.save(context)
    result["oca_data"] = body["oca_data"]

    return web.json_response(result)


@docs(
    tags=["Consents"],
    summary="Removes consent by its uuid",
)
async def delete_consent(request: web.BaseRequest):
    context = request.app["request_context"]
    consent_id = request.match_info["consent_uuid"]

    try:
        record = await DefinedConsentRecord.retrieve_by_id(context, consent_id)
    except StorageNotFoundError:
        return web.json_response(status=404)

    await record.delete_record(context)

    return web.json_response()


@docs(tags=["Consents"], summary="Get all consent definitions")
async def get_consents(request: web.BaseRequest):
    context = request.app["request_context"]

    pds_name = await pds_active_get_full_name(context)
    all_consents = await DefinedConsentRecord.query(
        context, {"pds_name": str(pds_name)}
    )

    result = []
    for consent in all_consents:
        current = consent.serialize()
        current["consent_uuid"] = consent.consent_id
        oca_data = await pds_load(context, current["oca_data_dri"])

        if oca_data:
            current["oca_data"] = oca_data

        result.append(current)

    return web.json_response(result)


class GetConsentsGivenQuerySchema(Schema):
    connection_id = fields.Str(required=False)


@docs(
    tags=["Defined Consents"],
    summary="Get all the consents I have given to other people",
)
@querystring_schema(GetConsentsGivenQuerySchema)
async def get_consents_given(request: web.BaseRequest):
    context = request.app["request_context"]

    try:
        all_consents = await ConsentGivenRecord.query(context, request.query)
    except StorageError as err:
        raise web.HTTPInternalServerError(reason=err)

    result = []
    for i in all_consents:
        record = i.serialize()
        record["credential"] = await i.credential_pds_get(context)
        result.append(record)

    return web.json_response({"success": True, "result": result})


consent_routes = [
    web.post("/consents", post_consent),
    web.get("/consents", get_consents, allow_head=False),
    web.delete("/consents/{consent_uuid}", delete_consent),
    web.get(
        "/verifiable-services/given-consents",
        get_consents_given,
        allow_head=False,
    ),
]