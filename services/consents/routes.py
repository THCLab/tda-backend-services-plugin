from aiohttp import web
from aiohttp_apispec import docs, request_schema, querystring_schema

from marshmallow import fields, Schema
import json

from aries_cloudagent.pdstorage_thcf.api import *
from aries_cloudagent.storage.error import StorageError
from .models.defined_consent import *
from .models.given_consent import ConsentGivenRecord
from ..models import ConsentSchema

CONSENTS_TABLE = "consents"


class AddConsentSchema(Schema):
    label = fields.Str(required=True)
    oca_data = fields.Dict(required=True)
    oca_schema_dri = fields.Str(required=True)
    oca_schema_namespace = fields.Str(required=True)


@request_schema(AddConsentSchema())
@docs(
    tags=["Defined Consents"],
    summary="Add consent definition",
    description="""
    "oca_data": {
            "expiration": "7200",
            "limitation": "7200",
            "dictatedBy": "test",
            "validityTTL": "7200",
        }
""",
)
async def add_consent(request: web.BaseRequest):
    context = request.app["request_context"]
    params = await request.json()
    errors = []

    try:
        existing_consents = await DefinedConsentRecord.query(
            context, {"label": params["label"]}
        )
    except StorageError as err:
        raise web.HTTPInternalServerError(reason=err)

    if existing_consents:
        errors.append(f"Consent with '{params['label']}' label is already defined")

    if errors:
        return web.json_response({"success": False, "errors": errors})
    else:
        oca_data_dri = await pds_save_a(
            context,
            params["oca_data"],
            table=CONSENTS_TABLE,
            oca_schema_dri=params["oca_schema_dri"],
        )

        pds_usage_policy = await pds_get_usage_policy_if_active_pds_supports_it(context)

        pds_name = await pds_get_active_name(context)
        defined_consent = DefinedConsentRecord(
            label=params["label"],
            oca_schema_dri=params["oca_schema_dri"],
            oca_schema_namespace=params["oca_schema_namespace"],
            oca_data_dri=oca_data_dri,
            pds_name=str(pds_name),
            usage_policy=pds_usage_policy,
        )

        consent_id = await defined_consent.save(context)

        return web.json_response({"success": True, "consent_id": consent_id})


@docs(tags=["Defined Consents"], summary="Get all consent definitions")
async def get_consents(request: web.BaseRequest):
    context = request.app["request_context"]

    try:
        pds_name = await pds_get_active_name(context)
        all_consents = await DefinedConsentRecord.query(
            context, {"pds_name": str(pds_name)}
        )
    except StorageError as err:
        raise web.HTTPNotFound(reason=err)

    result = []
    for consent in all_consents:
        current = consent.serialize()
        current["consent_id"] = consent.consent_id
        oca_data = await pds_load(context, current["oca_data_dri"])

        if oca_data:
            current["oca_data"] = oca_data
        else:
            current["oca_data"] = None

        result.append(current)

    return web.json_response({"success": True, "result": result})


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
