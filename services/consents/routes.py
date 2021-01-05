from aiohttp import web
from aiohttp_apispec import docs, request_schema

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
@docs(tags=["Defined Consents"], summary="Add consent definition")
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
        metadata = {
            "oca_schema_dri": params["oca_schema_dri"],
            "table": CONSENTS_TABLE,
        }

        """
        If pds supports usage policy then pack it into consent
        """

        oca_data_dri = await save_string(
            context, json.dumps(params["oca_data"]), json.dumps(metadata)
        )

        defined_consent = DefinedConsentRecord(
            label=params["label"],
            oca_schema_dri=params["oca_schema_dri"],
            oca_schema_namespace=params["oca_schema_namespace"],
            oca_data_dri=oca_data_dri,
        )

        consent_id = await defined_consent.save(context)

        return web.json_response({"success": True, "consent_id": consent_id})


@docs(tags=["Defined Consents"], summary="Get all consent definitions")
async def get_consents(request: web.BaseRequest):
    context = request.app["request_context"]

    try:
        all_consents = await DefinedConsentRecord.query(context, {})
    except StorageError as err:
        raise web.HTTPInternalServerError(reason=err)

    result = list(map(lambda el: el.record_value, all_consents))
    for consent in result:
        oca_data = await load_string(context, consent["oca_data_dri"])
        if oca_data:
            consent["oca_data"] = json.loads(oca_data)
        else:
            consent["oca_data"] = None

    return web.json_response({"success": True, "result": result})


@docs(
    tags=["Defined Consents"],
    summary="Get all the consents I have given to other people",
)
async def get_consents_given(request: web.BaseRequest):
    context = request.app["request_context"]

    try:
        all_consents = await ConsentGivenRecord.query(context)
    except StorageError as err:
        raise web.HTTPInternalServerError(reason=err)
    serialized = [i.serialize() for i in all_consents]

    return web.json_response({"success": True, "result": serialized})
