from aries_cloudagent.connections.models.connection_record import ConnectionRecord
from aries_cloudagent.storage.error import StorageNotFoundError, StorageDuplicateError
from ..consents.models.defined_consent import *

from aiohttp import web
from aiohttp_apispec import docs, request_schema, match_info_schema

from marshmallow import fields, Schema
import time

# Internal
from ..models import *
from .message_types import *
from .handlers import *


class ConsentContentSchema(Schema):
    expiration = fields.Str(required=True)
    limitation = fields.Str(required=True)
    dictatedBy = fields.Str(required=True)
    validityTTL = fields.Str(required=True)


class AddServiceSchema(Schema):
    label = fields.Str(required=True)
    consent_id = fields.Str(required=True)
    service_schema = fields.Nested(ServiceSchema())


@request_schema(AddServiceSchema())
@docs(tags=["Verifiable Services"], summary="Add a verifiable service")
async def add_service(request: web.BaseRequest):
    context = request.app["request_context"]
    params = await request.json()

    try:
        await DefinedConsentRecord.retrieve_by_id(context, params["consent_id"])
    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up)

    service_record = ServiceRecord(
        label=params["label"],
        service_schema=params["service_schema"],
        consent_id=params["consent_id"],
    )

    try:
        hash_id = await service_record.save(context)
    except StorageDuplicateError:
        raise web.HTTPBadRequest(reason="Duplicate. Consent already defined.")

    return web.json_response({"success": True, "service_id": hash_id})


@docs(
    tags=["Service Discovery"],
    summary="Request a list of services from another agent",
    description="Reading the list requires webhook handling",
)
async def request_services_list(request: web.BaseRequest):
    context = request.app["request_context"]
    connection_id = request.match_info["connection_id"]
    outbound_handler = request.app["outbound_message_router"]

    try:
        connection: ConnectionRecord = await ConnectionRecord.retrieve_by_id(
            context, connection_id
        )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err)

    if connection.is_ready:
        request = Discovery()
        await outbound_handler(request, connection_id=connection_id)
        return web.json_response(
            {
                "success": True,
                "message": "SUCCESS: request sent, expect a webhook notification",
            }
        )

    raise web.HTTPNotFound("Connection with agent is not ready. ")


@docs(
    tags=["Service Discovery"],
    summary="Get a list of all services I registered",
)
async def self_service_list(request: web.BaseRequest):
    context = request.app["request_context"]

    try:
        result = await ServiceRecord().query_fully_serialized(
            context, skip_invalid=False
        )
    except StorageNotFoundError:
        raise web.HTTPNotFound

    return web.json_response({"success": True, "result": result})


class GetServiceSchema(Schema):
    service_id = fields.Str(required=True)


@docs(
    tags=["Service Discovery"],
    summary="Get a service registered by ME",
)
@match_info_schema(GetServiceSchema)
async def get_service(request: web.BaseRequest):
    context = request.app["request_context"]
    service_id = request.match_info["service_id"]

    result = await ServiceRecord.routes_retrieve_by_id_fully_serialized(
        context, service_id
    )

    return web.json_response({"success": True, "result": result})


discovery_routes = [
    web.post("/verifiable-services/add", add_service),
    web.get(
        "/verifiable-services/request-service-list/{connection_id}",
        request_services_list,
        allow_head=False,
    ),
    web.get(
        "/verifiable-services/self-service-list",
        self_service_list,
        allow_head=False,
    ),
    web.get(
        "/verifiable-services/service/{service_id}",
        get_service,
        allow_head=False,
    ),
]