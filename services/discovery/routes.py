from aries_cloudagent.connections.models.connection_record import ConnectionRecord
from aries_cloudagent.storage.error import StorageNotFoundError

from aiohttp import web
from aiohttp_apispec import docs


# Internal
from ..models import *
from .message_types import *
from .handlers import *


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


discovery_routes = [
    web.get(
        "/verifiable-services/request-service-list/{connection_id}",
        request_services_list,
        allow_head=False,
    ),
]