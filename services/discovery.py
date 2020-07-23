# Acapy
from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    RequestContext,
)
from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.core.plugin_registry import PluginRegistry
from aries_cloudagent.protocols.connections.v1_0.manager import ConnectionManager

# Records, messages and schemas
from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from aries_cloudagent.connections.models.connection_record import ConnectionRecord
from aries_cloudagent.storage.record import StorageRecord

# Exceptions
from aries_cloudagent.storage.error import StorageDuplicateError, StorageNotFoundError
from aries_cloudagent.protocols.problem_report.v1_0.message import ProblemReport

# Internal
from .records import (
    ServiceRecord,
    ServiceRecordSchema,
    ConsentSchema,
    ServiceSchema,
    ServiceDiscoveryRecord,
)
from .message_types import (
    PROTOCOL_PACKAGE_DISCOVERY as PROTOCOL_PACKAGE,
    DISCOVERY,
    DISCOVERY_RESPONSE,
)
from .util import generate_model_schema

# External
from marshmallow import fields, Schema
import hashlib
import uuid
import json


Discovery, DiscoverySchema = generate_model_schema(
    name="Discovery",
    handler=f"{PROTOCOL_PACKAGE}.DiscoveryHandler",
    msg_type=DISCOVERY,
    schema={},
)


class DiscoveryServiceSchema(Schema):
    label = fields.Str(required=True)
    service_schema = fields.Nested(ServiceSchema())
    consent_schema = fields.Nested(ConsentSchema())


class DiscoveryResponse(AgentMessage):
    class Meta:
        handler_class = f"{PROTOCOL_PACKAGE}.DiscoveryResponseHandler"
        message_type = DISCOVERY_RESPONSE
        schema_class = "DiscoveryResponseSchema"

    def __init__(self, *, services: DiscoveryServiceSchema = None, **kwargs):
        super(DiscoveryResponse, self).__init__(**kwargs)
        self.services = services


class DiscoveryResponseSchema(AgentMessageSchema):
    """DiscoveryResponse message schema used in serialization/deserialization."""

    class Meta:
        model_class = DiscoveryResponse

    services = fields.List(fields.Nested(DiscoveryServiceSchema()), required=True,)


class DiscoveryHandler(BaseHandler):
    async def handle(self, context: RequestContext, responder: BaseResponder):
        storage: BaseStorage = await context.inject(BaseStorage)

        self._logger.debug("SERVICES DISCOVERY %s, ", context)
        assert isinstance(context.message, Discovery)

        query = await ServiceRecord().query(context)

        response = DiscoveryResponse(services=query)
        response.assign_thread_from(context.message)
        await responder.send_reply(response)


class DiscoveryResponseHandler(BaseHandler):
    async def handle(self, context: RequestContext, responder: BaseResponder):
        self._logger.debug("SERVICES DISCOVERY RESPONSE %s, ", context)
        assert isinstance(context.message, DiscoveryResponse)

        connection_id = context.connection_record.connection_id
        print(context.message.services)

        try:
            record: ServiceDiscoveryRecord = ServiceDiscoveryRecord(
                services=context.message.services, connection_id=connection_id,
            )

            print(record)
            if context.message.services != []:
                assert record.services != []

            await record.save(context)
        except StorageDuplicateError:
            record = await ServiceDiscoveryRecord.retrieve_by_connection_id(
                context, connection_id
            )
            record.services = context.message.services
            await record.save(context)

