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
from aries_cloudagent.storage.error import (
    StorageDuplicateError,
    StorageNotFoundError,
    StorageError,
)
from aries_cloudagent.protocols.problem_report.v1_0.message import ProblemReport

# Internal
from ..models import *
from .message_types import *
from ..util import generate_model_schema

# External
from marshmallow import fields, Schema
import hashlib
import uuid
import json

from ..util import verify_usage_policy
from aries_cloudagent.pdstorage_thcf.api import *
from aries_cloudagent.aathcf.utils import debug_handler


class DiscoveryHandler(BaseHandler):
    async def handle(self, context: RequestContext, responder: BaseResponder):
        debug_handler(self._logger.debug, context, Discovery)

        usage_policy = await pds_get_usage_policy_if_active_pds_supports_it(context)
        records = await ServiceRecord.query_fully_serialized(context)
        response = DiscoveryResponse(services=records, usage_policy=usage_policy)
        response.assign_thread_from(context.message)
        await responder.send_reply(response)


def trim_acapy_fields(list_of_dict):
    for i in list_of_dict:
        i.pop("created_at", None)
        i.pop("updated_at", None)
        i.pop("consent_id", None)


class DiscoveryResponseHandler(BaseHandler):
    async def handle(self, context: RequestContext, responder: BaseResponder):
        debug_handler(self._logger.debug, context, DiscoveryResponse)
        connection_id = context.connection_record.connection_id

        services = context.message.services
        his_usage_policy = context.message.usage_policy
        trim_acapy_fields(services)

        storage: BaseStorage = await context.inject(BaseStorage)

        services_serialized = json.dumps(services)
        try:
            query = storage.search_records(
                "service_list", {"connection_id": connection_id}
            )
            query = await query.fetch_single()
            await storage.update_record_value(query, services_serialized)
            print("QUERY", query)
        except StorageError:
            record = StorageRecord(
                "service_list", services_serialized, {"connection_id": connection_id}
            )
            await storage.add_record(record)
            print("ADD RECORD ", record)

        await responder.send_webhook(
            "verifiable-services/request-service-list",
            {"connection_id": connection_id, "services": services_serialized},
        )

        # TODO: We only need to check usage_policy once !!!!!!!!
        # this is so that things dont break on frontend
        usage_policy = await pds_get_usage_policy_if_active_pds_supports_it(context)
        if usage_policy and his_usage_policy:
            for i in services:
                result = {}
                result[i["service_id"]] = await verify_usage_policy(
                    usage_policy, his_usage_policy
                )
                await responder.send_webhook(
                    "verifiable-services/request-service-list/usage-policy", result,
                )


"""
DEBUG
"""


class DEBUGServiceDiscoveryRecord(BaseRecord):
    RECORD_ID_NAME = "record_id"
    RECORD_TYPE = "DEBUGservice_discovery"

    class Meta:
        schema_class = "DEBUGServiceDiscoveryRecordSchema"

    def __init__(
        self,
        *,
        services=None,
        connection_id: str = None,
        state: str = None,
        record_id: str = None,
        **keywordArgs,
    ):
        super().__init__(record_id, state, **keywordArgs)
        self.services = services
        self.connection_id = connection_id

    @property
    def record_value(self) -> dict:
        """Accessor to for the JSON record value properties"""
        return {prop: getattr(self, prop) for prop in ("services", "connection_id")}

    @property
    def record_tags(self) -> dict:
        """Get tags for record"""
        return {
            "connection_id": self.connection_id,
        }

    @classmethod
    async def retrieve_by_connection_id(
        cls, context: InjectionContext, connection_id: str
    ):
        return await cls.retrieve_by_tag_filter(
            context, {"connection_id": connection_id},
        )


class DEBUGServiceDiscoveryRecordSchema(BaseRecordSchema):
    class Meta:
        model_class = "DEBUGServiceDiscoveryRecord"

    services = fields.List(fields.Dict())
    connection_id = fields.Str()


class DEBUGDiscoveryHandler(BaseHandler):
    async def handle(self, context: RequestContext, responder: BaseResponder):
        debug_handler(self._logger.debug, context, DEBUGDiscovery)

        records = await ServiceRecord().query_fully_serialized(context)
        response = DEBUGDiscoveryResponse(services=records)
        response.assign_thread_from(context.message)
        await responder.send_reply(response)


class DEBUGDiscoveryResponseHandler(BaseHandler):
    async def handle(self, context: RequestContext, responder: BaseResponder):
        debug_handler(self._logger.debug, context, DEBUGDiscoveryResponse)
        connection_id = context.connection_record.connection_id

        services = context.message.services
        trim_acapy_fields(services)

        try:
            record = await DEBUGServiceDiscoveryRecord.retrieve_by_connection_id(
                context, connection_id
            )
            record.services = services
        except StorageNotFoundError:
            record: DEBUGServiceDiscoveryRecord = DEBUGServiceDiscoveryRecord(
                services=services, connection_id=connection_id,
            )

        await record.save(context)
