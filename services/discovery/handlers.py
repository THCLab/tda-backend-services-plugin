# Acapy
from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    RequestContext,
)
from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.config.injection_context import InjectionContext

# Records, messages and schemas
from aries_cloudagent.storage.record import StorageRecord

# Exceptions
from aries_cloudagent.storage.error import (
    StorageNotFoundError,
    StorageError,
)

# Internal
from ..models import *
from .message_types import *

# External
from marshmallow import fields
import json
import logging

from ..util import verify_usage_policy
from aries_cloudagent.pdstorage_thcf.api import *
from aries_cloudagent.aathcf.utils import debug_handler

LOGGER = logging.getLogger(__name__)


class DiscoveryHandler(BaseHandler):
    async def handle(self, context: RequestContext, responder: BaseResponder):
        debug_handler(self._logger.debug, context, Discovery)

        usage_policy = await pds_get_usage_policy_if_active_pds_supports_it(context)
        records = await ServiceRecord.query_fully_serialized(context)
        response = DiscoveryResponse(services=records, usage_policy=usage_policy)
        response.assign_thread_from(context.message)
        await responder.send_reply(response)


class DiscoveryResponseHandler(BaseHandler):    
    async def handle(self, context: RequestContext, responder: BaseResponder):
        debug_handler(self._logger.debug, context, DiscoveryResponse)
        connection_id = context.connection_record.connection_id

        services = context.message.services
        for i in services:
            i.pop("created_at", None)
            i.pop("updated_at", None)
            i.pop("consent_dri", None)

        storage: BaseStorage = await context.inject(BaseStorage)
        services_serialized = json.dumps(services)

        """
        Check if service list from agent exists. If it exists overwrite it with new version, 
        else create and save a service list
        """
        try:
            query = storage.search_records(
                "service_list", {"connection_id": connection_id}
            )
            query = await query.fetch_single()
            await storage.update_record_value(query, services_serialized)
            LOGGER.info("QUERY %s", query)
        except StorageError:
            record = StorageRecord(
                "service_list", services_serialized, {"connection_id": connection_id}
            )
            await storage.add_record(record)
            LOGGER.info("ADD RECORD %s", record)

        await responder.send_webhook(
            "verifiable-services/request-service-list",
            {"connection_id": connection_id, "services": services},
        )

        # TODO: We only need to check usage_policy once !!!!!!!!
        # this is so that things dont break on frontend
        usage_policy = await pds_get_usage_policy_if_active_pds_supports_it(context)
        if usage_policy:
            for i in services:
                result = {}
                result[i["service_id"]] = await verify_usage_policy(
                    i["consent_schema"]["usage_policy"], usage_policy
                )
                await responder.send_webhook(
                    "verifiable-services/request-service-list/usage-policy",
                    result,
                )
