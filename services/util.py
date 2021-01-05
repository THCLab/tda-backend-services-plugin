import sys
import logging
import functools
from datetime import datetime, timezone
from dateutil.parser import isoparse
from aiohttp import web

from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.storage.error import *
from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    RequestContext,
)
from aiohttp import ClientSession, FormData, ClientTimeout
from .issue.models import ServiceIssueRecord
from .models import ServiceRecord


async def verify_usage_policy(controller_usage_policy, subject_usage_policy):
    # print("Controller usage policy:", controller_usage_policy)
    # print("Subject usage policy:", subject_usage_policy)
    timeout = ClientTimeout(total=15)
    async with ClientSession(timeout=timeout) as session:
        result = await session.post(
            "https://governance.ownyourdata.eu/api/usage-policy/match",
            json={
                "data-subject": subject_usage_policy,
                "data-controller": controller_usage_policy,
            },
        )
        result = await result.text()
        return result


async def retrieve_service_issue(context, issue_id):
    try:
        issue: ServiceIssueRecord = await ServiceIssueRecord.retrieve_by_id(
            context, issue_id
        )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(
            reason=f"Service Issue with ID {issue_id} not found {err.roll_up}"
        )
    except StorageError as err:
        raise web.HTTPInternalServerError(
            reason=f"Oops: This was not supposed to happen, ID: {issue_id}, Error: {err.roll_up}"
        )

    return issue


async def retrieve_service(context, service_id):
    try:
        service: ServiceRecord = await ServiceRecord.retrieve_by_id(context, service_id)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(
            reason=f"Service Record with ID {service_id} not found {err.roll_up}"
        )
    except StorageError as err:
        raise web.HTTPInternalServerError(
            reason=f"Oops: This was not supposed to happen, ID: {service_id}, Error: {err.roll_up}"
        )

    return service


def generic_init(instance, **kwargs):
    """Initialize from kwargs into slots."""
    for slot in instance.__slots__:
        setattr(instance, slot, kwargs.get(slot))
        if slot in kwargs:
            del kwargs[slot]
    super(type(instance), instance).__init__(**kwargs)


def generate_model_schema(
    name: str, handler: str, msg_type: str, schema: dict, *, init: callable = None
):
    """Generate a Message model class and schema class programmatically.

    The following would result in a class named XYZ inheriting from
    AgentMessage and XYZSchema inheriting from AgentMessageSchema.

    XYZ, XYZSchema = generate_model_schema(
        name='XYZ',
        handler='aries_cloudagent.admin.handlers.XYZHandler',
        msg_type='{}/xyz'.format(PROTOCOL),
        schema={}
    )

    The attributes of XYZ are determined by schema's keys. The actual
    schema of XYZSchema is defined by the field-value combinations of
    schema_dict, similar to marshmallow's Schema.from_dict() (can't actually
    use that here as the model_class must be set in the Meta inner-class of
    AgentMessageSchemas).

    Example:

    RecordsGet, RecordsGetSchema = generate_model_schema(
        name="RecordsGet",
        handler=RECORDS_GET_HANDLER,
        msg_type=RECORDS_GET,
        schema={"record_id": fields.Str(required=True),},
    )

    Pretty much equivalent to:

    class RecordsGet(AgentMessage):
        class Meta:
            handler_class = RECORDS_GET_HANDLER
            message_type = RECORDS_GET
            schema_class = "RecordsGetSchema"

        def __init__(self, record_id: str, **kwargs):
            super(RecordsGet, self).__init__(**kwargs)
            self.record_id = record_id


    class RecordsGetSchema(AgentMessageSchema):
        class Meta:
            model_class = RecordsGet

        record_id = fields.Str(required=True)

    """
    if isinstance(schema, dict):
        slots = list(schema.keys())
        schema_dict = schema
    elif hasattr(schema, "_declared_fields"):
        slots = list(schema._declared_fields.keys())
        schema_dict = schema._declared_fields
    else:
        raise TypeError("Schema must be dict or class defining _declared_fields")

    class Model(AgentMessage):
        """Generated Model."""

        __slots__ = slots
        __qualname__ = name
        __name__ = name
        __module__ = sys._getframe(2).f_globals["__name__"]
        __init__ = init if init else generic_init

        class Meta:
            """Generated Meta."""

            __qualname__ = name + ".Meta"
            handler_class = handler
            message_type = msg_type
            schema_class = name + "Schema"

    class Schema(AgentMessageSchema):
        """Generated Schema."""

        __qualname__ = name + "Schema"
        __name__ = name + "Schema"
        __module__ = sys._getframe(2).f_globals["__name__"]

        class Meta:
            """Generated Schema Meta."""

            __qualname__ = name + "Schema.Meta"
            model_class = Model

    Schema._declared_fields.update(schema_dict)

    return Model, Schema
