from aries_cloudagent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.storage.error import StorageDuplicateError
from aries_cloudagent.messaging.util import datetime_to_str, time_now

import hashlib
from marshmallow import fields, Schema
from typing import Mapping, Any
import uuid
import json
from .consents.models.defined_consent import DefinedConsentRecord
import logging

LOGGER = logging.getLogger(__name__)


class ConsentContentSchema(Schema):
    expiration = fields.Str(required=True)
    limitation = fields.Str(required=True)
    dictatedBy = fields.Str(required=True)
    validityTTL = fields.Str(required=True)


class ConsentSchema(Schema):
    # dri - decentralized resource identifier
    oca_schema_dri = fields.Str(required=False)
    oca_schema_namespace = fields.Str(required=False)
    oca_data_dri = fields.Str(required=False)
    oca_data = fields.Dict()


class ServiceSchema(Schema):
    oca_schema_dri = fields.Str(required=True)
    oca_schema_namespace = fields.Str(required=True)


class OcaSchema(Schema):
    oca_schema_dri = fields.Str(required=False)
    oca_schema_namespace = fields.Str(required=False)


class ServiceRecord(BaseRecord):
    RECORD_ID_NAME = "record_id"
    RECORD_TYPE = "verifiable_services"

    class Meta:
        schema_class = "ServiceRecordSchema"

    def __init__(
        self,
        *,
        label: str = None,
        service_schema: ServiceSchema = None,
        consent_id: str = None,
        state: str = None,
        record_id: str = None,
        **keyword_args,
    ):
        super().__init__(record_id, state, **keyword_args)
        self.service_schema = service_schema
        self.consent_id = consent_id
        self.label = label

    @property
    def record_value(self) -> dict:
        """Accessor to for the JSON record value properties"""
        return {
            prop: getattr(self, prop)
            for prop in (
                "service_schema",
                "consent_id",
                "label",
            )
        }

    @property
    def record_tags(self) -> dict:
        return {"label": self.label}

    @classmethod
    async def query_fully_serialized(
        cls, context, tag_filter=None, positive_filter=None, negative_filter=None
    ):
        query = await cls.query(
            context,
            tag_filter=tag_filter,
            post_filter_positive=positive_filter,
            post_filter_negative=negative_filter,
        )

        result = []
        for current in query:
            record = current.serialize()
            consent = await DefinedConsentRecord.retrieve_by_id_fully_serialized(
                context, record["consent_id"]
            )
            record["consent_schema"] = consent
            record["service_id"] = current._id

            result.append(record)

        return result

    @classmethod
    async def retrieve_by_id_fully_serialized(cls, context, id):
        record = await cls.retrieve_by_id(context, id)
        consent = await DefinedConsentRecord.retrieve_by_id_fully_serialized(
            context, record.consent_id
        )

        record = record.serialize()
        record["consent_schema"] = consent
        record.pop("created_at", None)
        record.pop("updated_at", None)

        return record

    @classmethod
    async def routes_retrieve_by_id_fully_serialized(cls, context, id):
        try:
            record = await cls.retrieve_by_id_fully_serialized(context, id)
        except PersonalDataStorageNotFoundError as err:
            raise web.HTTPNotFound(reason=err)
        except StorageNotFoundError as err:
            raise web.HTTPNotFound(reason=err)
        except PersonalDataStorageError as err:
            raise web.HTTPInternalServerError(reason=err)
        except StorageError as err:
            raise web.HTTPInternalServerError(reason=err)

        return record


class ServiceRecordSchema(BaseRecordSchema):
    class Meta:
        model_class = "ServiceRecord"

    label = fields.Str(required=True)
    service_id = fields.Str(required=True)
    service_schema = fields.Nested(ServiceSchema())
    consent_id = fields.Str(required=True)
