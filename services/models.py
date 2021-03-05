from aries_cloudagent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from aries_cloudagent.storage.error import (
    StorageError,
    StorageNotFoundError,
)

from marshmallow import fields, Schema
from .consents.models.defined_consent import DefinedConsentRecord
from .consents.routes import DefinedConsent
import logging
from aiohttp import web
from aries_cloudagent.pdstorage_thcf.api import *

LOGGER = logging.getLogger(__name__)


class ConsentSchema(Schema):
    # dri - decentralized resource identifier
    oca_schema_dri = fields.Str(required=False)
    oca_schema_namespace = fields.Str(required=False)
    oca_data_dri = fields.Str(required=False)
    oca_data = fields.Dict()
    usage_policy = fields.Str(required=False)


class ServiceSchema(Schema):
    oca_schema_dri = fields.Str(required=True)
    oca_schema_namespace = fields.Str(required=True)


class OcaSchema(Schema):
    oca_schema_dri = fields.Str(required=False)
    oca_schema_namespace = fields.Str(required=False)


class ServiceRecord(BaseRecord):
    RECORD_ID_NAME = "record_id"
    RECORD_TYPE = "verifiable_services"
    CONNECTION_ID_SELF = "mine"

    class Meta:
        schema_class = "ServiceRecordSchema"

    def __init__(
        self,
        *,
        label: str = None,
        service_schema_dri,
        consent_id: str = None,
        state: str = None,
        record_id: str = None,
        connection_id: str = CONNECTION_ID_SELF,
        **keyword_args,
    ):
        super().__init__(record_id, state, **keyword_args)
        self.service_schema_dri = service_schema_dri
        self.connection_id = connection_id
        self.consent_id = consent_id
        self.label = label

    @property
    def record_value(self) -> dict:
        """Accessor to for the JSON record value properties"""
        return {
            prop: getattr(self, prop)
            for prop in (
                "connection_id",
                "service_schema_dri",
                "consent_id",
                "label",
            )
        }

    @property
    def record_tags(self) -> dict:
        return {"label": self.label, "connection_id": self.connection_id}

    @classmethod
    async def query_fully_serialized(
        cls,
        context,
        *,
        tag_filter=None,
        positive_filter=None,
        negative_filter=None,
        skip_invalid=True,
    ):
        "Serializes consents with backing of valid PDS records"
        query = await cls.query(
            context,
            tag_filter=tag_filter,
            post_filter_positive=positive_filter,
            post_filter_negative=negative_filter,
        )

        result = []
        for current in query:
            record = current.serialize()
            try:
                record["consent_schema"] = await pds_load_model(
                    context, record["consent_id"], DefinedConsent
                )
                record["consent_schema"] = record["consent_schema"].__dict__
            except PDSError as err:
                if skip_invalid:
                    LOGGER.warn(
                        "Consent not found when serializing service %s", err.roll_up
                    )
                    continue
                else:
                    record["consent_schema"] = {
                        "msg": "Failed to fetch consent!",
                        "exception": err.roll_up,
                    }

            record["service_uuid"] = current._id

            result.append(record)

        return result

    @classmethod
    async def retrieve_by_id_fully_serialized(cls, context, id):
        record = await cls.retrieve_by_id(context, id)
        try:
            consent = await pds_load_model(context, record.consent_id, DefinedConsent)
        except PDSError as err:
            raise StorageError(err.roll_up)

        record = record.serialize()
        record["consent_schema"] = consent
        record.pop("created_at", None)
        record.pop("updated_at", None)

        return record


class ServiceRecordSchema(BaseRecordSchema):
    class Meta:
        model_class = "ServiceRecord"

    label = fields.Str(required=True)
    service_id = fields.Str(required=True)
    service_schema_dri = fields.Str(required=True)
    consent_id = fields.Str(required=True)
    connection_id = fields.Str(required=True)
