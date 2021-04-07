from aries_cloudagent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from aries_cloudagent.storage.error import (
    StorageError,
)

from marshmallow import fields, Schema
from .consents.routes import DefinedConsent
import logging
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


class ServiceRecord(BaseRecord):
    RECORD_ID_NAME = "record_id"
    RECORD_TYPE = "verifiable_services"

    class Meta:
        schema_class = "ServiceRecordSchema"

    def __init__(
        self,
        *,
        label: str = None,
        service_schema_dri,
        consent_dri: str = None,
        state: str = None,
        record_id: str = None,
        **keyword_args,
    ):
        super().__init__(record_id, state, **keyword_args)
        self.service_schema_dri = service_schema_dri
        self.consent_dri = consent_dri
        self.label = label

    @property
    def record_value(self) -> dict:
        """Accessor to for the JSON record value properties"""
        return {
            prop: getattr(self, prop)
            for prop in (
                "service_schema_dri",
                "consent_dri",
                "label",
            )
        }

    @property
    def record_tags(self) -> dict:
        return {"label": self.label}

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
            record = current.record_value
            try:
                print(record)
                qu = await DefinedConsent.load(context, record["consent_dri"])
                record["consent_schema"] = qu.serialize()
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
            consent = await pds_load(context, record.consent_dri)
        except PDSError as err:
            raise StorageError(err.roll_up)

        record = record.record_value
        record["consent_schema"] = consent
        return record


class ServiceRecordSchema(BaseRecordSchema):
    class Meta:
        model_class = "ServiceRecord"

    label = fields.Str(required=True)
    service_id = fields.Str(required=True)
    service_schema_dri = fields.Str(required=True)
    consent_dri = fields.Str(required=True)
