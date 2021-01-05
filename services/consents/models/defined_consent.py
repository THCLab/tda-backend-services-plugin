from aries_cloudagent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from marshmallow import fields

from aries_cloudagent.pdstorage_thcf.api import *
from aries_cloudagent.pdstorage_thcf.error import *
import json

from aries_cloudagent.storage.error import *
from aiohttp import web


class DefinedConsentRecord(BaseRecord):
    RECORD_ID_NAME = "record_id"
    RECORD_TYPE = "defined_consent"

    class Meta:
        schema_class = "DefinedConsentRecordSchema"

    def __init__(
        self,
        *,
        label: str = None,
        oca_schema_dri: str = None,
        oca_schema_namespace: str = None,
        oca_data_dri: str = None,
        state: str = None,
        record_id: str = None,
        **keyword_args,
    ):
        super().__init__(record_id, state, **keyword_args)
        self.label = label
        self.oca_data_dri = oca_data_dri
        self.oca_schema_namespace = oca_schema_namespace
        self.oca_schema_dri = oca_schema_dri

    @property
    def record_value(self) -> dict:
        """Accessor to for the JSON record value properties"""
        return {
            prop: getattr(self, prop)
            for prop in (
                "label",
                "oca_schema_namespace",
                "oca_schema_dri",
                "oca_data_dri",
            )
        }

    @property
    def record_tags(self) -> dict:
        return {"label": self.label, "oca_data_dri": self.oca_data_dri}

    @classmethod
    async def retrieve_by_id_fully_serialized(cls, context, id):
        record = await cls.retrieve_by_id(context, id)
        oca_data = await load_string(context, record.oca_data_dri)

        record = record.serialize()
        record["oca_data"] = json.loads(oca_data)
        record.pop("created_at", None)
        record.pop("updated_at", None)
        record.pop("label", None)

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

    @classmethod
    async def routes_retrieve_by_id_serialized(cls, context, id):
        try:
            record = await cls.retrieve_by_id(context, id)
        except StorageNotFoundError as err:
            raise web.HTTPNotFound(reason=err)
        except StorageError as err:
            raise web.HTTPInternalServerError(reason=err)

        record = record.serialize()
        record.pop("created_at", None)
        record.pop("updated_at", None)
        record.pop("label", None)

        return record


class DefinedConsentRecordSchema(BaseRecordSchema):
    class Meta:
        model_class = "DefinedConsentRecord"

    label = fields.Str(required=True)
    oca_data_dri = fields.Str(required=True)
    oca_schema_namespace = fields.Str(required=True)
    oca_schema_dri = fields.Str(required=True)
