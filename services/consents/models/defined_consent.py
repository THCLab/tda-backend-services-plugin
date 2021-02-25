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
        oca_data_dri: str = None,
        pds_name: str = None,
        usage_policy: str = None,
        state: str = None,
        record_id: str = None,
        **keyword_args,
    ):
        super().__init__(record_id, state, **keyword_args)
        self.label = label
        self.oca_data_dri = oca_data_dri
        self.oca_schema_dri = oca_schema_dri
        self.pds_name = pds_name
        self.usage_policy = usage_policy

    @property
    def record_value(self) -> dict:
        """Accessor to for the JSON record value properties"""
        return {
            prop: getattr(self, prop)
            for prop in (
                "label",
                "oca_schema_dri",
                "oca_data_dri",
                "pds_name",
                "usage_policy",
            )
        }

    @property
    def record_tags(self) -> dict:
        return {
            "label": self.label,
            "oca_data_dri": self.oca_data_dri,
            "pds_name": self.pds_name,
        }

    @property
    def consent_id(self):
        return self._id

    @classmethod
    async def retrieve_by_id_fully_serialized(cls, context, id):
        record = await cls.retrieve_by_id(context, id)
        oca_data = await pds_load(context, record.oca_data_dri)

        record = record.serialize()
        record["oca_data"] = oca_data
        record.pop("created_at", None)
        record.pop("updated_at", None)
        record.pop("label", None)

        return record

    @classmethod
    async def routes_retrieve_by_id_fully_serialized(cls, context, id):
        try:
            record = await cls.retrieve_by_id_fully_serialized(context, id)
        except PDSRecordNotFoundError as err:
            raise web.HTTPNotFound(reason=err)
        except StorageNotFoundError as err:
            raise web.HTTPNotFound(reason=err)
        except PDSError as err:
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
    oca_schema_dri = fields.Str(required=True)
