from aries_cloudagent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from marshmallow import fields

from ...models import OcaSchema


class DefinedConsentRecord(BaseRecord):
    RECORD_ID_NAME = "record_id"
    RECORD_TYPE = "defined_consent"

    class Meta:
        schema_class = "DefinedConsentRecordSchema"

    def __init__(
        self,
        *,
        label: str = None,
        oca_schema: OcaSchema = None,
        payload_dri: str = None,
        state: str = None,
        record_id: str = None,
        **keyword_args,
    ):
        super().__init__(record_id, state, **keyword_args)
        self.label = label
        self.oca_schema = oca_schema
        self.payload_dri = payload_dri

    @property
    def record_value(self) -> dict:
        """Accessor to for the JSON record value properties"""
        return {
            prop: getattr(self, prop)
            for prop in ("label", "oca_schema", "payload_dri")
        }

    @property
    def record_tags(self) -> dict:
        return {"label": self.label, "payload_dri": self.payload_dri}


class DefinedConsentRecordSchema(BaseRecordSchema):
    class Meta:
        model_class = "DefinedConsentRecord"

    label = fields.Str(required=True)
    oca_schema = fields.Nested(OcaSchema())
    payload_dri = fields.Str(required=True)
