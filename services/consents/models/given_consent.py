from aries_cloudagent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from marshmallow import fields

from ...models import ConsentSchema


class ConsentGivenRecord(BaseRecord):
    RECORD_ID_NAME = "record_id"
    RECORD_TYPE = "given_consent_credential"

    class Meta:
        schema_class = "ConsentGivenRecordSchema"

    def __init__(
        self,
        *,
        connection_id: str = None,
        credential: dict = None,
        state: str = None,
        record_id: str = None,
        **keyword_args,
    ):
        super().__init__(record_id, state, **keyword_args)
        self.connection_id = connection_id
        self.credential = credential

    @property
    def record_value(self) -> dict:
        """Accessor to for the JSON record value properties"""
        return {
            prop: getattr(self, prop)
            for prop in (
                "connection_id",
                "credential",
            )
        }

    @property
    def record_tags(self) -> dict:
        return {
            "connection_id": self.connection_id,
        }


class ConsentGivenRecordSchema(BaseRecordSchema):
    class Meta:
        model_class = "ConsentGivenRecord"

    connection_id = fields.Str(required=True)
    credential = fields.Dict()
