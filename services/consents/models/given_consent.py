from aries_cloudagent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from marshmallow import fields

from ...models import ConsentSchema
from aries_cloudagent.pdstorage_thcf.api import *


class ConsentGivenRecord(BaseRecord):
    RECORD_ID_NAME = "record_id"
    RECORD_TYPE = "given_consent_credential"

    class Meta:
        schema_class = "ConsentGivenRecordSchema"

    def __init__(
        self,
        *,
        connection_id: str = None,
        credential_dri: str = None,
        state: str = None,
        record_id: str = None,
        **keyword_args,
    ):
        super().__init__(record_id, state, **keyword_args)
        self.connection_id = connection_id
        self.credential_dri = credential_dri

    @property
    def record_value(self) -> dict:
        """Accessor to for the JSON record value properties"""
        return {
            prop: getattr(self, prop) for prop in ("connection_id", "credential_dri")
        }

    @property
    def record_tags(self) -> dict:
        return {
            "connection_id": self.connection_id,
        }

    async def credential_pds_set(self, context, credential):
        if isinstance(credential, str):
            credential = json.loads(credential)
        self.credential_dri = await pds_save_a(
            context, credential, table="consent_given"
        )

    async def credential_pds_get(self, context):
        if self.credential_dri is None:
            return None
        credential = await pds_load(context, self.credential_dri)
        return credential


class ConsentGivenRecordSchema(BaseRecordSchema):
    class Meta:
        model_class = "ConsentGivenRecord"

    connection_id = fields.Str(required=True)
    credential_dri = fields.Str(required=False)
