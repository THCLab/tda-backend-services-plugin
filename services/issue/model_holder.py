from aries_cloudagent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from aries_cloudagent.config.injection_context import InjectionContext

import hashlib
from marshmallow import fields
from typing import Mapping, Any
import uuid
import json
from aries_cloudagent.pdstorage_thcf.api import *


class ServiceExchangeIssuer(BaseRecord):
    RECORD_ID_NAME = "record_id"
    RECORD_TYPE = "service_issue"

    ISSUE_PENDING = "pending"
    ISSUE_REJECTED = "rejected"
    ISSUE_ACCEPTED = "accepted"
    ISSUE_CREDENTIAL_RECEIVED = "credential_received"

    AUTHOR_SELF = "self"
    AUTHOR_OTHER = "other"

    class Meta:
        schema_class = "ServiceExchangeIssuerSchema"

    def __init__(
        self,
        *,
        state: str = None,
        author: str = None,
        connection_id: str = None,
        exchange_id: str = None,
        service_id: str = None,
        service_schema_dri: str = None,
        consent_schema: dict = None,
        service_consent_match_id: str = None,
        user_data_dri: str = None,
        id: str = None,
        **kwargs,
    ):
        return
        super().__init__(id, state, **kwargs)
        self.connection_id = connection_id
        self.author = author
        self.exchange_id = str(uuid.uuid4()) if exchange_id is None else exchange_id
        self.service_id = service_id
        self.user_data_dri = user_data_dri
        self.user_public_did = user_public_did
        self.user_consent_dri = user_consent_dri
        self.service_consent_match_id = service_consent_match_id
        self.issued_credential_dri = issued_credential_dri

    @property
    def record_value(self) -> dict:
        return {
            prop: getattr(self, prop)
            for prop in (
                "connection_id",
                "author",
                "exchange_id",
                "service_id",
                "user_data_dri",
                "user_public_did",
                "user_consent_dri",
                "service_consent_match_id",
                "issued_credential_dri",
            )
        }

    @property
    def unique_record_values(self) -> dict:
        """Hash id of a record is based on those values"""
        return {
            prop: getattr(self, prop)
            for prop in (
                "connection_id",
                "exchange_id",
            )
        }

    @property
    def record_tags(self) -> dict:
        return {
            "connection_id": self.connection_id,
            "exchange_id": self.exchange_id,
            "state": self.state,
            "author": self.author,
        }

    async def save(
        self,
        context: InjectionContext,
        *,
        reason: str = None,
        log_params: Mapping[str, Any] = None,
        log_override: bool = False,
        webhook: bool = None,
    ) -> str:
        unique_record_value = json.dumps(self.unique_record_values)
        result = await super().save(
            context,
            reason=reason,
            log_params=log_params,
            log_override=log_override,
            webhook=webhook,
            custom_id_gen=hashlib.sha256(
                unique_record_value.encode("UTF-8")
            ).hexdigest(),
        )
        return result

    @classmethod
    async def retrieve_by_exchange_id_and_connection_id(
        cls, context: InjectionContext, exchange_id: str, connection_id: str
    ):
        return await cls.retrieve_by_tag_filter(
            context,
            {"exchange_id": exchange_id, "connection_id": connection_id},
        )


class ServiceExchangeIssuerSchema(BaseRecordSchema):
    class Meta:
        model_class = "ServiceExchangeIssuer"

    state = fields.Str(required=False)
    author = fields.Str(required=False)
    connection_id = fields.Str(required=False)
    exchange_id = fields.Str(required=False)
    user_data_dri = fields.Str(required=False)
    user_public_did = fields.Str(required=False)
    user_consent_dri = fields.Str(required=False)
    service_consent_match_id = fields.Str(required=False)
    issued_credential_dri = fields.Str(required=False)
