from aiohttp import web
from aries_cloudagent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.storage.error import StorageDuplicateError
from aries_cloudagent.messaging.util import datetime_to_str, time_now

import hashlib
from marshmallow import fields, Schema
from typing import Mapping, Any, overload
import uuid
import json
from aries_cloudagent.pdstorage_thcf.api import *

from ..models import ConsentSchema, ServiceSchema


class ServiceIssueRecord(BaseRecord):
    """
    dri - (without oca) identifier pointing to a public storage record in a
    active data vault
    oca_dri - it's located in a different repo I think(oca_vault), there are no enpoints
    for them in the agent, at least I don't think that will work
    """

    RECORD_ID_NAME = "record_id"
    RECORD_TYPE = "service_issue"

    ISSUE_SERVICE_NOT_FOUND = "service not found"
    ISSUE_PENDING = "pending"
    ISSUE_REJECTED = "rejected"
    ISSUE_ACCEPTED = "accepted"
    ISSUE_CREDENTIAL_RECEIVED = "credential_received"

    AUTHOR_SELF = "self"
    AUTHOR_OTHER = "other"

    class Meta:
        schema_class = "ServiceIssueRecordSchema"

    def __init__(
        self,
        *,
        state: str = None,
        author: str = None,
        service_id: str = None,
        connection_id: str = None,
        # Holder / (cred requester) values
        label: str = None,
        credential_definition_id: str = None,
        service_consent_schema: ConsentSchema = None,
        service_schema_dri: str = None,
        service_user_data_dri: str = None,
        service_consent_match_id: str = None,
        user_consent_credential_dri: dict = None,
        credential_id: str = None,
        their_public_did: str = None,
        #
        exchange_id: str = None,
        record_id: str = None,
        **keywordArgs,
    ):
        super().__init__(record_id, state, **keywordArgs)
        self.service_id = service_id
        self.connection_id = connection_id
        self.author = author
        self.exchange_id = str(uuid.uuid4()) if exchange_id is None else exchange_id
        # Holder / (cred requester) values
        self.label = label
        self.service_consent_schema = service_consent_schema
        self.service_schema_dri = service_schema_dri
        self.credential_definition_id = credential_definition_id
        self.service_user_data_dri = service_user_data_dri
        self.service_consent_match_id = service_consent_match_id
        self.credential_id = credential_id
        self.their_public_did = their_public_did
        self.user_consent_credential_dri = user_consent_credential_dri

    @property
    def record_value(self) -> dict:
        """Accessor to for the JSON record value properties"""
        return {
            prop: getattr(self, prop)
            for prop in (
                "connection_id",
                "state",
                "author",
                "exchange_id",
                "service_id",
                "label",
                "service_consent_schema",
                "service_schema_dri",
                "credential_definition_id",
                "service_user_data_dri",
                "service_consent_match_id",
                "user_consent_credential_dri",
                "credential_id",
                "their_public_did",
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
        """Get tags for record,
        NOTE: relevent when filtering by tags"""
        return {
            "connection_id": self.connection_id,
            "exchange_id": self.exchange_id,
            "service_id": self.service_id,
            "service_consent_match_id": self.service_consent_match_id,
            "state": self.state,
            "author": self.author,
            "label": self.label,
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

    async def issuer_credential_pds_set(self, context, credential):
        if isinstance(credential, str):
            credential = json.loads(credential)
        self.credential_id = await pds_save(context, credential)

    async def issuer_credential_pds_get(self, context):
        if self.credential_id is None:
            return None
        credential = await pds_load(context, self.credential_id)
        return credential

    async def user_consent_credential_pds_set(self, context, credential):
        if isinstance(credential, str):
            credential = json.loads(credential)
        self.user_consent_credential_dri = await pds_save(context, credential)

    async def user_consent_credential_pds_get(self, context):
        if self.user_consent_credential_dri is None:
            return None
        credential = await pds_load(context, self.user_consent_credential_dri)
        return credential


class ServiceIssueRecordSchema(BaseRecordSchema):
    class Meta:
        model_class = "ServiceIssueRecord"

    state = fields.Str(required=False)
    author = fields.Str(required=False)
    connection_id = fields.Str(required=False)
    exchange_id = fields.Str(required=False)
    label = fields.Str(required=False)
    service_id = fields.Str(required=False)
    service_consent_match_id = fields.Str(required=False)
    service_schema_dri = fields.Str(required=False)
    user_consent_credential_dri = fields.Str(required=False)
    credential_id = fields.Str(required=False)
    service_user_data_dri = fields.Str(required=False)
    their_public_did = fields.Str(required=False)
