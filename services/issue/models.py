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

    ISSUE_WAITING_FOR_RESPONSE = "no response"
    ISSUE_SERVICE_NOT_FOUND = "service not found"
    ISSUE_SERVICE_LEDGER_ERROR = "ledger error"
    ISSUE_CREDENTIAL_DEFINITION_PREPARATION_COMPLETE = "cred prep complete"
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
        service_schema: ServiceSchema = None,
        service_user_data_dri: str = None,
        service_consent_match_id: str = None,
        user_consent_credential: dict = None,
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
        self.service_schema = service_schema
        self.credential_definition_id = credential_definition_id
        self.service_user_data_dri = service_user_data_dri
        self.service_consent_match_id = service_consent_match_id
        self.user_consent_credential = user_consent_credential
        self.credential_id = credential_id
        self.their_public_did = their_public_did

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
                "service_schema",
                "credential_definition_id",
                "service_user_data_dri",
                "service_consent_match_id",
                "user_consent_credential",
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

    @classmethod
    async def retrieve_by_exchange_id_and_connection_id(
        cls, context: InjectionContext, exchange_id: str, connection_id: str
    ):
        return await cls.retrieve_by_tag_filter(
            context,
            {"exchange_id": exchange_id, "connection_id": connection_id},
        )

    async def save(
        self,
        context: InjectionContext,
        *,
        reason: str = None,
        log_params: Mapping[str, Any] = None,
        log_override: bool = False,
        webhook: bool = None,
    ) -> str:
        """Persist the record to storage.

        Args:
            context: The injection context to use
            reason: A reason to add to the log
            log_params: Additional parameters to log
            webhook: Flag to override whether the webhook is sent

         NOTE: only deviation from the standard
               is in id generation (hash based)
        """
        new_record = None
        log_reason = reason or ("Updated record" if self._id else "Created record")
        try:
            self.updated_at = time_now()
            storage: BaseStorage = await context.inject(BaseStorage)
            if not self._id:
                # NOTE: only change here, calculating id
                unique_record_value = json.dumps(self.unique_record_values)
                print(unique_record_value)
                self._id = hashlib.sha256(
                    unique_record_value.encode("UTF-8")
                ).hexdigest()

                self.created_at = self.updated_at
                await storage.add_record(self.storage_record)
                new_record = True
            else:
                record = self.storage_record
                await storage.update_record_value(record, record.value)
                await storage.update_record_tags(record, record.tags)
                new_record = False
        finally:
            params = {self.RECORD_TYPE: self.serialize()}
            if log_params:
                params.update(log_params)
            if new_record is None:
                log_reason = f"FAILED: {log_reason}"
            self.log_state(context, log_reason, params, override=log_override)

        await self.post_save(context, new_record, self._last_state, webhook)
        self._last_state = self.state

        return self._id


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
    user_consent_credential = fields.Str(required=False)
    credential_id = fields.Str(required=False)
    service_user_data_dri = fields.Str(required=False)
    their_public_did = fields.Str(required=False)
