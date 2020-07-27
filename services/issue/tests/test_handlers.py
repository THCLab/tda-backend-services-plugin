from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.messaging.responder import BaseResponder, MockResponder
from aries_cloudagent.storage.base import BaseStorage, StorageRecord
from aries_cloudagent.storage.basic import BasicStorage
from asynctest import TestCase as AsyncTestCase, mock as async_mock

import hashlib
from marshmallow import fields
from unittest import mock, TestCase
import datetime
import json

# Internal
from ..models import *
from ..message_types import *
from ..handlers import *


class TestIssueHandlers(AsyncTestCase):
    consent_schema = {
        "oca_schema_dri": "1234",
        "oca_schema_namespace": "test",
        "data_url": "http://test.com/test",
    }
    service_schema = {
        "oca_schema_dri": "1234",
        "oca_schema_namespace": "test",
    }
    connection_id = "1234"
    exchange_id = "1234"
    state = ServiceIssueRecord.ISSUE_PENDING

    def assert_confirmation_record(self, record, state):
        assert isinstance(record, Confirmation)
        assert self.service_schema == record.service_schema
        assert self.service_schema == record.service_schema
        assert state == record.state

    def create_default_context(self):
        context = InjectionContext()
        storage = BasicStorage()
        responder = MockResponder()

        context.injector.bind_instance(BaseStorage, storage)

        context.connection_ready = True
        context.connection_record = ConnectionRecord(connection_id=self.connection_id)

        return [context, storage, responder]

    async def test_application_handler(self):
        context, storage, responder = self.create_default_context()

        context.message = Application(
            consent_schema=self.consent_schema, service_schema=self.service_schema
        )

        handler = ApplicationHandler()
        await handler.handle(context, responder)

        assert len(responder.messages) == 2

        result, message = responder.messages[0]
        self.assert_confirmation_record(result, ServiceIssueRecord.ISSUE_PENDING)

        result, message = responder.messages[1]
        self.assert_confirmation_record(result, ServiceIssueRecord.ISSUE_ACCEPTED)

    async def test_confirmation_handler(self):
        context, storage, responder = self.create_default_context()
        context.message = Confirmation(
            exchange_id=self.exchange_id,
            service_schema=self.service_schema,
            consent_schema=self.consent_schema,
            state=self.state,
        )

        handler = ConfirmationHandler()
        await handler.handle(context, responder)
