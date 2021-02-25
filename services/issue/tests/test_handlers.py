from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.messaging.responder import MockResponder
from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.storage.basic import BasicStorage
from asynctest import TestCase as AsyncTestCase


# Internal
from ..models import *
from ..message_types import *
from ..handlers import *


class TestIssueHandlers(AsyncTestCase):
    consent_schema = {
        "oca_schema_dri": "1234",
        "oca_schema_namespace": "test",
        "data_dri": "http://test.com/test",
    }
    service_schema = {
        "oca_schema_dri": "1234",
        "oca_schema_namespace": "test",
    }
    connection_id = "1234"
    exchange_id = "1234"
    state = ServiceIssueRecord.ISSUE_PENDING
    label = "aaaa"

    def assert_confirmation_record(self, record, state):
        assert isinstance(record, Confirmation)
        assert state == record.state

    def assert_issue_records_are_the_same(self, record1, record2):
        assert record1.state == record2.state
        assert record1.author == record2.author
        assert record1.exchange_id == record2.exchange_id
        assert record1.connection_id == record2.connection_id

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

        record = ServiceRecord(
            label=self.label,
            consent_schema=self.consent_schema,
            service_schema=self.service_schema,
        )
        service_id = await record.save(context)

        context.message = Application(
            exchange_id=self.exchange_id, service_id=service_id
        )

        handler = ApplicationHandler()
        await handler.handle(context, responder)

        assert len(responder.messages) == 2

        result, message = responder.messages[0]
        self.assert_confirmation_record(result, ServiceIssueRecord.ISSUE_PENDING)

        result, message = responder.messages[1]
        self.assert_confirmation_record(result, ServiceIssueRecord.ISSUE_ACCEPTED)

        query = await ServiceIssueRecord.retrieve_by_exchange_id_and_connection_id(
            context,
            context.message.exchange_id,
            context.connection_record.connection_id,
        )
        assert query.service_schema == self.service_schema

    async def test_confirmation_handler(self):
        context, storage, responder = self.create_default_context()
        record = ServiceIssueRecord(
            state=ServiceIssueRecord.ISSUE_PENDING,
            author=ServiceIssueRecord.AUTHOR_OTHER,
            connection_id=self.connection_id,
            exchange_id=self.exchange_id,
        )
        await record.save(context)

        context.message = Confirmation(
            exchange_id=self.exchange_id,
            state=self.state,
        )

        handler = ConfirmationHandler()
        await handler.handle(context, responder)

        query = await ServiceIssueRecord.retrieve_by_exchange_id_and_connection_id(
            context,
            context.message.exchange_id,
            context.connection_record.connection_id,
        )
        self.assert_issue_records_are_the_same(query, record)
