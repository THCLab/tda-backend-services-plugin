from ..util import generate_model_schema
from marshmallow import Schema, fields
from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from ..models import ConsentSchema, ServiceSchema

# Message Types
PROTOCOL_URI = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/verifiable-services/1.0"
PROTOCOL_PACKAGE = "services.issue.handlers"


APPLICATION = f"{PROTOCOL_URI}/application"
APPLICATION_RESPONSE = f"{PROTOCOL_URI}/application-response"
CONFIRMATION = f"{PROTOCOL_URI}/confirmation"
GET_ISSUE = f"{PROTOCOL_URI}/get-issue"
GET_ISSUE_RESPONSE = f"{PROTOCOL_URI}/get-issue-response"

MESSAGE_TYPES = {
    APPLICATION: f"{PROTOCOL_PACKAGE}.Application",
    APPLICATION_RESPONSE: f"{PROTOCOL_PACKAGE}.ApplicationResponse",
    CONFIRMATION: f"{PROTOCOL_PACKAGE}.Confirmation",
    GET_ISSUE: f"{PROTOCOL_PACKAGE}.GetIssue",
    GET_ISSUE_RESPONSE: f"{PROTOCOL_PACKAGE}.GetIssueResponse",
}


# Messages
Application, ApplicationSchema = generate_model_schema(
    name="Application",
    handler=f"{PROTOCOL_PACKAGE}.ApplicationHandler",
    msg_type=APPLICATION,
    schema={
        "service_id": fields.Str(required=True),
        "exchange_id": fields.Str(required=True),
        "service_user_data": fields.Str(required=True),
        "service_user_data_dri": fields.Str(required=True),
        "service_consent_match_id": fields.Str(required=True),
        "consent_credential": fields.Str(required=True),
        "public_did": fields.Str(required=True),
    },
)

ApplicationResponse, ApplicationResponseSchema = generate_model_schema(
    name="ApplicationResponse",
    handler=f"{PROTOCOL_PACKAGE}.ApplicationResponseHandler",
    msg_type=APPLICATION_RESPONSE,
    schema={
        "credential": fields.Str(required=True),
        "exchange_id": fields.Str(required=True),
    },
)

Confirmation, ConfirmationSchema = generate_model_schema(
    name="Confirmation",
    handler=f"{PROTOCOL_PACKAGE}.ConfirmationHandler",
    msg_type=CONFIRMATION,
    schema={
        "exchange_id": fields.Str(required=True),
        "state": fields.Str(required=True),
    },
)
