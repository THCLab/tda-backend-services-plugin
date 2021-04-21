from ..discovery.routes import certificate_get
from aries_cloudagent.connections.models.connection_record import ConnectionRecord
from aries_cloudagent.storage.error import *

from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.issuer.base import BaseIssuer
from aries_cloudagent.wallet.base import BaseWallet

from aiohttp import web
from aiohttp_apispec import docs, request_schema, match_info_schema

from marshmallow import fields, Schema
import logging
import json

from .models import *
from .message_types import *
from ..models import *
from ..consents.models.given_consent import ConsentGivenRecord
from ..discovery.message_types import DiscoveryServiceSchema
from aries_cloudagent.pdstorage_thcf.api import *
from aries_cloudagent.protocols.issue_credential.v1_1.utils import (
    retrieve_connection,
)
from ..util import *
from aries_cloudagent.protocols.present_proof.v1_1.routes import verify_usage_policy
from aries_cloudagent.aathcf.utils import run_standalone_async, build_context

LOGGER = logging.getLogger(__name__)
MY_SERVICE_DATA_TABLE = "my_service_data_table"
OCA_DATA_CHUNKS = "tda.oca_chunks"


class ApplySchema(Schema):
    connection_id = fields.Str(required=True)
    user_data = fields.Str(required=True)
    service = fields.Nested(DiscoveryServiceSchema(), required=True)


async def get_public_did(context):
    wallet: BaseWallet = await context.inject(BaseWallet)
    public_did = await wallet.get_public_did()
    public_did = public_did[0]

    if public_did == None:
        raise web.HTTPBadRequest(reason="This operation requires a public DID!")

    return public_did


@docs(
    tags=["Verifiable Services"],
    summary="Apply to a service that connected agent provides",
)
@request_schema(ApplySchema())
async def apply(request: web.BaseRequest):
    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    params = await request.json()
    connection_id = params["connection_id"]
    service_user_data = params["user_data"]
    service_id = params["service"]["service_id"]

    # service consent and service to check for correctness
    service_consent_schema = params["service"]["consent_schema"]
    service_schema = params["service"]["service_schema"]
    service_label = params["service"]["label"]

    connection = await retrieve_connection(context, connection_id)

    service_consent_match_id = str(uuid.uuid4())

    service_consent_copy = service_consent_schema.copy()
    service_consent_copy.pop("oca_data", None)
    usage_policy = await pds_get_usage_policy_if_active_pds_supports_it(context)
    credential_values = {"service_consent_match_id": service_consent_match_id}
    credential_values["usage_policy"] = usage_policy

    credential_values.update(service_consent_copy)

    issuer: BaseIssuer = await context.inject(BaseIssuer)
    credential = await issuer.create_credential_ex(
        credential_values,
    )

    service_appliance_data = service_user_data
    if isinstance(service_appliance_data, str):
        service_appliance_data = json.loads(service_appliance_data)

    payload_key = "p"
    for schema_dri in service_appliance_data:
        dri = schema_dri.replace("DRI:", "")

        if payload_key not in service_appliance_data[schema_dri]:
            continue

        await pds_save_a(
            context,
            service_appliance_data[schema_dri][payload_key],
            oca_schema_dri=dri,
            table=OCA_DATA_CHUNKS + "." + dri,
        )

    service_user_data_dri = await pds_save_a(
        context,
        service_user_data,
        oca_schema_dri=service_schema["oca_schema_dri"],
        table=MY_SERVICE_DATA_TABLE,
    )

    record = ServiceIssueRecord(
        connection_id=connection_id,
        state=ServiceIssueRecord.ISSUE_WAITING_FOR_RESPONSE,
        author=ServiceIssueRecord.AUTHOR_SELF,
        label=service_label,
        service_consent_schema=service_consent_schema,
        service_id=service_id,
        service_schema=service_schema,
        service_user_data_dri=service_user_data_dri,
        service_consent_match_id=service_consent_match_id,
    )

    await record.save(context)

    """ 
    service_user_data_dri - is here so that in the future it would be easier
    to not send the service_user_data, because from what I understand we only
    want to send that to the other party under certain conditions

    dri is used only to make sure DRI's are the same 
    when I store the data in other's agent PDS

    """
    public_did = await get_public_did(context)

    request = Application(
        service_id=record.service_id,
        exchange_id=record.exchange_id,
        service_user_data=service_user_data,
        service_user_data_dri=service_user_data_dri,
        service_consent_match_id=service_consent_match_id,
        consent_credential=credential,
        public_did=public_did,
    )
    await outbound_handler(request, connection_id=connection_id)

    """

    Record the given credential

    """

    consent_given_record = ConsentGivenRecord(connection_id=connection_id)
    await consent_given_record.credential_pds_set(context, credential)
    await consent_given_record.save(context)

    return web.json_response({"success": True, "exchange_id": record.exchange_id})


async def send_confirmation(outbound_handler, connection_id, exchange_id, state):
    confirmation = Confirmation(exchange_id=exchange_id, state=state)
    await outbound_handler(confirmation, connection_id=connection_id)


class ProcessApplicationSchema(Schema):
    issue_id = fields.Str(required=True)
    decision = fields.Str(required=True)
    data = fields.Dict(required=True)


@docs(
    tags=["Verifiable Services"],
    summary="Decide whether application should be accepted or rejected",
    description="""
    issue_id - first you need to call get_issue_self and search for 
    issues with "pending" state, those should return you issue_id

    decision:
    "accept"
    "reject" 
    """,
)
@request_schema(ProcessApplicationSchema())
async def process_application(request: web.BaseRequest):
    outbound_handler = request.app["outbound_message_router"]
    context = request.app["request_context"]
    params = await request.json()
    issue_id = params["issue_id"]
    report_data = params["data"]

    issue: ServiceIssueRecord = await retrieve_service_issue(context, issue_id)
    exchange_id = issue.exchange_id
    connection_id = issue.connection_id

    service: ServiceRecord = await retrieve_service(context, issue.service_id)
    connection: ConnectionRecord = await retrieve_connection(context, connection_id)

    if (
        params["decision"] == "reject"
        or issue.state == ServiceIssueRecord.ISSUE_REJECTED
    ):
        issue.state = ServiceIssueRecord.ISSUE_REJECTED
        await issue.save(context, reason="Issue reject saved")
        await send_confirmation(
            outbound_handler, connection_id, exchange_id, issue.state
        )
        return web.json_response(
            {
                "success": True,
                "issue_id": issue._id,
                "connection_id": connection_id,
            }
        )

    cred_schem_dri = service.service_schema.get("oca_schema_dri")
    cred_namspc = service.service_schema.get("oca_schema_namespace")
    cred_data_dri = issue.service_user_data_dri
    cred_data = await pds_load(context, issue.service_user_data_dri)
    if service.certificate_schema:
        print(service.certificate_schema)
        cert_schema_dri = service.certificate_schema["oca_schema_dri"]
        try:
            certificate = await certificate_get(context, cert_schema_dri)
        except json.JSONDecodeError:
            raise web.HTTPBadRequest("certificate_schema doesn't conform to json spec")
        if certificate is None:
            raise web.HTTPNotFound(reason="certificate_schema not found")

        certificate["associatedReportID"] = issue.exchange_id
        cred_data_dri = await pds_save_a(
            context,
            certificate,
            table="dip.data.tda.oca_chunks." + cert_schema_dri,
        )

        cred_data = certificate
        cred_schem_dri = cert_schema_dri
        cred_namspc = service.certificate_schema["oca_schema_namespace"]

    issuer: BaseIssuer = await context.inject(BaseIssuer)
    credential = await issuer.create_credential_ex(
        {
            "oca_schema_dri": cred_schem_dri,
            "oca_schema_namespace": cred_namspc,
            "oca_data_dri": cred_data_dri,
            "service_consent_match_id": issue.service_consent_match_id,
        },
        subject_public_did=issue.their_public_did,
    )

    issue.state = ServiceIssueRecord.ISSUE_ACCEPTED
    issue.report_data = report_data
    await issue.issuer_credential_pds_set(context, credential)
    await issue.save(context, reason="Accepted service issue, credential offer created")
    resp = ApplicationResponse(
        credential=credential,
        exchange_id=exchange_id,
        report_data=report_data,
        credential_data=cred_data,
    )
    await outbound_handler(resp, connection_id=connection_id)
    return web.json_response(
        {
            "success": True,
            "issue_id": issue._id,
            "connection_id": connection_id,
        }
    )


async def test_():
    context = await build_context()
    payload = {
        "associatedReportID": "Text",
        "uniqueNumericIDHash": "Text",
        "disease": "Text",
        "vaccineDescription": "Text",
        "atcCode": "Text",
        "certificateIssuer": "Text",
        "certificateNumber": "Text",
        "certificateValidFrom": "Date",
        "certificateValidTo": "Date",
        "formVersion": "Text",
    }
    await pds_save_a(
        context,
        payload,
        table="dip.data.tda.oca_chunks.predefined.9GdWoQwth9299oYj8HfdgRZjtSxW9sTVyy1RnfhQ35yJ",
    )

    result = await load_multiple(
        context,
        table="dip.data.tda.oca_chunks.predefined.9GdWoQwth9299oYj8HfdgRZjtSxW9sTVyy1RnfhQ35yJ",
    )

    print(result[0]["content"]["associatedReportID"])


# run_standalone_async(__name__, test_)


class GetIssueFilteredSchema(Schema):
    connection_id = fields.Str(required=False)
    exchange_id = fields.Str(required=False)
    service_id = fields.Str(required=False)
    label = fields.Str(required=False)
    author = fields.Str(required=False)
    state = fields.Str(required=False)


# TODO: This needs a rewrite cause it can get very easily inconsistent on one of the
# sides
async def serialize_and_verify_service_issue(context, issue):
    record: dict = issue.serialize()
    if issue.author == issue.AUTHOR_SELF:
        storage: BaseStorage = await context.inject(BaseStorage)
        try:
            query = storage.search_records(
                "service_list", {"connection_id": record["connection_id"]}
            )
            query = await query.fetch_single()
            services = json.loads(query.value)
            for i in services:
                if i["service_id"] == record["service_id"]:
                    record["consent_schema"] = i["consent_schema"]
                    record["service_schema"] = i["service_schema"]
                    record["label"] = i["label"]
        except StorageError:
            pass

    else:
        consent_data = None
        if record["service_id"] is not None:
            try:
                service = await ServiceRecord.retrieve_by_id_fully_serialized(
                    context, record["service_id"]
                )
            except StorageNotFoundError:
                return "Record not found id:" + issue.service_id
            except StorageError as err:
                return (
                    f"Error when retrieving service: {err.roll_up} id: "
                    + issue.service_id
                )

            consent_data = service["consent_schema"]
            if consent_data.get("usage_policy") is not None:
                if issue.author == ServiceIssueRecord.AUTHOR_OTHER:
                    cred = await issue.user_consent_credential_pds_get(context)
                    record["usage_policies_match"], _ = await verify_usage_policy(
                        cred["credentialSubject"]["usage_policy"],
                        consent_data["usage_policy"],
                    )

        record.update(
            {
                "issue_id": issue._id,
                "label": issue.label,
                "service_schema": issue.service_schema,
                "consent_schema": consent_data,
            }
        )

    if issue.service_user_data_dri is not None:
        try:
            record["service_user_data"] = await pds_load(
                context, issue.service_user_data_dri
            )
        except PDSError as err:
            record["service_user_data"] = err.roll_up

    return record


@docs(
    tags=["Verifiable Services"],
    summary="Search for issue by a specified tag",
    description="""
    You don't need to fill any of this, all the filters are optional
    make sure to delete ones you dont use

    STATES: 
    "pending" - not processed yet (not rejected or accepted)
    "no response" - agent didn't respond at all yet
    "rejected"
    "accepted"

    AUTHORS:
    "self"
    "other"

    """,
)
@request_schema(GetIssueFilteredSchema())
async def get_issue_self(request: web.BaseRequest):
    context = request.app["request_context"]
    params = await request.json()
    result = await get_issue_self_(context, params)

    return web.json_response({"success": True, "result": result})


async def get_issue_self_(context, params):
    try:
        query = await ServiceIssueRecord.query(context, tag_filter=params)
    except StorageError as err:
        raise web.HTTPInternalServerError(err)

    result = []
    for i in query:
        record = await serialize_and_verify_service_issue(context, i)
        result.append(record)
    return result


@docs(
    tags=["Verifiable Services"],
    summary="Query a report by id",
)
async def query_report(request: web.BaseRequest):
    context = request.app["request_context"]
    report_id = request.match_info["associatedReportID"]
    result = await get_issue_self_(context, {"exchange_id": report_id})
    if len(result) == 0:
        return web.json_response({})
    result = result[0]
    return web.json_response(result["report_data"])


class GetIssueByIdSchema(Schema):
    issue_id = fields.Str(required=True)


@docs(
    tags=["Verifiable Services"],
    summary="Search for issue by id",
)
@match_info_schema(GetIssueByIdSchema())
async def get_issue_by_id(request: web.BaseRequest):
    context = request.app["request_context"]
    issue_id = request.match_info["issue_id"]

    try:
        query: ServiceIssueRecord = await ServiceIssueRecord.retrieve_by_id(
            context, issue_id
        )
    except StorageError as err:
        raise web.HTTPInternalServerError(err)

    record = await serialize_and_verify_service_issue(context, query)

    return web.json_response({"success": True, "result": record})


async def DEBUGapply_status(request: web.BaseRequest):
    context = request.app["request_context"]
    params = await request.json()

    query = await ServiceIssueRecord.query(context, tag_filter=params)

    query = [i.serialize() for i in query]

    return web.json_response({"success": True, "result": query})


async def DEBUGget_credential_data(request: web.BaseRequest):
    context = request.app["request_context"]
    data_dri = request.match_info["data_dri"]

    query: ServiceIssueRecord = await ServiceIssueRecord.retrieve_by_id(
        context, data_dri
    )

    return web.json_response({"success": True, "credential_data": query.payload})
