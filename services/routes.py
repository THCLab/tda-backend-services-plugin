from aiohttp import web

from .issue.routes import *
from .discovery.routes import *
from .consents.routes import *

# NOTE: define functions in sub routes files (i.e issue.routes) and register
# them here


async def register(app: web.Application):
    app.add_routes(
        [
            web.post("/verifiable-services/add", add_service),
            web.post("/verifiable-services/apply", apply),
            web.post("/verifiable-services/get-issue", get_issue_self,),
            web.get(
                "/verifiable-services/get-issue/{issue_id}",
                get_issue_by_id,
                allow_head=False,
            ),
            web.post("/verifiable-services/process-application", process_application,),
            web.get(
                "/verifiable-services/request-service-list/{connection_id}",
                request_services_list,
                allow_head=False,
            ),
            web.get(
                "/verifiable-services/self-service-list",
                self_service_list,
                allow_head=False,
            ),
            web.get(
                "/verifiable-services/service/{service_id}",
                get_service,
                allow_head=False,
            ),
            web.get(
                "/verifiable-services/DEBUGrequest/{connection_id}",
                DEBUGrequest_services_list,
                allow_head=False,
            ),
            web.post("/verifiable-services/consents", add_consent),
            web.get("/verifiable-services/consents", get_consents, allow_head=False),
            web.get(
                "/verifiable-services/given-consents",
                get_consents_given,
                allow_head=False,
            ),
            # web.get(
            #     "/verifiable-services/get-credential-data/{data_dri}",
            #     DEBUGget_credential_data,
            #     allow_head=False,
            # ),
            # web.get(
            #     "/verifiable-services/apply-status",
            #     DEBUGapply_status,
            #     allow_head=False,
            # ),
        ]
    )
