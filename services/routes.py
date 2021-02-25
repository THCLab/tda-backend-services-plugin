from aiohttp import web

from .issue.routes import *
from .discovery.routes import *
from .consents.routes import consent_routes

# NOTE: define functions in sub routes files (i.e issue.routes) and register
# them here


async def register(app: web.Application):
    routes_list = [
        web.post("/verifiable-services/add", add_service),
        web.post("/verifiable-services/apply", apply),
        web.post(
            "/verifiable-services/get-issue",
            get_issue_self,
        ),
        web.get(
            "/verifiable-services/get-issue/{issue_id}",
            get_issue_by_id,
            allow_head=False,
        ),
        web.post(
            "/verifiable-services/process-application",
            process_application,
        ),
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
    ]

    routes_list.extend(consent_routes)
    app.add_routes(routes_list)
