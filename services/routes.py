from aiohttp import web

from .issue.routes import *
from .discovery.routes import *
from .consents.routes import consent_routes

# NOTE: define functions in sub routes files (i.e issue.routes) and register
# them here


async def register(app: web.Application):
    routes_list = []

    routes_list.extend(discovery_routes)
    routes_list.extend(consent_routes)
    routes_list.extend(services_routes)
    app.add_routes(routes_list)
