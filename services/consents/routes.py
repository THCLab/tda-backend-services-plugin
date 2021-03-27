from aiohttp import web
from aiohttp_apispec import docs, request_schema
from aries_cloudagent.aathcf.utils import build_pds_context
from aries_cloudagent.pdstorage_thcf.api import *
import aries_cloudagent.generated_models as Model

#    @classmethod
#     def from_storage(cls, record_id: str, record: Mapping[str, Any]):
#         """Initialize a record from its stored representation.

#         Args:
#             record_id: The unique record identifier
#             record: The stored representation
#         """
#         record_id_name = cls.RECORD_ID_NAME
#         if record_id_name in record:
#             raise ValueError(f"Duplicate {record_id_name} inputs")
#         params = dict(**record)
#         params[record_id_name] = record_id
#         return cls(**params)


class OCARecord:
    def __init__(self, oca_schema_dri=None, dri=None):
        self.oca_schema_dri = oca_schema_dri
        self.dri = dri

    def serialize(self):
        result = self.__dict__.copy()
        result.pop("dri", None)
        result.pop("oca_schema_dri", None)
        return result

    async def save(self, context):
        self.dri = await pds_save(
            context, self.serialize(), oca_schema_dri=self.oca_schema_dri
        )
        return self.dri

    @classmethod
    async def load(cls, context, dri):
        fetch = await pds_load(context, dri, with_meta=True)
        schema = {
            "oca_schema_dri": fetch.get("oca_schema_dri"),
            "dri": dri,
        }
        schema.update(fetch["content"])
        return cls(**schema)


class DefinedConsent(OCARecord):
    def __init__(self, label, usage_policy, oca_data, *, oca_schema_dri=None, dri=None):
        self.label = label
        self.usage_policy = usage_policy
        self.oca_data = oca_data
        super().__init__(oca_schema_dri, dri)


class ConsentGiven:
    def __init__(self, credential, connection_id):
        self.credential = credential
        self.connection_id = connection_id


async def add_consent(context, label, oca_data, oca_schema_dri):
    pds_usage_policy = await pds_get_usage_policy_if_active_pds_supports_it(context)
    m = DefinedConsent(label, pds_usage_policy, oca_data, oca_schema_dri=oca_schema_dri)
    dri = await m.save(context)
    record = await m.load(context, dri)
    assert Model.Consent().validate(record.__dict__) == {}

    return record


async def retrieve_from_pds(context, oca_schema_dri):
    try:
        result = await pds_query_model_by_oca_schema_dri(context, oca_schema_dri)
    except PDSError as err:
        raise web.HTTPInternalServerError(reason=err.roll_up)
    return result


@request_schema(Model.Consent)
@docs(
    tags=["Consents"],
    summary="Add consent definition",
)
async def post_consent_api(request: web.BaseRequest):
    context = request.app["request_context"]
    body = await request.json()
    result = await add_consent(
        context, body["label"], body["oca_data"], body["oca_schema_dri"]
    )

    return web.json_response(result.__dict__)


@docs(tags=["Consents"], summary="Get all consent definitions")
async def get_consents_api(request: web.BaseRequest):
    consent_oca_schema_dri = "consent_dri"
    context = request.app["request_context"]
    result = await retrieve_from_pds(context, consent_oca_schema_dri)
    for i in result:
        i["oca_schema_dri"] = consent_oca_schema_dri
    return web.json_response(result)


@docs(
    tags=["Documents"],
    summary="Get all the consents I have given to other people",
)
async def get_consents_given_api(request: web.BaseRequest):
    context = request.app["request_context"]
    result = await retrieve_from_pds(context, "consent_given")
    return web.json_response(result)


@docs(
    tags=["Documents"],
    summary="Get all my consent credentials",
)
async def get_consents_mine_api(request: web.BaseRequest):
    context = request.app["request_context"]
    result = await retrieve_from_pds(context, "consent_mine")
    return web.json_response(result)


consent_routes = [
    web.post("/consents", post_consent_api),
    web.get("/consents", get_consents_api, allow_head=False),
    web.get(
        "/documents/given-consents",
        get_consents_given_api,
        allow_head=False,
    ),
    web.get(
        "/documents/mine-consents",
        get_consents_mine_api,
        allow_head=False,
    ),
]


async def test_consent():
    context, _ = await build_pds_context()
    consent = {
        "oca_schema_dri": "consent_dri",
        "label": "TestConsentLabel",
        "oca_data": {
            "additionalProp1": "string1",
            "additionalProp2": "string",
            "additionalProp3": "string",
        },
    }
    result = await add_consent(
        context, consent["label"], consent["oca_data"], consent["oca_schema_dri"]
    )
    result = await retrieve_from_pds(context, consent["oca_schema_dri"])
    print(len(result))


run_standalone_async(__name__, test_consent)