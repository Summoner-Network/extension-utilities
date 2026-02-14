import json
import os
import pytest


HUBSPOT_DOCS = r"""
HubSpot CRM API (v3 objects)

Auth:
Authorization: Bearer <token>

Example: List companies
GET https://api.hubapi.com/crm/v3/objects/companies?limit=10

curl --request GET \
  --url 'https://api.hubapi.com/crm/v3/objects/companies?limit=10' \
  --header 'Authorization: Bearer <token>'

Example: Create company
POST https://api.hubapi.com/crm/v3/objects/companies

curl --request POST \
  --url https://api.hubapi.com/crm/v3/objects/companies \
  --header 'Authorization: Bearer <token>' \
  --header 'Content-Type: application/json' \
  --data '{"properties": {"name": "Example Co"}}'
"""


def _assert_json_roundtrip(d: dict) -> None:
    s = json.dumps(d, sort_keys=True)
    assert isinstance(s, str) and len(s) > 0


def _assert_has_env_placeholder(d: dict) -> None:
    blob = json.dumps(d)
    assert "{{env:" in blob


def test_hubspot_to_dict_roundtrip_from_curl_parse(compiler):
    curl = r"""
    curl --request GET \
      --url 'https://api.hubapi.com/crm/v3/objects/companies?limit=10' \
      --header 'Authorization: Bearer $HUBSPOT_TOKEN'
    """.strip()

    tool = compiler.parse(curl, description="HubSpot: List companies")
    d1 = tool.to_dict()

    _assert_json_roundtrip(d1)
    _assert_has_env_placeholder(d1)

    tool2 = compiler.request_schema_from_dict(d1)
    d2 = tool2.to_dict()

    assert d2 == d1


pytestmark = pytest.mark.skipif(
    not os.getenv("OPENAI_API_KEY"),
    reason="OPENAI_API_KEY not set (skipping gpt_parse to_dict test)",
)


@pytest.mark.asyncio
async def test_hubspot_to_dict_roundtrip_from_gpt_parse(compiler):
    tool = await compiler.gpt_parse(
        HUBSPOT_DOCS,
        model_name="gpt-4o-mini",
        cost_limit=0.02,
        debug=False,
    )
    d1 = tool.to_dict()

    _assert_json_roundtrip(d1)
    _assert_has_env_placeholder(d1)

    tool2 = compiler.request_schema_from_dict(d1)
    d2 = tool2.to_dict()

    assert d2 == d1
