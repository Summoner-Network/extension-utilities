import json
import os
import pytest


HEYREACH_DOCS = r"""
HeyReach Public API

Base URL:
https://api.heyreach.io/api/public

Authentication:
All endpoints require an API key passed in the X-API-KEY header.
Environment:
HEYREACH_API_KEY=your-api-key-here

Example: Check API key (read-only)
GET /auth/CheckApiKey

curl --location 'https://api.heyreach.io/api/public/auth/CheckApiKey' \
  --header 'X-API-KEY: $HEYREACH_API_KEY' \
  --header 'Accept: text/plain'

Example: Get all campaigns (read-only)
POST /campaign/GetAll

curl --location 'https://api.heyreach.io/api/public/campaign/GetAll' \
  --header 'X-API-KEY: $HEYREACH_API_KEY' \
  --header 'Content-Type: application/json' \
  --header 'Accept: text/plain' \
  --data '{
    "offset": 0,
    "keyword": "",
    "statuses": [],
    "accountIds": [],
    "limit": 10
  }'
"""


def _assert_json_roundtrip(d: dict) -> None:
    # JSON-serializable
    s = json.dumps(d, sort_keys=True)
    assert isinstance(s, str) and len(s) > 0


def _assert_has_env_placeholder(d: dict) -> None:
    # Should contain at least one {{env:...}} placeholder
    blob = json.dumps(d)
    assert "{{env:" in blob


def test_heyreach_to_dict_roundtrip_from_curl_parse(compiler):
    curl = r"""
    curl --location 'https://api.heyreach.io/api/public/auth/CheckApiKey' \
      --header 'X-API-KEY: $HEYREACH_API_KEY' \
      --header 'Accept: text/plain'
    """.strip()

    tool = compiler.parse(curl, description="HeyReach: CheckApiKey (read-only)")
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
async def test_heyreach_to_dict_roundtrip_from_gpt_parse(compiler):
    tool = await compiler.gpt_parse(
        HEYREACH_DOCS,
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
