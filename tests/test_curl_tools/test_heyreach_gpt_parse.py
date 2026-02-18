import os
import pytest
from dotenv import load_dotenv

load_dotenv()  # <-- ensure OPENAI_API_KEY is loaded from .env before skipif


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

Example: Webhooks (mutation endpoints exist, do NOT run them by default)
POST /webhooks/CreateWebhook
DELETE /webhooks/DeleteWebhook
"""

@pytest.mark.asyncio
async def test_heyreach_gpt_parse_builds_tool(compiler):
    # Skip at runtime (after fixtures ran), not at import time.
    if getattr(compiler, "_openai_client", None) is None:
        pytest.skip("OPENAI_API_KEY not set (compiler has no OpenAI client)")

    tool = await compiler.gpt_parse(
        HEYREACH_DOCS,
        model_name="gpt-4o-mini",
        cost_limit=0.02,
        debug=False,
    )

    # Basic sanity: URL should be HeyReach public API
    assert isinstance(tool.spec.url, str)
    assert "api.heyreach.io" in tool.spec.url
    assert "/api/public/" in tool.spec.url

    # Method: allow a few because the model may choose any documented endpoint
    assert tool.spec.method in ("GET", "POST", "PATCH", "DELETE")

    # Must include the API key header (case-insensitive)
    headers = {k.lower(): v for k, v in (tool.spec.headers or {}).items()}
    assert "x-api-key" in headers, f"Missing X-API-KEY header. Got headers: {tool.spec.headers}"

    # Must be templated (no raw secrets)
    x_api_key_val = headers["x-api-key"]
    assert "{{env:" in x_api_key_val, f"X-API-KEY should be templated, got: {x_api_key_val}"

