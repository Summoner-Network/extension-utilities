import os
import pytest
from dotenv import load_dotenv

load_dotenv()  # <-- ensure OPENAI_API_KEY is loaded from .env before skipif

HUBSPOT_DOCS = r"""
HubSpot CRM API (excerpt)

Goal: build a tool that retrieves (lists) companies.
Use the endpoint that lists companies with a limit query parameter.

Base:
https://api.hubapi.com

Auth:
All requests require an OAuth access token in the header:
Authorization: Bearer $HUBSPOT_ACCESS_TOKEN

Companies - Retrieve (list)
GET /crm/v3/objects/companies?limit=10

cURL:
curl --request GET \
  --url 'https://api.hubapi.com/crm/v3/objects/companies?limit=10' \
  --header 'Authorization: Bearer $HUBSPOT_ACCESS_TOKEN'

On 200:
{
  "results": [
    {
      "id": "<string>",
      "properties": {},
      "createdAt": "2023-11-07T05:31:56Z",
      "updatedAt": "2023-11-07T05:31:56Z",
      "archived": true
    }
  ],
  "paging": {
    "next": {
      "after": "NTI1Cg%3D%3D"
    }
  }
}
"""


@pytest.mark.asyncio
async def test_hubspot_gpt_parse_builds_tool(compiler):
    if not os.getenv("OPENAI_API_KEY"):
        pytest.skip("OPENAI_API_KEY not set")

    tool = await compiler.gpt_parse(
        HUBSPOT_DOCS,
        model_name="gpt-4o-mini",
        cost_limit=0.02,
        debug=False,
    )

    # Should target HubSpot CRM companies list
    assert tool.spec.method == "GET"
    assert "api.hubapi.com" in tool.spec.url
    assert "/crm/v3/objects/companies" in tool.spec.url

    # Must include Authorization Bearer header and keep it templated
    headers_lower = {k.lower(): v for k, v in (tool.spec.headers or {}).items()}
    assert "authorization" in headers_lower
    auth_val = headers_lower["authorization"]
    assert "Bearer" in auth_val
    assert "{{env:" in auth_val
