# tests/test_curl_tools/test_hubspot_integration_readonly.py

import os
import pytest
from dotenv import load_dotenv

load_dotenv()

def _missing_env() -> list[str]:
    missing = []
    if os.getenv("RUN_HUBSPOT_INTEGRATION") != "1":
        missing.append("RUN_HUBSPOT_INTEGRATION=1")
    if not os.getenv("HUBSPOT_ACCESS_TOKEN"):
        missing.append("HUBSPOT_ACCESS_TOKEN")
    return missing

@pytest.mark.asyncio
async def test_hubspot_companies_list_readonly(compiler):
    missing = _missing_env()
    if missing:
        pytest.skip("Missing: " + ", ".join(missing))

    tool = compiler.request_schema(
        method="GET",
        url="https://api.hubapi.com/crm/v3/objects/companies",
        params={"limit": "10"},
        headers={
            "Authorization": "Bearer {{env:HUBSPOT_ACCESS_TOKEN}}",
            "Accept": "application/json",
        },
        body_mode="raw",
        body=None,
        description="HubSpot: list companies (read-only)",
    )

    report = await tool.call({})
    assert report.ok is True, f"{report.status_code} {report.response_text}"
    assert isinstance(report.response_json, dict)
    assert "results" in report.response_json
