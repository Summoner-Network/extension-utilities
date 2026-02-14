import os
import json
from dotenv import load_dotenv
import pytest

load_dotenv() 


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_HEYREACH_INTEGRATION") != "1",
    reason="Set RUN_HEYREACH_INTEGRATION=1 to run HeyReach live tests",
)


def _as_json(report):
    """
    HeyReach may return JSON with content-type text/plain.
    Prefer report.response_json; fallback to json.loads(response_text).
    """
    if report.response_json is not None:
        return report.response_json
    if report.response_text:
        txt = report.response_text.strip()
        if txt.startswith("{") or txt.startswith("["):
            return json.loads(txt)
    return None


@pytest.fixture
def has_heyreach_env() -> bool:
    return bool(os.getenv("HEYREACH_API_KEY"))


@pytest.mark.asyncio
async def test_heyreach_check_api_key_live(compiler, has_heyreach_env):
    if not has_heyreach_env:
        pytest.skip("Missing HEYREACH_API_KEY")

    tool = compiler.request_schema(
        method="GET",
        url="https://api.heyreach.io/api/public/auth/CheckApiKey",
        headers={"X-API-KEY": "{{env:HEYREACH_API_KEY}}"},
        body_mode="raw",
        body=None,
        description="HeyReach: Check API key",
    )

    report = await tool.call({})
    assert report.ok is True
    assert report.status_code in (200, 204)


@pytest.mark.asyncio
async def test_heyreach_campaign_get_all_readonly_live(compiler, has_heyreach_env):
    if not has_heyreach_env:
        pytest.skip("Missing HEYREACH_API_KEY")

    tool = compiler.request_schema(
        method="POST",
        url="https://api.heyreach.io/api/public/campaign/GetAll",
        headers={
            "X-API-KEY": "{{env:HEYREACH_API_KEY}}",
            "Content-Type": "application/json",
            # Prefer JSON response, but we still tolerate text/plain via _as_json
            "Accept": "application/json",
        },
        body_mode="json",
        body={
            "offset": 0,
            "keyword": "",
            "statuses": [],
            "accountIds": [],
            "limit": 1,
        },
        description="HeyReach: Get all campaigns (read-only)",
    )

    report = await tool.call({})
    assert report.ok is True
    assert report.status_code == 200

    payload = _as_json(report)
    assert payload is not None
    assert "totalCount" in payload
    assert "items" in payload
