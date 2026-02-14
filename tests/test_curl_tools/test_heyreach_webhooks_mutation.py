import os
import json
import time
import uuid
import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_HEYREACH_MUTATION") != "1",
    reason="Set RUN_HEYREACH_MUTATION=1 to run HeyReach mutation tests (create+delete only)",
)

def _as_json(report):
    if report.response_json is not None:
        return report.response_json
    if report.response_text:
        txt = report.response_text.strip()
        if txt.startswith("{") or txt.startswith("[") or txt.isdigit():
            try:
                return json.loads(txt)
            except Exception:
                # Some endpoints might return plain numbers like "0"
                return txt
    return None


@pytest.fixture
def has_heyreach_env() -> bool:
    return bool(os.getenv("HEYREACH_API_KEY"))


@pytest.mark.asyncio
async def test_heyreach_webhook_create_then_delete(compiler, has_heyreach_env):
    if not has_heyreach_env:
        pytest.skip("Missing HEYREACH_API_KEY")

    # HeyReach enforces WebhookName max length 25.
    # Keep it unique but short: "sdk-" + 4 hex time + "-" + 8 hex uuid = 4+4+1+8 = 17 chars.
    t_hex = hex(int(time.time()))[-4:]
    u_hex = uuid.uuid4().hex[:8]
    webhook_name = f"sdk-{t_hex}-{u_hex}"  # <= 25 chars guaranteed
    unique = f"{t_hex}-{u_hex}"  # keep separate "unique" token for URL/query usage

    # Use a stable endpoint that reliably returns 200 (some providers validate the URL at creation time).
    webhook_url = f"https://httpbin.org/status/200?run={unique}"

    # Many accounts require selecting at least one campaign for webhook creation.
    # Fetch a campaign id first (read-only) and attach the webhook to it.
    campaign_tool = compiler.request_schema(
        method="POST",
        url="https://api.heyreach.io/api/public/campaign/GetAll",
        headers={
            "X-API-KEY": "{{env:HEYREACH_API_KEY}}",
            "Content-Type": "application/json",
            "Accept": "text/plain",
        },
        body_mode="json",
        body={
            "offset": 0,
            "limit": 10,
            "keyword": "",
            "statuses": [],
            "accountIds": [],
        },
        description="HeyReach: Get campaigns (read-only helper for webhook mutation test)",
    )

    campaign_report = await campaign_tool.call({})
    if not campaign_report.ok or not isinstance(campaign_report.response_json, dict):
        pytest.skip(f"HeyReach campaigns query failed: {campaign_report.status_code} {campaign_report.response_text}")

    items = campaign_report.response_json.get("items") or []
    if not items or not isinstance(items, list):
        pytest.skip("No HeyReach campaigns found; cannot safely create a webhook without attaching it to a campaign.")

    campaign_id = items[0].get("id")
    if campaign_id is None:
        pytest.skip("HeyReach campaigns response missing 'id' in first item; cannot proceed with webhook creation.")

    create_tool = compiler.request_schema(
        method="POST",
        url="https://api.heyreach.io/api/public/webhooks/CreateWebhook",
        headers={
            "X-API-KEY": "{{env:HEYREACH_API_KEY}}",
            "Content-Type": "application/json",
            "Accept": "text/plain",
        },
        body_mode="json",
        body={
            "webhookName": webhook_name,
            "webhookUrl": webhook_url,
            "eventType": "VIEWED_PROFILE",
            "campaignIds": [campaign_id],
        },
        description="HeyReach: Create webhook (mutation test)",
    )

    # Prefer query params for GET listing (GET bodies are often ignored by clients/proxies).
    # HeyReach docs claim GET, but some deployments reject it (405). Use POST for robustness.
    list_tool = compiler.request_schema(
        method="POST",
        url="https://api.heyreach.io/api/public/webhooks/GetAllWebhooks",
        headers={
            "X-API-KEY": "{{env:HEYREACH_API_KEY}}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        # Use raw JSON so numeric placeholders are injected without quotes.
        body_mode="raw",
        body='{"offset": {{offset}}, "limit": {{limit}}}',
        description="HeyReach: List webhooks",
    )

    deactivate_tool = compiler.request_schema(
        method="PATCH",
        url="https://api.heyreach.io/api/public/webhooks/UpdateWebhook?webhookId={{webhookId}}",
        headers={
            "X-API-KEY": "{{env:HEYREACH_API_KEY}}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        body_mode="json",
        body={
            "isActive": False,
            # Keep other fields null so we only toggle activation.
            "webhookName": None,
            "webhookUrl": None,
            "eventType": None,
            "campaignIds": None,
        },
        description="HeyReach: Deactivate webhook (required before delete)",
    )

    delete_tool = compiler.request_schema(
        method="DELETE",
        url="https://api.heyreach.io/api/public/webhooks/DeleteWebhook?webhookId={{webhookId}}",
        headers={
            "X-API-KEY": "{{env:HEYREACH_API_KEY}}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        body_mode="raw",
        body=None,
        description="HeyReach: Delete webhook (mutation test)",
    )

    created_id = None
    try:
        # Create
        create_report = await create_tool.call({})

        # If the account/key cannot create webhooks (plan/permissions), skip instead of failing the suite.
        if create_report.status_code in (401, 403):
            pytest.skip(f"HeyReach API key not permitted to create webhooks: {create_report.status_code} {create_report.response_text}")

        assert create_report.ok is True, f"{create_report.status_code} {create_report.response_text}"

        assert create_report.status_code in (200, 201)

        # Try to extract ID from response; if absent, we will discover via list.
        create_payload = _as_json(create_report)
        if isinstance(create_payload, dict) and "id" in create_payload:
            created_id = create_payload["id"]

        # List (paginate) and find by name.
        # Many APIs cap limit at 100, so stay conservative.
        found = None
        last_list_report = None
        limit = 100

        for offset in range(0, 500, limit):
            last_list_report = await list_tool.call({"offset": offset, "limit": limit})
            if not last_list_report.ok:
                break

            payload = _as_json(last_list_report)

            if isinstance(payload, dict):
                items = payload.get("items") or []
            elif isinstance(payload, list):
                items = payload
            else:
                items = []

            if not isinstance(items, list):
                items = []

            for it in items:
                if not isinstance(it, dict):
                    continue
                if it.get("webhookName") == webhook_name or it.get("webhookUrl") == webhook_url:
                    found = it
                    break

            if found is not None:
                break

            # If fewer than limit returned, stop early.
            if len(items) < limit:
                break

        assert last_list_report is not None
        if not last_list_report.ok:
            pytest.skip(f"HeyReach GetAllWebhooks failed: {last_list_report.status_code} {last_list_report.response_text}")

        assert found is not None, "Created webhook not found in GetAllWebhooks results (after pagination)."

        # If create response did not include an id, recover it from the list result.
        if created_id is None:
            created_id = found.get("id")

        # We already found the created webhook during pagination.
        assert last_list_report.status_code == 200

        # Ensure we recovered an id for cleanup.
        assert created_id is not None, "Found webhook but could not recover its id for cleanup."

    finally:
        # Always attempt cleanup if we found an id.
        if created_id is not None:
            # HeyReach requires deactivation before deletion.
            deact_report = await deactivate_tool.call({"webhookId": str(created_id)})

            # If we cannot deactivate due to permissions, fail loudly (otherwise we may leave artifacts).
            assert deact_report.status_code in (200, 204), (
                f"Deactivate failed: {deact_report.status_code} {deact_report.response_text}"
            )

            del_report = await delete_tool.call({"webhookId": str(created_id)})

            assert del_report.status_code in (200, 204), (
                f"Delete failed: {del_report.status_code} {del_report.response_text}"
            )

