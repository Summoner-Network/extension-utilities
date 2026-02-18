import os
import json
import pytest
from typing import Any, Optional


def _assert_report_ok(report: Any, expected_status: int = 200) -> None:
    assert getattr(report, "ok", False), f"Request failed: {getattr(report, 'response_text', None)}"
    assert getattr(report, "status_code", None) == expected_status, (
        f"Unexpected status: {getattr(report, 'status_code', None)}; "
        f"body={getattr(report, 'response_text', None)}"
    )


def _payload(report: Any) -> dict:
    """
    CurlToolCompiler's HttpTool.call returns ToolCallReport.
    Prefer response_json; fallback to parsing response_text if needed.
    """
    pj = getattr(report, "response_json", None)
    if isinstance(pj, dict):
        return pj
    pt = getattr(report, "response_text", None)
    if isinstance(pt, str) and pt.strip():
        return json.loads(pt)
    raise TypeError(f"Cannot decode payload from report: {type(report)}")


def _extract_text(message_payload: dict) -> str:
    """
    Anthropic Messages returns: {"content": [{"type":"text","text":"..."} , ...], ...}
    """
    content = message_payload.get("content") or []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            t = block.get("text")
            if isinstance(t, str):
                return t
    return ""


@pytest.mark.asyncio
async def test_anthropic_messages_create_and_count_tokens(compiler):
    if not os.getenv("ANTHROPIC_API_KEY"):
        pytest.skip("ANTHROPIC_API_KEY not set")

    # Prefer the cheapest tier: Claude Haiku 3
    preferred_model = "claude-3-haiku-20240307"

    list_models_curl = r"""
curl https://api.anthropic.com/v1/models \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -H "X-Api-Key: $ANTHROPIC_API_KEY" \
  -m 60
""".strip()

    create_message_curl = r"""
curl https://api.anthropic.com/v1/messages \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -H "X-Api-Key: $ANTHROPIC_API_KEY" \
  -m 60 \
  -d '{
    "model": "{{model_id}}",
    "max_tokens": 64,
    "temperature": 0,
    "messages": [
      { "role": "user", "content": "{{prompt}}" }
    ]
  }'
""".strip()

    count_tokens_curl = r"""
curl https://api.anthropic.com/v1/messages/count_tokens \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -H "X-Api-Key: $ANTHROPIC_API_KEY" \
  -m 60 \
  -d '{
    "model": "{{model_id}}",
    "messages": [
      { "role": "user", "content": "{{prompt}}" }
    ]
  }'
""".strip()

    get_model_curl = r"""
curl https://api.anthropic.com/v1/models/{{model_id}} \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -H "X-Api-Key: $ANTHROPIC_API_KEY" \
  -m 60
""".strip()

    list_tool = compiler.parse(list_models_curl)
    create_tool = compiler.parse(create_message_curl)
    count_tool = compiler.parse(count_tokens_curl)
    get_model_tool = compiler.parse(get_model_curl)

    # 1) List models (robustly pick a Haiku model)
    models_report = await list_tool.call({})
    _assert_report_ok(models_report, expected_status=200)
    models_payload = _payload(models_report)

    data = models_payload.get("data") or []
    model_ids = [m.get("id") for m in data if isinstance(m, dict) and isinstance(m.get("id"), str)]

    chosen: Optional[str] = None
    if preferred_model in model_ids:
        chosen = preferred_model
    else:
        # fallback: pick the first "haiku" model available to this account
        for mid in model_ids:
            if isinstance(mid, str) and "haiku" in mid:
                chosen = mid
                break

    if not chosen:
        pytest.skip("No Haiku model available on this Anthropic account")

    # 2) Create a message
    prompt = "Say 'ok' and one short sentence describing what you are."
    msg_report = await create_tool.call({"model_id": chosen, "prompt": prompt})
    _assert_report_ok(msg_report, expected_status=200)
    msg = _payload(msg_report)

    assert msg.get("type") == "message"
    assert isinstance(msg.get("id"), str) and msg["id"]
    assert isinstance(msg.get("model"), str) and msg["model"]
    assert msg.get("role") == "assistant"

    text = _extract_text(msg)
    assert isinstance(text, str) and text.strip()

    # 3) Count tokens for the same prompt
    ct_report = await count_tool.call({"model_id": chosen, "prompt": prompt})
    _assert_report_ok(ct_report, expected_status=200)
    ct = _payload(ct_report)

    assert isinstance(ct.get("input_tokens"), int)
    assert ct["input_tokens"] > 0

    # 4) Get model info for the chosen model id
    model_report = await get_model_tool.call({"model_id": chosen})
    _assert_report_ok(model_report, expected_status=200)
    mi = _payload(model_report)

    assert isinstance(mi.get("id"), str)
    assert mi["id"] == chosen
