# tests/test_openai_responses_curl.py

import json
import pytest
import httpx
from dotenv import load_dotenv

load_dotenv()


# ----------------------------
# cURL snippets (Responses API)
# ----------------------------

CURL_CREATE_RESPONSE = (
    'curl https://api.openai.com/v1/responses '
    '-H "Content-Type: application/json" '
    '-H "Authorization: Bearer $OPENAI_API_KEY" '
    "-d '{\"model\":\"gpt-4o-mini\",\"input\":\"Tell me a three sentence bedtime story about a unicorn.\"}'"
)

CURL_RETRIEVE_RESPONSE = (
    "curl https://api.openai.com/v1/responses/resp_123 "
    '-H "Content-Type: application/json" '
    '-H "Authorization: Bearer $OPENAI_API_KEY"'
)

CURL_DELETE_RESPONSE = (
    "curl -X DELETE https://api.openai.com/v1/responses/resp_123 "
    '-H "Content-Type: application/json" '
    '-H "Authorization: Bearer $OPENAI_API_KEY"'
)

CURL_LIST_INPUT_ITEMS = (
    "curl https://api.openai.com/v1/responses/resp_abc123/input_items "
    '-H "Content-Type: application/json" '
    '-H "Authorization: Bearer $OPENAI_API_KEY"'
)


# ----------------------------
# httpx mocking helper
# ----------------------------

@pytest.fixture
def install_mock_httpx(monkeypatch):
    """
    Patch tooling.curl_tools.compiler.httpx.AsyncClient so HttpTool.call()
    uses httpx.MockTransport (no real network).
    """
    original_async_client = httpx.AsyncClient

    def _install(handler):
        transport = httpx.MockTransport(handler)

        class PatchedAsyncClient:
            def __init__(self, *args, **kwargs):
                self._client = original_async_client(*args, transport=transport, **kwargs)

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                await self._client.aclose()

            async def request(self, *args, **kwargs):
                return await self._client.request(*args, **kwargs)

        # Patch *the compiler module's* httpx.AsyncClient reference
        monkeypatch.setattr("tooling.curl_tools.compiler.httpx.AsyncClient", PatchedAsyncClient)
        return transport

    return _install


# ----------------------------
# Tests
# ----------------------------

@pytest.mark.asyncio
async def test_openai_responses_create_parse_and_call(compiler, monkeypatch, install_mock_httpx):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    expected_payload = {
        "id": "resp_test_create",
        "object": "response",
        "created_at": 1741476542,
        "status": "completed",
        "model": "gpt-4o-mini",
        "output": [
            {
                "type": "message",
                "id": "msg_test",
                "status": "completed",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "Once upon a time...", "annotations": []}],
            }
        ],
        "usage": {"input_tokens": 10, "output_tokens": 10, "total_tokens": 20},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert str(request.url) == "https://api.openai.com/v1/responses"
        assert request.headers.get("Content-Type") == "application/json"
        assert request.headers.get("Authorization") == "Bearer sk-test"

        body = json.loads(request.content.decode("utf-8"))
        assert body["model"] == "gpt-4o-mini"
        assert "unicorn" in body["input"].lower()

        return httpx.Response(
            status_code=200,
            json=expected_payload,
            headers={"Content-Type": "application/json"},
        )

    install_mock_httpx(handler)

    tool = compiler.parse(CURL_CREATE_RESPONSE)

    assert tool.spec.method == "POST"
    assert tool.spec.url == "https://api.openai.com/v1/responses"
    assert tool.spec.body_mode == "json"
    assert isinstance(tool.spec.body, dict)
    assert tool.spec.body["model"] == "gpt-4o-mini"

    report = await tool.call()
    assert report.ok is True
    assert report.status_code == 200
    assert report.response_json["id"] == "resp_test_create"
    assert report.request["has_body"] is True
    assert report.request["body_mode"] == "json"


@pytest.mark.asyncio
async def test_openai_responses_retrieve_parse_and_call(compiler, monkeypatch, install_mock_httpx):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    expected_payload = {
        "id": "resp_123",
        "object": "response",
        "created_at": 1741386163,
        "status": "completed",
        "model": "gpt-4o-mini",
        "output": [
            {
                "type": "message",
                "id": "msg_test_retrieve",
                "status": "completed",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "Haiku text", "annotations": []}],
            }
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert str(request.url) == "https://api.openai.com/v1/responses/resp_123"
        assert request.headers.get("Authorization") == "Bearer sk-test"
        return httpx.Response(200, json=expected_payload, headers={"Content-Type": "application/json"})

    install_mock_httpx(handler)

    tool = compiler.parse(CURL_RETRIEVE_RESPONSE)
    assert tool.spec.method == "GET"
    assert tool.spec.body is None

    report = await tool.call()
    assert report.ok is True
    assert report.status_code == 200
    assert report.response_json["id"] == "resp_123"
    assert report.request["has_body"] is False


@pytest.mark.asyncio
async def test_openai_responses_delete_parse_and_call(compiler, monkeypatch, install_mock_httpx):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    expected_payload = {"id": "resp_123", "object": "response", "deleted": True}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "DELETE"
        assert str(request.url) == "https://api.openai.com/v1/responses/resp_123"
        assert request.headers.get("Authorization") == "Bearer sk-test"
        return httpx.Response(200, json=expected_payload, headers={"Content-Type": "application/json"})

    install_mock_httpx(handler)

    tool = compiler.parse(CURL_DELETE_RESPONSE)
    assert tool.spec.method == "DELETE"
    assert tool.spec.body is None

    report = await tool.call()
    assert report.ok is True
    assert report.status_code == 200
    assert report.response_json == expected_payload


@pytest.mark.asyncio
async def test_openai_responses_list_input_items_parse_and_call(compiler, monkeypatch, install_mock_httpx):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    expected_payload = {
        "object": "list",
        "data": [
            {
                "id": "msg_abc123",
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": "Tell me a three sentence bedtime story about a unicorn."}],
            }
        ],
        "first_id": "msg_abc123",
        "last_id": "msg_abc123",
        "has_more": False,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert str(request.url) == "https://api.openai.com/v1/responses/resp_abc123/input_items"
        assert request.headers.get("Authorization") == "Bearer sk-test"
        return httpx.Response(200, json=expected_payload, headers={"Content-Type": "application/json"})

    install_mock_httpx(handler)

    tool = compiler.parse(CURL_LIST_INPUT_ITEMS)
    assert tool.spec.method == "GET"
    assert tool.spec.body is None

    report = await tool.call()
    assert report.ok is True
    assert report.status_code == 200
    assert report.response_json["object"] == "list"
    assert report.response_json["has_more"] is False
    assert report.response_json["data"][0]["id"] == "msg_abc123"
