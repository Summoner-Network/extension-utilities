import json

import httpx
import pytest

from tooling.curl_tools import CurlToolCompiler, SecretResolver


DOCS_TEXT = """
HubSpot CRM API (excerpt)

Goal: build a read-only tool that lists companies.

Base:
https://api.hubapi.com

Auth:
Authorization: Bearer $HUBSPOT_ACCESS_TOKEN

Endpoint:
GET /crm/v3/objects/companies?limit=10
""".strip()


@pytest.fixture
def install_mock_httpx(monkeypatch):
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

        monkeypatch.setattr("tooling.curl_tools.compiler.httpx.AsyncClient", PatchedAsyncClient)
        return transport

    return _install


def _build_structured_response(blueprint: dict) -> dict:
    return {
        "id": "resp_test",
        "object": "response",
        "status": "completed",
        "model": "gpt-4o-mini",
        "output": [
            {
                "id": "msg_test",
                "type": "message",
                "role": "assistant",
                "content": [
                    {
                        "type": "output_text",
                        "text": json.dumps(blueprint),
                        "annotations": [],
                    }
                ],
            }
        ],
        "usage": {"input_tokens": 25, "output_tokens": 50, "total_tokens": 75},
    }


@pytest.mark.asyncio
async def test_gpt_parse_bootstraps_openai_via_http_tool(monkeypatch, install_mock_httpx):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    compiler = CurlToolCompiler(
        secrets=SecretResolver(auto_dotenv=False),
        openai_api_key="sk-direct",
        auto_dotenv=False,
        validate_model_name=False,
    )

    blueprint = {
        "name": "hubspot_list_companies",
        "description": "HubSpot: list companies",
        "method": "GET",
        "url": "https://api.hubapi.com/crm/v3/objects/companies",
        "headers": [{"key": "Authorization", "value": "Bearer {{env:HUBSPOT_ACCESS_TOKEN}}"}],
        "params": [{"key": "limit", "value": "10"}],
        "body_mode": "json",
        "body_text": None,
        "form_fields": [],
        "basic_auth_username": None,
        "basic_auth_password": None,
        "follow_redirects": False,
        "verify_tls": True,
        "timeout_s": 30.0,
        "required_env": ["HUBSPOT_ACCESS_TOKEN"],
        "templating_notes": "Keep the bearer token templated.",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert str(request.url) == "https://api.openai.com/v1/responses"
        assert request.headers.get("Authorization") == "Bearer sk-direct"
        assert request.headers.get("Content-Type") == "application/json"

        payload = json.loads(request.content.decode("utf-8"))
        assert payload["model"] == "gpt-4o-mini"
        assert payload["max_output_tokens"] == compiler.max_chat_output_tokens
        assert payload["input"][0]["role"] == "user"
        assert "HubSpot CRM API" in payload["input"][0]["content"]
        assert payload["text"]["format"]["type"] == "json_schema"
        assert payload["text"]["format"]["name"] == "curl_tool_blueprint"
        assert payload["text"]["format"]["strict"] is True
        assert payload["text"]["format"]["schema"]["additionalProperties"] is False
        assert "method" in payload["text"]["format"]["schema"]["properties"]

        return httpx.Response(
            200,
            json=_build_structured_response(blueprint),
            headers={"Content-Type": "application/json"},
        )

    install_mock_httpx(handler)

    tool = await compiler.gpt_parse(
        DOCS_TEXT,
        model_name="gpt-4o-mini",
        cost_limit=0.02,
        debug=False,
    )

    assert tool.spec.method == "GET"
    assert tool.spec.url == "https://api.hubapi.com/crm/v3/objects/companies"
    assert tool.spec.params == {"limit": "10"}
    assert tool.spec.headers["Authorization"] == "Bearer {{env:HUBSPOT_ACCESS_TOKEN}}"


@pytest.mark.asyncio
async def test_gpt_parse_model_validation_uses_models_endpoint(monkeypatch, install_mock_httpx):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    compiler = CurlToolCompiler(
        secrets=SecretResolver(auto_dotenv=False),
        openai_api_key="sk-direct",
        auto_dotenv=False,
        validate_model_name=True,
    )

    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        assert request.headers.get("Authorization") == "Bearer sk-direct"

        if request.url.path == "/v1/models":
            return httpx.Response(
                200,
                json={
                    "object": "list",
                    "data": [{"id": "gpt-4o-mini"}, {"id": "gpt-4o"}],
                },
                headers={"Content-Type": "application/json"},
            )

        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    install_mock_httpx(handler)

    with pytest.raises(ValueError, match="Invalid model_name 'not-a-real-model'"):
        await compiler.gpt_parse(
            DOCS_TEXT,
            model_name="not-a-real-model",
            cost_limit=0.02,
            debug=False,
        )

    assert calls == [("GET", "/v1/models")]
