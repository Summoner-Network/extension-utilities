# cURL tools: cURL parsing and HTTP tool compilation

> [!CAUTION]
> **Development vs composed SDK import path**
>
> The repo `extension-utilities` hosting this extension contains tests under `tests/` that import **curl_tools** as `tooling.curl_tools`, along with a small `sys.path` insertion so they can run directly inside the extension-template layout.
>
> In a composed SDK, the same module is imported as `summoner.curl_tools`, and no `sys.path` insertion is needed.

`curl_tools` is a small module that turns HTTP request descriptions into a callable async tool.

It supports three ways to define a request:

1. **Deterministic parsing** from a practical subset of `curl` (`compiler.parse(...)`).
2. **Explicit specification** through a direct schema (`compiler.request_schema(...)`).
3. **GPT-assisted parsing** from docs and snippets (`compiler.gpt_parse(...)`), guarded by token and cost ceilings.

A key feature is determinism after parsing: once you have a tool, you can call `tool.to_dict()` to snapshot its spec (JSON-safe), store it, and later re-create the exact same tool via `compiler.request_schema_from_dict(...)`.

This lets you treat a GPT-parsed tool as a one-time extraction step, then lock the resulting tool spec in a deterministic format.

## Canonical examples you can run anytime

The hosting repo (`extension-utilities`) contains tests that demonstrate all entry points:

```bash
pytest -q tests/test_curl_tools/
pytest -q tests/test_curl_tools/test_heyreach_*
pytest -q tests/test_curl_tools/test_hubspot_*
pytest -q tests/test_curl_tools/test_twilio_*
```

Integration tests (live API calls) are gated behind explicit flags and secrets:

```bash
RUN_HUBSPOT_INTEGRATION=1 pytest -q tests/test_curl_tools/test_hubspot_integration_readonly.py
RUN_TWILIO_INTEGRATION=1  pytest -q tests/test_curl_tools/test_twilio_integration.py
```

These tests are the reference demo for this README.

## What `curl_tools` does

`curl_tools` compiles to a single runtime object:

* `HttpTool`: an async callable wrapper around an HTTP request spec (`HttpRequestSpec`).

At call time it resolves:

* `{{env:NAME}}` placeholders using a `SecretResolver`
* `{{var}}` placeholders using the `inputs` dict passed to `tool.call(...)`

Then it executes the request through `httpx.AsyncClient`, parses JSON when possible, and returns a `ToolCallReport`.

## Quick reference

### Public entry points

This module exposes:

```python
from tooling.curl_tools import (
    CurlToolCompiler,
    SecretResolver,
    BasicAuthSpec,
    parse_curl_command,
)
```

### `CurlToolCompiler` methods at a glance

| Method                        | What it does                                                          | Key detail                                                     |
| ----------------------------- | --------------------------------------------------------------------- | -------------------------------------------------------------- |
| `parse(curl_text, ...)`       | Deterministically parse a practical subset of curl into an `HttpTool` | Converts `$FOO` and `${FOO}` into `{{env:FOO}}`                |
| `request_schema(...)`         | Build an `HttpTool` from explicit request fields                      | Use when you want a fully deterministic spec with no inference |
| `gpt_parse(docs, ...)`        | Ask OpenAI to extract a request blueprint from docs/snippets          | Enforced by token + cost ceilings via `gpt_guardrails`         |
| `request_schema_from_dict(d)` | Rehydrate a tool spec saved via `tool.to_dict()`                      | Deterministic re-creation of a previously parsed tool          |
| `set_budget(...)`             | Adjust GPT parse ceilings (tokens/cost)                               | Affects `gpt_parse` only                                       |

### `HttpTool` methods at a glance

| Method                          | What it does                                  | Key detail                                                      |
| ------------------------------- | --------------------------------------------- | --------------------------------------------------------------- |
| `call(inputs=None)`             | Executes the request asynchronously           | Renders `{{env:...}}` and `{{var}}` placeholders before sending |
| `to_dict(include_models=False)` | Returns a JSON-safe snapshot of the tool spec | Designed for persistence and deterministic reload               |

## Getting started

The simplest workflow is:

1. Compile a tool via `parse`, `request_schema`, or `gpt_parse`
2. Call `tool.call(...)`
3. If the spec came from GPT or from a curl snippet you want to "freeze", persist `tool.to_dict()`
4. Reload it later deterministically with `request_schema_from_dict(...)`

### Imports and development import path

```python
import sys, os

target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
if target_path not in sys.path:
    sys.path.insert(0, target_path)

from tooling.curl_tools import CurlToolCompiler, SecretResolver
```

In a composed SDK, use:

```python
from summoner.curl_tools import CurlToolCompiler, SecretResolver
```

and no `sys.path` insertion is needed.

## Deterministic curl parsing

`compiler.parse(...)` consumes a practical subset of curl syntax and produces an `HttpTool`.

Supported curl features:

* URL: positional `https://...` or `--url`
* Method: `-X/--request`, or `-G/--get` (forces GET)
* Headers: `-H/--header "Key: Value"`
* Body:

  * `-d/--data/--data-raw/...` payload
  * `--data-urlencode` (produces `body_mode="form"`)
* Basic auth: `-u user:pass`
* Redirects: `-L/--location`
* TLS verify disable: `-k/--insecure`
* Timeout: `--connect-timeout`, `-m/--max-time`

Environment variables such as `$API_TOKEN` or `${API_TOKEN}` are converted into `{{env:API_TOKEN}}`.

Example:

```python
compiler = CurlToolCompiler(secrets=SecretResolver(auto_dotenv=True))

curl_text = r'''
curl --request GET \
  --url "https://api.hubapi.com/crm/v3/objects/companies?limit={{limit}}" \
  --header "Authorization: Bearer $HUBSPOT_TOKEN"
'''

tool = compiler.parse(curl_text, description="HubSpot: list companies")
report = await tool.call({"limit": 10})
assert report.ok
```

## Explicit tools with `request_schema`

If you already know the request shape and want zero inference, use `request_schema(...)`.

Example:

```python
tool = compiler.request_schema(
    method="GET",
    url="https://api.hubapi.com/crm/v3/objects/companies",
    headers={"Authorization": "Bearer {{env:HUBSPOT_TOKEN}}"},
    params={"limit": "{{limit}}"},
    body=None,
    body_mode="json",
    description="HubSpot: list companies",
)

report = await tool.call({"limit": 10})
assert report.status_code == 200
```

## GPT-assisted parsing with `gpt_parse`

`gpt_parse(...)` is intended for "docs-first" tool construction: you paste docs or a mixed docs + curl snippet, and the model emits a structured `CurlToolBlueprint` that your compiler turns into an `HttpTool`.

`gpt_parse` is guarded by:

* prompt token ceiling (`max_chat_input_tokens`)
* worst-case cost ceiling based on output token budget (`max_chat_output_tokens`)
* optional `cost_limit`

This guardrail logic is implemented using `tooling.gpt_guardrails`.

Example:

```python
tool = await compiler.gpt_parse(
    docs_text,
    model_name="gpt-4o-mini",
    cost_limit=0.02,
)

# tool.spec is a normal HttpRequestSpec
assert "api.hubapi.com" in tool.spec.url
```

### What GPT is allowed to do

The GPT prompt enforces these constraints:

* never include real secrets, only `{{env:...}}`
* preserve `$TOKEN` or `${TOKEN}` as `{{env:TOKEN}}`
* do not guess endpoints or parameters not present in the docs
* prefer minimal correct output over speculative completeness

## Templating model

`HttpTool.call(inputs)` performs template rendering in three places:

* URL string
* headers / params dicts
* body (for json/form/raw)

Two placeholder syntaxes exist:

* `{{env:NAME}}`: resolved via `SecretResolver`
* `{{var}}`: resolved via `inputs["var"]`

If a required env var is missing, `SecretResolver.require(...)` raises.
If a required runtime input is missing, `_render_template_str(...)` raises.

This fail-fast behavior is intentional: it prevents partially-formed requests from silently executing.

## Persisting a tool with `to_dict` and reloading later

A common workflow is:

* use `gpt_parse(...)` once to extract the initial tool
* snapshot the result with `to_dict()`
* commit that JSON into your repo (or store it elsewhere)
* later, load and rehydrate deterministically

### Persist

```python
tool = await compiler.gpt_parse(docs_text, model_name="gpt-4o-mini", cost_limit=0.02)
spec_dict = tool.to_dict()  # JSON-safe
with open("hubspot_list_companies.tool.json", "w") as f:
    json.dump(spec_dict, f, indent=2, sort_keys=True)
```

### Reload deterministically

```python
with open("hubspot_list_companies.tool.json", "r") as f:
    d = json.load(f)

tool2 = compiler.request_schema_from_dict(d)
report = await tool2.call({"limit": 10})
```

### Notes about body serialization

`to_dict()` is designed to be JSON-safe:

* tuples become lists (not JSON-native)
* dataclasses become dict-like structures
* non-JSON objects are stringified

When rehydrating, `request_schema_from_dict(...)` performs one special fixup:

* if `body_mode == "form"`, it converts stored lists like `["k","v"]` back to `("k","v")` pairs so `HttpTool.call()` can encode them correctly.

### Models are not persisted by default

`HttpRequestSpec.to_dict(include_models=False)` omits `input_model` and `output_model`.

This is intentional, because serializing python types is not robust across:

* refactors
* module renames
* different packaging layouts

> [!NOTE]
> In future versions, we can add full rehydration for models by allowing the user to set `include_models=True` and extend `request_schema_from_dict(...)` to import by `module:qualname`.

## Integration tests and environment gating

The repo uses explicit "live test" flags to prevent accidental network calls:

* `RUN_HUBSPOT_INTEGRATION=1`
* `RUN_TWILIO_INTEGRATION=1`
* other providers can follow the same pattern

Tests should also skip cleanly when required secrets are missing, for example:

* `HUBSPOT_TOKEN`
* `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN` (depending on your tests)
* `HEYREACH_API_KEY`

A typical integration test gate is:

```python
if os.getenv("RUN_HUBSPOT_INTEGRATION") != "1":
    pytest.skip("Set RUN_HUBSPOT_INTEGRATION=1 (env or .env) to run live HubSpot test", allow_module_level=True)
```

Then, inside the test, skip again if required tokens are missing.

## Troubleshooting

* **My GPT parse test is skipped**
  `gpt_parse` requires `OPENAI_API_KEY`. If it is missing, tests should skip via `pytest.mark.skipif(...)`.

* **`Using pytest.skip outside of a test`**
  If you skip at import time, use `allow_module_level=True`:
  `pytest.skip("...", allow_module_level=True)`.

* **Form requests fail after reload**
  `to_dict()` stores tuples as lists. Reload via `request_schema_from_dict(...)` (not `request_schema(...)` directly) so form bodies are rehydrated correctly.

* **Headers or URL contain raw secrets**
  The intended pattern is to always use `{{env:...}}`. For GPT parsing, `_redact_probable_secrets(...)` performs best-effort redaction before sending docs to OpenAI, but you should still avoid pasting real secrets.
