# Utility Extensions

This repository is a Summoner extension workspace focused on reusable utilities under `tooling/`. It started from the extension template, but the main value here is the set of extension modules you can develop locally, test in isolation, and later compose into a Summoner SDK.

## Extensions in `tooling/`

| Extension | What it does | Main entry points | More detail |
| --- | --- | --- | --- |
| `tooling.curl_tools` | Compiles HTTP tools from curl snippets, explicit request schemas, or GPT-assisted extraction from docs | `CurlToolCompiler`, `SecretResolver`, `BasicAuthSpec`, `parse_curl_command` | [tooling/curl_tools/readme.md](tooling/curl_tools/readme.md) |
| `tooling.gpt_guardrails` | Counts tokens, estimates cost before OpenAI calls, and computes actual cost from usage metadata | `count_chat_tokens`, `estimate_chat_request_cost`, `count_embedding_tokens`, `get_usage_from_response` | [tooling/gpt_guardrails/readme.md](tooling/gpt_guardrails/readme.md) |
| `tooling.visionary` | Visualizes Summoner client flow graphs in the browser, including active states and streamed logs | `ClientFlowVisualizer` | [tooling/visionary/readme.md](tooling/visionary/readme.md) |

### `curl_tools`

`curl_tools` is for turning request definitions into deterministic async tools.

- Parse a practical subset of `curl`
- Build tools directly from an explicit request schema
- Extract request blueprints from docs or snippets with GPT
- Persist a parsed tool with `tool.to_dict()` and recreate it later without re-parsing

This is the most API-integration-heavy extension in the repo, and its tests cover HubSpot, Twilio, HeyReach, and OpenAI-shaped request flows.

### `gpt_guardrails`

`gpt_guardrails` is a small budgeting layer for LLM calls.

- Count prompt or embedding tokens before a request
- Estimate worst-case cost from a token budget
- Block requests that exceed token or dollar ceilings
- Normalize usage data and compute actual cost after the response

It is intentionally narrow: it does not do retries, validation, or rate limiting.

### `visionary`

`visionary` is a lightweight browser visualizer for Summoner client flows.

- Renders the static graph extracted from `client.dna()`
- Highlights the active nodes and edge-label tokens you push at runtime
- Streams Python logger output into a small in-browser activity terminal

The demo agent in `tests/test_visionary/agent.py` is the quickest way to see it in action.

## Development import path vs composed SDK import path

Inside this repository, examples and tests import from `tooling.*`:

```python
from tooling.curl_tools import CurlToolCompiler
from tooling.gpt_guardrails import count_chat_tokens
from tooling.visionary import ClientFlowVisualizer
```

Once these extensions are composed into a Summoner SDK, the public import path becomes `summoner.*`:

```python
from summoner.curl_tools import CurlToolCompiler
from summoner.gpt_guardrails import count_chat_tokens
from summoner.visionary import ClientFlowVisualizer
```

## Quick start

Clone the repo and set up the Summoner core environment:

```bash
git clone https://github.com/Summoner-Network/extension-utilities.git
cd extension-utilities
source install.sh setup
```

Then install the repo's Python requirements for the extensions, agents, and tests:

```bash
bash install_requirements.sh
```

If you prefer not to source the setup script, run `bash install.sh setup` and then activate the virtual environment manually with `source venv/bin/activate` before installing requirements.

On Windows, use:

```powershell
.\install_on_windows.ps1 setup
.\install_requirements_on_windows.ps1
```

## Run the main extension demos

### `curl_tools`

Run the full local test suite:

```bash
pytest -q tests/test_curl_tools/
```

A few narrower test groups are also useful while iterating:

```bash
pytest -q tests/test_curl_tools/test_heyreach_*
pytest -q tests/test_curl_tools/test_hubspot_*
pytest -q tests/test_curl_tools/test_twilio_*
```

Live integration tests are opt-in and require secrets plus explicit flags:

```bash
RUN_HUBSPOT_INTEGRATION=1 pytest -q tests/test_curl_tools/test_hubspot_integration_readonly.py
RUN_TWILIO_INTEGRATION=1  pytest -q tests/test_curl_tools/test_twilio_integration.py
```

### `gpt_guardrails`

Run the budgeting and usage tests:

```bash
pytest -q tests/test_gpt_guardrails
```

Or target chat and embedding coverage separately:

```bash
pytest -q tests/test_gpt_guardrails/test_chat.py
pytest -q tests/test_gpt_guardrails/test_emb.py
```

### `visionary`

Start a Summoner server:

```bash
python server.py
```

Then run the demo visualizer agent:

```bash
python tests/test_visionary/agent.py
```

That agent opens the browser visualizer, loads a flow graph from client DNA, and starts pushing active state updates.

## Manual testing helpers

The repo also includes a small CLI agent for sending ad hoc messages while you develop:

- `python agents/agent_InputAgent/agent.py`
- `python agents/agent_InputAgent/agent.py --multiline 1`

`InputAgent` tries to parse JSON before sending, which makes it useful for driving flow demos and structured tool inputs. See [agents/agent_InputAgent/readme.md](agents/agent_InputAgent/readme.md) for examples.

## Repo layout

```text
.
├── agents/
│   └── agent_InputAgent/      # Small manual input agent for local testing
├── configs/                   # Server/client config variants
├── tests/                     # Extension demos and regression tests
├── tooling/
│   ├── curl_tools/            # HTTP tool compiler
│   ├── gpt_guardrails/        # Token and cost budgeting helpers
│   ├── visionary/             # Browser flow visualizer
│   └── your_package/          # Template stub kept for bootstrap smoke tests
├── install.sh
├── install_requirements.sh
├── server.py                  # Simple local Summoner server entry point
└── README_template.md         # Original template context
```

## Notes

- `install.sh test_server` is still the template-style bootstrap smoke test and uses `tooling/your_package`; it is separate from the three main extension modules documented above.
- The extension-specific docs under `tooling/*/readme.md` are the best place to look for API details and longer examples.
