# GPT guardrails: token and cost budgeting helpers

> [!CAUTION]
> **Development vs composed SDK import path**
>
> The repo `extension-utilities` hosting this extension contains test scripts under `tests/` that import **gpt_guardrails** as `tooling.gpt_guardrails`, along with a small `sys.path` insertion so they can run directly inside the extension-template layout.
>
> In a composed SDK, the same module is imported as `summoner.gpt_guardrails`, and no `sys.path` insertion is needed.

`gpt_guardrails` is a small set of utilities to **measure tokens** and **budget cost** before calling OpenAI, and to **compute actual cost** after the response when usage is available.

It is intentionally narrow:

* It does not validate content.
* It does not retry.
* It does not split batches.
* It does not enforce rate limits.

It gives you a simple pattern:

1. Count tokens for the payload you are about to send.
2. Estimate worst-case cost given your output token budget (chat) or input tokens (embeddings).
3. Block the call if you exceed a token ceiling or a dollar ceiling.
4. Extract usage from the response and compute actual cost.

## Canonical examples you can run anytime

The hosting repo (`extension-utilities`) includes tests that demonstrate these guardrails end-to-end. Typical workflows are:

```bash
pytest -q tests/test_gpt_guardrails
pytest -q tests/test_gpt_guardrails/test_chat.py    # test for chat-based guardrails
pytest -q tests/test_gpt_guardrails/test_emb.py     # test for embedding-based guardrails
```

The chat example demonstrates:

* token counting for chat messages
* estimated cost using `max_completion_tokens`
* actual cost from response usage
* optional structured parsing via the Responses API

The embedding example demonstrates:

* token counting for a list of texts
* estimated cost (input-only)
* actual cost from response usage

These tests are the reference demo for this README.

## How `llm_guardrails` works

### What is budgeted

| API family | Token function                              | What it counts                                                                                      | Cost estimate inputs                      | Actual cost inputs                                |
| ---------- | ------------------------------------------- | --------------------------------------------------------------------------------------------------- | ----------------------------------------- | ------------------------------------------------- |
| Chat       | `count_chat_tokens(messages, model)`        | Estimated **prompt tokens** for a chat payload (includes per-message overhead + final `+3` priming) | `prompt_tokens` + `max_completion_tokens` | `usage.prompt_tokens` + `usage.completion_tokens` |
| Embeddings | `count_embedding_tokens(texts, model_name)` | Sum of tokens across the **entire text list**                                                       | `input_tokens`                            | `usage.total_tokens` (input-only billing)         |

### Tokenization fallback

Both chat and embeddings use `tiktoken.encoding_for_model(...)`. If the model is not mapped in `tiktoken`, the encoding falls back to `cl100k_base` (best-effort approximation).

### Usage extraction

`get_usage_from_response(response)` returns a unified `Usage(prompt_tokens, completion_tokens, total_tokens)` by normalizing:

* Chat Completions usage: `prompt_tokens`, `completion_tokens`, `total_tokens`
* Responses API usage: `input_tokens`, `output_tokens`, `total_tokens`

If usage is missing, it returns `None` (pre-call estimates still work; post-call cost is unavailable).

## Quick reference

### Public entry points

`gpt_guardrails` exposes token and cost functions for:

* chat-style calls
* embeddings calls
* usage extraction and normalization

### Functions at a glance

| Function                                                                  | What it does                                      | Key detail                                                   |
| ------------------------------------------------------------------------- | ------------------------------------------------- | ------------------------------------------------------------ |
| `count_chat_tokens(messages, model)`                                      | Counts prompt tokens for a chat payload           | Includes per-message overhead and assistant priming overhead |
| `estimate_chat_request_cost(model, prompt_tokens, max_completion_tokens)` | Estimates USD cost for a chat call                | Uses pricing table and assumes full `max_completion_tokens`  |
| `actual_chat_request_cost(model, prompt_tokens, completion_tokens)`       | Computes USD cost after a chat call               | Uses usage tokens from the response                          |
| `count_embedding_tokens(texts, model)`                                    | Counts total input tokens for an embeddings batch | Sums tokens across the entire list                           |
| `estimate_embedding_request_cost(model, input_tokens)`                    | Estimates USD cost for embeddings                 | Input-only billing                                           |
| `actual_embedding_request_cost(model, input_tokens)`                      | Computes USD cost for embeddings                  | Same as estimate in this module                              |
| `normalize_usage(usage_obj)`                                              | Normalizes usage dict-like objects                | Accepts `prompt/completion` or `input/output` keys           |
| `get_usage_from_response(response)`                                       | Extracts a unified `Usage` from a response        | Returns `None` if `response.usage` is missing                |

## Getting started

The simplest way to use `gpt_guardrails` is to wrap your OpenAI call with two checks:

* a token ceiling
* a dollar ceiling (optional)

and then compute actual cost from response usage.

### Imports and development import path

```python
import sys, os

target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
if target_path not in sys.path:
    sys.path.insert(0, target_path)

from tooling.gpt_guardrails import (
    count_chat_tokens,
    estimate_chat_request_cost,
    actual_chat_request_cost,
    count_embedding_tokens,
    estimate_embedding_request_cost,
    actual_embedding_request_cost,
    get_usage_from_response,
)
```

The `sys.path` insertion is only there for the extension-template development layout (so `tooling.*` imports resolve). In a composed SDK, users should import from:

```python
from summoner.gpt_guardrails import ...
```

and no `sys.path` manipulation is needed.

## Chat example

This example shows a single-turn chat call with:

* prompt token ceiling
* estimated cost ceiling (optional)
* actual cost calculation from usage

```python
from typing import Any, Optional
from openai import AsyncOpenAI

client = AsyncOpenAI(api_key=os.environ["OPENAI_API_KEY"])

max_chat_input_tokens = 100
max_chat_output_tokens = 1000

async def guarded_chat(
    message: str,
    model_name: str,
    cost_limit: Optional[float] = None,
) -> dict[str, Any]:
    messages = [{"role": "user", "content": message}]

    prompt_tokens = count_chat_tokens(messages, model_name)
    est_cost = estimate_chat_request_cost(model_name, prompt_tokens, max_chat_output_tokens)

    if prompt_tokens >= max_chat_input_tokens:
        return {"output": None, "cost": None}

    if cost_limit is not None and est_cost > cost_limit:
        return {"output": None, "cost": None}

    response = await client.chat.completions.create(
        model=model_name,
        messages=messages,
        max_completion_tokens=max_chat_output_tokens,
    )

    usage = get_usage_from_response(response)
    act_cost = None
    if usage:
        act_cost = actual_chat_request_cost(model_name, usage.prompt_tokens, usage.completion_tokens)

    return {"output": response.choices[0].message.content, "cost": act_cost}
```

### Practical notes for chat budgeting

* `estimate_chat_request_cost` is conservative because it assumes the model uses the full `max_completion_tokens`.
* If you want a less conservative estimate, you can pass an “expected output tokens” number instead of your hard cap. The module does not enforce a specific policy here.

## Embeddings example

This example shows embeddings for a batch of texts with:

* total batch token ceiling
* cost ceiling (optional)
* actual cost calculation from usage

```python
from typing import Any, Optional
from openai import AsyncOpenAI

client = AsyncOpenAI(api_key=os.environ["OPENAI_API_KEY"])

max_embedding_input_tokens = 500

async def guarded_embeddings(
    texts: list[str],
    model_name: str = "text-embedding-3-small",
    cost_limit: Optional[float] = None,
) -> dict[str, Any]:
    input_tokens = count_embedding_tokens(texts, model_name)
    est_cost = estimate_embedding_request_cost(model_name, input_tokens)

    if input_tokens > max_embedding_input_tokens:
        return {"output": None, "cost": None}

    if cost_limit is not None and est_cost > cost_limit:
        return {"output": None, "cost": None}

    response = await client.embeddings.create(model=model_name, input=texts)

    usage = get_usage_from_response(response)
    act_cost = None
    if usage:
        act_cost = actual_embedding_request_cost(model_name, usage.total_tokens)

    return {"output": [r.embedding for r in response.data], "cost": act_cost}
```

### Practical notes for embeddings budgeting

* `count_embedding_tokens(texts, ...)` returns a **batch total**.
* If you want “per-text ceilings” or “auto-splitting into multiple requests”, implement that in your wrapper. The module does not split batches.

## Updating pricing tables

`gpt_guardrails/cost.py` includes two pricing tables:

* `PRICING` for chat models, expressed as USD per 1k prompt tokens and USD per 1k completion tokens
* `EMBEDDING_PRICING` for embedding models, expressed as USD per 1k tokens (input-only)

If you add or rename model IDs, you will typically need to add entries to these tables. The module fails fast with a `ValueError` when pricing is missing.

## Troubleshooting

* **`ValueError: No pricing info for model ...`**
  Your model ID is not present in `PRICING` (chat) or `EMBEDDING_PRICING` (embeddings). Add an entry or normalize your model name before calling the cost functions.

* **Token counts look wrong for a new model**
  If `tiktoken` does not recognize the model name, the code falls back to `cl100k_base`. Update `tiktoken` or use a model name that `tiktoken` maps correctly.

* **`usage` is `None`**
  Some responses do not expose usage in the SDK object you are using. In that case, you can still enforce pre-call ceilings, but you will not get an actual cost.

* **My embeddings request is blocked even though each string is short**
  The default guardrail checks the **sum** of tokens across the list. If you want a different policy, split the list into smaller batches.

## Imports in development and in the composed SDK

In the extension-template layout, tests often import:

```python
from tooling.gpt_guardrails import ...
```

and use a small `sys.path` insertion.

In a composed SDK, users should import:

```python
from summoner.gpt_guardrails import ...
```

No `sys.path` insertion is needed in that environment.

## OpenAI API

This module does not wrap the OpenAI SDK. It only helps you budget tokens and cost around OpenAI calls.

### Howtos

- OpenAI Python SDK: https://github.com/openai/openai-python
- API reference: https://platform.openai.com/docs/api-reference/introduction
- Quickstart: https://platform.openai.com/docs/quickstart

### API keys

Create and manage API keys in the OpenAI Platform settings. The API reference for key management lives here:
https://platform.openai.com/docs/api-reference/project-api-keys

> [!CAUTION]
> Do not commit API keys to source control.
> Prefer environment variables or a local `.env` file.

Minimal setup:

```bash
export OPENAI_API_KEY="..."
```

### Pricing

Official pricing changes over time. Treat the pricing tables in `gpt_guardrails/cost.py` as a local copy that must be updated when OpenAI prices change.

* Pricing overview: [https://openai.com/api/pricing/](https://openai.com/api/pricing/)
* Per-model pricing in the platform UI: [https://platform.openai.com/docs/models/compare](https://platform.openai.com/docs/models/compare)


