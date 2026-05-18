from typing import Optional, Any
from dataclasses import dataclass
import re
import tiktoken

def count_chat_tokens(
    messages: list[dict[str, str]],
    model: str = "gpt-4o",
) -> int:
    """
    Returns the number of tokens that will be sent as 'prompt_tokens'
    for a chat.completions call with the given messages.
    """
    try:
        encoding = tiktoken.encoding_for_model(model)
    except KeyError:
        # Fallback if a brand-new model string is not yet mapped in tiktoken
        encoding = tiktoken.get_encoding("cl100k_base")

    # Overhead rules adapted from the OpenAI cookbook
    if model.startswith("gpt-3.5-turbo-0301"):
        tokens_per_message = 4
        tokens_per_name = -1
    elif model.startswith("gpt-3.5-turbo"):
        tokens_per_message = 4
        tokens_per_name = -1
    elif model.startswith("gpt-4"):
        tokens_per_message = 3
        tokens_per_name = 1
    else:
        # Default for newer families (4o, 5, etc.)
        tokens_per_message = 3
        tokens_per_name = 1

    total_tokens = 0
    for msg in messages:
        total_tokens += tokens_per_message
        for key, val in msg.items():
            # Encode each field value
            total_tokens += len(encoding.encode(val))
            if key == "name":
                total_tokens += tokens_per_name

    # Every reply is primed with this many tokens for the assistant role
    total_tokens += 3
    return total_tokens



# Per-1k token prices for standard processing: {"prompt": <USD>, "completion": <USD>}
PRICING: dict[str, dict[str, float]] = {
    # Current flagship / reasoning / specialized models
    "gpt-5.5":              {"prompt": 0.00500, "completion": 0.03000},
    "gpt-5.5-pro":          {"prompt": 0.03000, "completion": 0.18000},

    "gpt-5.4":              {"prompt": 0.00250, "completion": 0.01500},
    "gpt-5.4-mini":         {"prompt": 0.00075, "completion": 0.00450},
    "gpt-5.4-nano":         {"prompt": 0.00020, "completion": 0.00125},
    "gpt-5.4-pro":          {"prompt": 0.03000, "completion": 0.18000},

    "gpt-5.3-codex":        {"prompt": 0.00175, "completion": 0.01400},

    "chat-latest":          {"prompt": 0.00500, "completion": 0.03000},

    "gpt-4.1":              {"prompt": 0.00200, "completion": 0.00800},
    "gpt-4.1-mini":         {"prompt": 0.00040, "completion": 0.00160},
    "gpt-4.1-nano":         {"prompt": 0.00010, "completion": 0.00040},

    "gpt-4o":               {"prompt": 0.00250, "completion": 0.01000},
    "gpt-4o-mini":          {"prompt": 0.00015, "completion": 0.00060},

    "o3-pro":               {"prompt": 0.02000, "completion": 0.08000},
    "o3":                   {"prompt": 0.00200, "completion": 0.00800},
    "o3-deep-research":     {"prompt": 0.01000, "completion": 0.04000},
    
    "o4-mini":              {"prompt": 0.00110, "completion": 0.00440},
    "o4-mini-deep-research":{"prompt": 0.00200, "completion": 0.00800},

    # Older GPT-5 aliases still seen in configs / code paths
    "gpt-5":                {"prompt": 0.00125, "completion": 0.01000},
    "gpt-5-mini":           {"prompt": 0.00025, "completion": 0.00200},
    "gpt-5-nano":           {"prompt": 0.00005, "completion": 0.00040},

    # Historical / legacy
    "gpt-3.5-turbo":        {"prompt": 0.00050, "completion": 0.00150},
    "gpt-3.5-turbo-16k":    {"prompt": 0.00300, "completion": 0.00400},
}

_DATE_SUFFIX_RE = re.compile(r"-(?:20\d{2}-\d{2}-\d{2}|latest)$")
_GPT5_FAMILY_RE = re.compile(r"^(gpt-5)(?:\.\d+)*(?:-(mini|nano))?$")


def resolve_chat_pricing_model(model_name: str) -> Optional[str]:
    """
    Resolve a model name to the pricing table key used by this local guardrails module.

    This supports:
    - exact matches already present in PRICING
    - dated model IDs such as `gpt-4o-mini-2024-07-18`
    - versioned GPT-5 family names such as `gpt-5.4-mini`, which can fall
      back to the closest base-family entry when an exact row is unavailable
    """
    normalized = (model_name or "").strip()
    if not normalized:
        return None
    if normalized in PRICING:
        return normalized

    without_date_suffix = _DATE_SUFFIX_RE.sub("", normalized)
    if without_date_suffix in PRICING:
        return without_date_suffix

    family_match = _GPT5_FAMILY_RE.fullmatch(without_date_suffix)
    if family_match:
        size = family_match.group(2)
        if size == "mini":
            return "gpt-5-mini"
        if size == "nano":
            return "gpt-5-nano"
        return "gpt-5"

    return None


def estimate_chat_request_cost(
    model_name: str,
    prompt_tokens: int,
    max_completion_tokens: int
) -> float:
    """
    Return the *estimated* cost (USD) if the model were to
    use prompt_tokens and then produce max_completion_tokens.
    """
    resolved_model = resolve_chat_pricing_model(model_name)
    rates = PRICING.get(resolved_model) if resolved_model else None
    if not rates:
        raise ValueError(f"No pricing info for model '{model_name}'")
    return (
        (prompt_tokens / 1_000) * rates["prompt"]
        + (max_completion_tokens / 1_000) * rates["completion"]
    )


def actual_chat_request_cost(
    model_name: str,
    prompt_tokens: int,
    completion_tokens: int
) -> float:
    """
    Return the *actual* cost (USD) once you know how many
    completion_tokens were consumed.
    """
    resolved_model = resolve_chat_pricing_model(model_name)
    rates = PRICING.get(resolved_model) if resolved_model else None
    if not rates:
        raise ValueError(f"No pricing info for model '{model_name}'")
    return (
        (prompt_tokens / 1_000) * rates["prompt"]
        + (completion_tokens / 1_000) * rates["completion"]
    )


def safe_estimate_chat_request_cost(
    model_name: str,
    prompt_tokens: int,
    max_completion_tokens: int,
) -> Optional[float]:
    """
    Best-effort estimate that returns None instead of raising when pricing
    is unknown for the model.
    """
    try:
        return estimate_chat_request_cost(model_name, prompt_tokens, max_completion_tokens)
    except ValueError:
        return None


def safe_actual_chat_request_cost(
    model_name: str,
    prompt_tokens: int,
    completion_tokens: int,
) -> Optional[float]:
    """
    Best-effort actual cost that returns None instead of raising when pricing
    is unknown for the model.
    """
    try:
        return actual_chat_request_cost(model_name, prompt_tokens, completion_tokens)
    except ValueError:
        return None


# Needed for newer openai models (gpt-5 family)
def normalize_usage(usage_obj: Any) -> Optional[dict[str, int]]:
    """
    Normalize usage from OpenAI SDK responses into:
      {"prompt_tokens": int, "completion_tokens": int, "total_tokens": int}
    Works for both Chat Completions and Responses API, when usage is present.
    Returns None if usage isn't available.
    """
    if usage_obj is None:
        return None

    # Try common shapes
    to_dict = None
    for attr in ("to_dict", "model_dump", "dict"):
        fn = getattr(usage_obj, attr, None)
        if callable(fn):
            try:
                to_dict = fn()
                break
            except Exception:
                pass

    if to_dict is None:
        if isinstance(usage_obj, dict):
            to_dict = usage_obj
        else:
            try:
                to_dict = dict(usage_obj)  # last resort
            except Exception:
                return None

    d = to_dict or {}

    # Chat Completions style
    if "prompt_tokens" in d or "completion_tokens" in d:
        prompt = int(d.get("prompt_tokens", 0))
        comp = int(d.get("completion_tokens", 0))
        total = int(d.get("total_tokens", prompt + comp))
        return {"prompt_tokens": prompt, "completion_tokens": comp, "total_tokens": total}

    # Responses API often uses input/output wording
    if "input_tokens" in d or "output_tokens" in d:
        prompt = int(d.get("input_tokens", 0))
        comp = int(d.get("output_tokens", 0))
        total = int(d.get("total_tokens", prompt + comp))
        return {"prompt_tokens": prompt, "completion_tokens": comp, "total_tokens": total}

    # Unknown/unsupported shape
    return None


@dataclass(frozen=True)
class Usage:
    """Unified usage view for both Chat Completions and Responses API."""
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int

    def to_dict(self) -> dict[str, int]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
        }


def get_usage_from_response(response: Any) -> Optional[Usage]:
    """
    Attempt to extract a unified Usage object from an OpenAI response.
    Works for:
      - Chat Completions SDK objects (response.usage has prompt/completion/total)
      - Responses API SDK objects (usage may expose input/output/total)
      - Raw JSON dictionaries returned by direct HTTP calls
    Returns None if usage isn't available.
    """
    if isinstance(response, dict):
        usage_obj = response.get("usage")
    else:
        usage_obj = getattr(response, "usage", None)
    if usage_obj is None:
        return None

    # Reuse your existing normalizer
    norm = normalize_usage(usage_obj)
    if norm is None:
        return None

    prompt = int(norm.get("prompt_tokens", 0))
    comp = int(norm.get("completion_tokens", 0))
    total = int(norm.get("total_tokens", prompt + comp))
    return Usage(prompt_tokens=prompt, completion_tokens=comp, total_tokens=total)



# Per-1k token input price for embeddings (input-only billing).
EMBEDDING_PRICING: dict[str, float] = {
    "text-embedding-3-small":  0.00002,
    "text-embedding-3-large":  0.00013,
    "text-embedding-ada-002":  0.00010,
}

def count_embedding_tokens(
    texts: list[str],
    model_name: str = "text-embedding-ada-002",
) -> int:
    """
    Returns the total number of tokens for a list of input strings
    when sent to the embeddings endpoint for model_name.
    """
    try:
        enc = tiktoken.encoding_for_model(model_name)
    except KeyError:
        enc = tiktoken.get_encoding("cl100k_base")

    # sum token counts for each string
    return sum(len(enc.encode(text)) for text in texts)


def estimate_embedding_request_cost(
    model_name: str,
    input_tokens: int,
) -> float:
    """
    Estimate the USD cost if the call used exactly input_tokens
    (e.g. your max or expected length).
    """
    rate_per_1k = EMBEDDING_PRICING.get(model_name)
    if rate_per_1k is None:
        raise ValueError(f"No embedding pricing on record for '{model_name}'")
    return input_tokens / 1_000 * rate_per_1k


def actual_embedding_request_cost(
    model_name: str,
    input_tokens: int,
) -> float:
    """
    Compute the USD cost once you know how many tokens were used.
    (Identical to estimate, since embeddings only bill for input.)
    """
    return estimate_embedding_request_cost(model_name, input_tokens)
