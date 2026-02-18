import warnings
warnings.filterwarnings("ignore", message=r".*supports OpenSSL.*LibreSSL.*")

from urllib.parse import urlencode

import os
import re
import json
import shlex
import time
from dataclasses import dataclass, field
import dataclasses
from typing import Any, Optional, Type, Literal, Callable, Mapping, Union, Tuple, List, Dict

from urllib.parse import parse_qsl

import httpx

import openai
from openai import AsyncOpenAI
from dotenv import load_dotenv
from pprint import pprint

from pydantic import BaseModel, Field, ValidationError

# Your existing guardrail helpers
from tooling.gpt_guardrails import (
    count_chat_tokens,
    estimate_chat_request_cost,
    actual_chat_request_cost,
    get_usage_from_response,
)

HttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
BodyMode = Literal["json", "form", "raw"]

FormPairs = List[Tuple[str, str]]
FormBody = Union[dict[str, Any], FormPairs]

JsonObject = Dict[str, Any]
JsonArray = List[Any]
ToolBody = Union[str, JsonObject, JsonArray]



# ----------------------------
# Secrets + templating
# ----------------------------

class SecretResolver:
    """
    Flexible secret resolver.
    Resolution order:
      1) explicit mapping passed at init
      2) os.environ
      3) optional fallback callable
    """
    def __init__(
        self,
        mapping: Optional[Mapping[str, str]] = None,
        fallback: Optional[Callable[[str], Optional[str]]] = None,
        auto_dotenv: bool = False,
        dotenv_path: Optional[str] = None,
        dotenv_override: bool = False,
    ):
        if auto_dotenv:
            load_dotenv(dotenv_path=dotenv_path, override=dotenv_override)

        self._mapping = dict(mapping or {})
        self._fallback = fallback

    def get(self, name: str) -> Optional[str]:
        if name in self._mapping:
            return self._mapping[name]
        if name in os.environ:
            return os.environ[name]
        if self._fallback is not None:
            return self._fallback(name)
        return None

    def require(self, name: str) -> str:
        v = self.get(name)
        if v is None:
            raise KeyError(f"Missing required secret: {name}")
        return v


_ENV_PLACEHOLDER_RE = re.compile(r"\{\{\s*env\s*:\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")
_TEMPLATE_VAR_RE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")


def _render_template_str(
    s: str,
    *,
    inputs: Mapping[str, Any],
    secrets: SecretResolver,
) -> str:
    """
    Templating rules:
      - {{env:NAME}} is replaced via secrets
      - {{var}} is replaced via inputs
    """
    def env_sub(m: re.Match) -> str:
        key = m.group(1)
        return secrets.require(key)

    def var_sub(m: re.Match) -> str:
        key = m.group(1)
        if key not in inputs:
            raise KeyError(f"Missing required input variable: {key}")
        return str(inputs[key])

    s = _ENV_PLACEHOLDER_RE.sub(env_sub, s)
    s = _TEMPLATE_VAR_RE.sub(var_sub, s)
    return s


def _render_template_any(
    obj: Any,
    *,
    inputs: Mapping[str, Any],
    secrets: SecretResolver,
) -> Any:
    if isinstance(obj, str):
        return _render_template_str(obj, inputs=inputs, secrets=secrets)
    if isinstance(obj, list):
        return [_render_template_any(x, inputs=inputs, secrets=secrets) for x in obj]
    if isinstance(obj, dict):
        return {str(k): _render_template_any(v, inputs=inputs, secrets=secrets) for k, v in obj.items()}
    if isinstance(obj, tuple):
        return tuple(_render_template_any(x, inputs=inputs, secrets=secrets) for x in obj)
    return obj


def _normalize_headers(headers: Mapping[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in headers.items():
        if v is None:
            continue
        out[str(k)] = str(v)
    return out


def _normalize_params(params: Mapping[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in params.items():
        if v is None:
            continue
        out[str(k)] = str(v)
    return out


def _json_safe(x: Any) -> Any:
    """
    Convert arbitrary python objects into JSON-serializable structures.
    Keeps your {{env:...}} / {{var}} placeholders intact.
    """
    if x is None or isinstance(x, (str, int, float, bool)):
        return x

    # tuples are common for form bodies; JSON needs lists
    if isinstance(x, tuple):
        return [_json_safe(v) for v in x]

    if isinstance(x, list):
        return [_json_safe(v) for v in x]

    if isinstance(x, dict):
        return {str(k): _json_safe(v) for k, v in x.items()}

    # pydantic models (rare in bodies, but safe)
    if isinstance(x, BaseModel):
        return _json_safe(x.model_dump())

    # dataclasses (BasicAuthSpec, etc.)
    if dataclasses.is_dataclass(x):
        d = dataclasses.asdict(x)
        return _json_safe(d)

    # fallback: stringify
    return str(x)


def _rehydrate_form_body(body: Any) -> Any:
    """
    request_schema() / HttpTool.call() expects FORM bodies as:
      - dict, or
      - list[tuple[str,str]], or
      - raw string "a=1&b=2"
    If we loaded JSON, tuples became lists; fix that here.
    """
    if body is None:
        return None

    if isinstance(body, list):
        out: list[tuple[str, str]] = []
        for it in body:
            # stored as ["k","v"]
            if isinstance(it, list) and len(it) == 2:
                out.append((str(it[0]), str(it[1])))
                continue
            # allow {"key": "...", "value": "..."} as well
            if isinstance(it, dict) and "key" in it and "value" in it:
                out.append((str(it["key"]), str(it["value"])))
                continue
            # if it's already a tuple, keep it
            if isinstance(it, tuple) and len(it) == 2:
                out.append((str(it[0]), str(it[1])))
                continue
        return out

    return body


# ----------------------------
# Request spec + tool
# ----------------------------

@dataclass
class BasicAuthSpec:
    username: str
    password: str


@dataclass
class HttpRequestSpec:
    method: HttpMethod
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)
    body: Optional[Any] = None  # raw str | dict/list (json) | dict/pairs (form)

    body_mode: BodyMode = "json"
    auth: Optional[BasicAuthSpec] = None

    timeout_s: Optional[float] = 30.0
    follow_redirects: bool = False
    verify_tls: bool = True

    description: Optional[str] = None

    input_model: Optional[Type[BaseModel]] = None
    output_model: Optional[Type[BaseModel]] = None

    def to_request_schema_kwargs(self) -> dict[str, Any]:
        """
        Python-native kwargs for compiler.request_schema(**kwargs).
        Not necessarily JSON-serializable (e.g. tuples, BasicAuthSpec).
        """
        return {
            "method": self.method,
            "url": self.url,
            "headers": dict(self.headers or {}),
            "params": dict(self.params or {}),
            "body": self.body,
            "body_mode": self.body_mode,
            "auth": self.auth,
            "timeout_s": self.timeout_s,
            "follow_redirects": self.follow_redirects,
            "verify_tls": self.verify_tls,
            "description": self.description,
            "input_model": self.input_model,
            "output_model": self.output_model,
        }

    def to_dict(self, *, include_models: bool = False) -> dict[str, Any]:
        """
        JSON-safe dict you can persist and later rehydrate deterministically.
        Models are omitted by default because they are not robust to serialize.
        """
        d: dict[str, Any] = {
            "method": self.method,
            "url": self.url,
            "headers": _json_safe(self.headers or {}),
            "params": _json_safe(self.params or {}),
            "body": _json_safe(self.body),
            "body_mode": self.body_mode,
            "auth": _json_safe(self.auth) if self.auth is not None else None,
            "timeout_s": self.timeout_s,
            "follow_redirects": self.follow_redirects,
            "verify_tls": self.verify_tls,
            "description": self.description,
        }

        if include_models:
            # best-effort: store import path; you can extend rehydration if you want
            def _qualname(tp: Optional[Type[Any]]) -> Optional[str]:
                if tp is None:
                    return None
                return f"{tp.__module__}:{tp.__qualname__}"

            d["input_model"] = _qualname(self.input_model)
            d["output_model"] = _qualname(self.output_model)

        return d


@dataclass
class ToolCallReport:
    ok: bool
    status_code: int
    elapsed_ms: int
    request: dict[str, Any]
    response_text: Optional[str] = None
    response_json: Optional[Any] = None
    output_validation_ok: Optional[bool] = None
    output_validation_error: Optional[str] = None


class HttpTool:
    """
    Callable tool generated from:
      - deterministic cURL parsing,
      - GPT-based parse,
      - explicit schema.

    Templating:
      - {{env:NAME}} resolved by SecretResolver
      - {{var}} resolved by inputs passed to call()
    """
    def __init__(self, spec: HttpRequestSpec, secrets: Optional[SecretResolver] = None):
        self.spec = spec
        self.secrets = secrets or SecretResolver()

    def to_dict(self, *, include_models: bool = False) -> dict[str, Any]:
        """
        Persistable snapshot of the tool spec (JSON-safe).
        """
        return self.spec.to_dict(include_models=include_models)

    async def call(self, inputs: Optional[dict[str, Any]] = None) -> ToolCallReport:
        inputs = dict(inputs or {})

        # Input validation
        if self.spec.input_model is not None:
            inputs = self.spec.input_model.model_validate(inputs).model_dump()

        # Render templates
        url = _render_template_str(self.spec.url, inputs=inputs, secrets=self.secrets)
        headers_any = _render_template_any(self.spec.headers, inputs=inputs, secrets=self.secrets)
        params_any = _render_template_any(self.spec.params, inputs=inputs, secrets=self.secrets)
        body_any = _render_template_any(self.spec.body, inputs=inputs, secrets=self.secrets)

        headers = _normalize_headers(headers_any if isinstance(headers_any, dict) else {})
        params = _normalize_params(params_any if isinstance(params_any, dict) else {})

        # Auth
        auth: Optional[Tuple[str, str]] = None
        if self.spec.auth is not None:
            user = _render_template_str(self.spec.auth.username, inputs=inputs, secrets=self.secrets)
            pw = _render_template_str(self.spec.auth.password, inputs=inputs, secrets=self.secrets)
            auth = (user, pw)

        # Default Content-Type if caller didn't specify
        if self.spec.body_mode == "json":
            headers.setdefault("Content-Type", "application/json")
        elif self.spec.body_mode == "form":
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

        req_summary = {
            "method": self.spec.method,
            "url": url,
            "headers": headers,
            "params": params,
            "has_body": body_any is not None,
            "body_mode": self.spec.body_mode,
            "has_auth": self.spec.auth is not None,
        }

        t0 = time.time()
        async with httpx.AsyncClient(
            follow_redirects=self.spec.follow_redirects,
            verify=self.spec.verify_tls,
        ) as client:
            try:
                kwargs: dict[str, Any] = dict(
                    method=self.spec.method,
                    url=url,
                    headers=headers or None,
                    params=params or None,
                    timeout=self.spec.timeout_s,
                    auth=auth,
                )

                if body_any is not None:
                    # JSON mode
                    if self.spec.body_mode == "json":
                        if isinstance(body_any, (dict, list)):
                            kwargs["json"] = body_any
                        elif isinstance(body_any, str):
                            # Allow raw JSON string if user passes it
                            kwargs["content"] = body_any
                        else:
                            kwargs["content"] = str(body_any)

                    # FORM mode
                    elif self.spec.body_mode == "form":
                        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

                        if isinstance(body_any, dict):
                            pairs = [(str(k), str(v)) for k, v in body_any.items()]
                            kwargs["content"] = urlencode(pairs)

                        elif (
                            isinstance(body_any, list)
                            and all(isinstance(x, tuple) and len(x) == 2 for x in body_any)
                        ):
                            pairs = [(str(k), str(v)) for (k, v) in body_any]
                            kwargs["content"] = urlencode(pairs)

                        elif isinstance(body_any, str):
                            # raw "a=1&b=2"
                            kwargs["content"] = body_any

                        else:
                            raise ValueError("form body_mode requires dict, list[tuple[str,str]], or str body.")

                    # RAW mode
                    else:
                        if isinstance(body_any, (dict, list)):
                            kwargs["content"] = json.dumps(body_any)
                        else:
                            kwargs["content"] = str(body_any)

                resp = await client.request(**kwargs)

            except Exception as e:
                elapsed_ms = int((time.time() - t0) * 1000)
                return ToolCallReport(
                    ok=False,
                    status_code=0,
                    elapsed_ms=elapsed_ms,
                    request=req_summary,
                    response_text=f"Request error: {type(e).__name__}: {e}",
                )

        elapsed_ms = int((time.time() - t0) * 1000)

        # Best-effort response parsing
        response_text: Optional[str] = None
        response_json: Optional[Any] = None

        ct = resp.headers.get("content-type", "")
        if "application/json" in ct.lower():
            try:
                response_json = resp.json()
            except Exception:
                response_text = resp.text
        else:
            response_text = resp.text

        # Output validation (only meaningful when JSON is parsed)
        output_validation_ok: Optional[bool] = None
        output_validation_error: Optional[str] = None

        if self.spec.output_model is not None:
            if response_json is None:
                output_validation_ok = False
                output_validation_error = "Output model provided but response was not valid JSON."
            else:
                try:
                    self.spec.output_model.model_validate(response_json)
                    output_validation_ok = True
                except ValidationError as ve:
                    output_validation_ok = False
                    output_validation_error = str(ve)

        return ToolCallReport(
            ok=resp.is_success,
            status_code=resp.status_code,
            elapsed_ms=elapsed_ms,
            request=req_summary,
            response_text=response_text,
            response_json=response_json,
            output_validation_ok=output_validation_ok,
            output_validation_error=output_validation_error,
        )


# ----------------------------
# Deterministic cURL parsing
# ----------------------------

_DOLLAR_ENV_RE = re.compile(r"(?<!\\)\$(\{)?([A-Za-z_][A-Za-z0-9_]*)\}?")

def _convert_shell_env_to_placeholder(s: str) -> str:
    """
    Converts $VARNAME or ${VARNAME} to {{env:VARNAME}}.
    Leaves escaped dollars intact: "\\$FOO" stays "$FOO".
    """
    sentinel = "__CURLTOOLS_ESCAPED_DOLLAR__"
    s = s.replace("\\$", sentinel)

    def sub(m: re.Match) -> str:
        name = m.group(2)
        return f"{{{{env:{name}}}}}"

    s = _DOLLAR_ENV_RE.sub(sub, s)
    s = s.replace(sentinel, "$")
    return s


def _parse_header_kv(h: str) -> tuple[str, str]:
    # Header format: "Key: Value"
    if ":" not in h:
        return h.strip(), ""
    k, v = h.split(":", 1)
    return k.strip(), v.strip()


def _parse_query_like_payload(payload: str) -> dict[str, str]:
    """
    Parse "a=1&b=2" into dict[str,str] (last wins).
    This is used only for the -G/--get + -d pattern.
    """
    pairs = parse_qsl(payload, keep_blank_values=True)
    out: dict[str, str] = {}
    for k, v in pairs:
        out[str(k)] = str(v)
    return out


def parse_curl_command(curl_text: str) -> HttpRequestSpec:
    """
    Parse a practical subset of curl into HttpRequestSpec.

    Supported:
      - URL: positional https://... or --url <url>
      - Method: -X/--request <METHOD>, -G/--get (forces GET)
      - Headers: -H/--header "Key: Value"
      - Body:
          - -d/--data/--data-raw/--data-binary/--data-ascii <payload>
          - --data-urlencode "k=v" (collects as list[(k,v)] and sets body_mode="form")
      - Auth:
          - -u/--user "user:pass" (Basic Auth). Split occurs before placeholder conversion.
      - Redirects: -L/--location
      - TLS verify: -k/--insecure (disables TLS verification)
      - Timeouts: --connect-timeout <seconds>, -m/--max-time <seconds>

    Notes:
      - --data-urlencode produces body_mode="form" and body as list[tuple[str,str]] (duplicates allowed).
      - If -G/--get is set and -d is present, -d is treated as query params (best-effort).
      - -d payloads are heuristically parsed as JSON if they look like JSON or Content-Type is JSON.
    """
    tokens = shlex.split(curl_text, posix=True)
    if not tokens:
        raise ValueError("Empty curl command.")

    if tokens[0] == "curl":
        tokens = tokens[1:]
    if not tokens:
        raise ValueError("curl command contains no arguments.")

    method: Optional[str] = None
    headers: dict[str, str] = {}
    data_parts: list[str] = []
    url: Optional[str] = None
    follow_redirects = False
    verify_tls = True
    timeout_s: Optional[float] = 30.0
    force_get = False

    auth: Optional[BasicAuthSpec] = None
    form_fields: list[tuple[str, str]] = []
    used_data_urlencode = False

    i = 0
    while i < len(tokens):
        t = tokens[i]

        if t in ("-X", "--request"):
            i += 1
            if i >= len(tokens):
                raise ValueError("curl: missing argument for -X/--request")
            method = tokens[i].upper()

        elif t in ("-H", "--header"):
            i += 1
            if i >= len(tokens):
                raise ValueError("curl: missing argument for -H/--header")
            k, v = _parse_header_kv(tokens[i])
            headers[k] = _convert_shell_env_to_placeholder(v)

        elif t in ("-d", "--data", "--data-raw", "--data-binary", "--data-ascii"):
            i += 1
            if i >= len(tokens):
                raise ValueError("curl: missing argument for -d/--data*")
            data_parts.append(_convert_shell_env_to_placeholder(tokens[i]))

        elif t in ("-G", "--get"):
            force_get = True

        elif t in ("-L", "--location"):
            follow_redirects = True

        elif t in ("-k", "--insecure"):
            verify_tls = False

        elif t == "--url":
            i += 1
            if i >= len(tokens):
                raise ValueError("curl: missing argument for --url")
            url = _convert_shell_env_to_placeholder(tokens[i])

        elif t in ("--connect-timeout",):
            i += 1
            if i >= len(tokens):
                raise ValueError("curl: missing argument for --connect-timeout")
            timeout_s = float(tokens[i])

        elif t in ("-m", "--max-time"):
            i += 1
            if i >= len(tokens):
                raise ValueError("curl: missing argument for -m/--max-time")
            timeout_s = float(tokens[i])

        elif t in ("-u", "--user"):
            i += 1
            if i >= len(tokens):
                raise ValueError("curl: missing argument for -u/--user")

            raw_userpass = tokens[i]  # split before placeholder conversion
            if ":" not in raw_userpass:
                raise ValueError("curl: -u expects user:pass")

            user_raw, pw_raw = raw_userpass.split(":", 1)
            user = _convert_shell_env_to_placeholder(user_raw)
            pw = _convert_shell_env_to_placeholder(pw_raw)
            auth = BasicAuthSpec(username=user, password=pw)

        elif t == "--data-urlencode":
            i += 1
            if i >= len(tokens):
                raise ValueError("curl: missing argument for --data-urlencode")
            used_data_urlencode = True
            kv = _convert_shell_env_to_placeholder(tokens[i])
            if "=" in kv:
                k, v = kv.split("=", 1)
            else:
                k, v = kv, ""
            form_fields.append((k, v))

        elif t.startswith("http://") or t.startswith("https://"):
            url = _convert_shell_env_to_placeholder(t)

        else:
            # Ignore other flags for now
            pass

        i += 1

    if url is None:
        raise ValueError("curl: no URL found")

    # Infer method
    if force_get:
        inferred_method: str = "GET"
    elif method is not None:
        inferred_method = method
    elif data_parts or used_data_urlencode:
        inferred_method = "POST"
    else:
        inferred_method = "GET"

    allowed = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
    if inferred_method not in allowed:
        raise ValueError(f"Unsupported or unrecognized HTTP method: {inferred_method}")

    # Build body/params
    body: Optional[Any] = None
    body_mode: BodyMode = "json"
    params: dict[str, str] = {}

    if used_data_urlencode:
        body = form_fields
        body_mode = "form"

    elif data_parts:
        raw = "&".join(data_parts)

        # -G/--get + -d : treat as query params
        if force_get:
            params = _parse_query_like_payload(raw)
            body = None
            body_mode = "raw"

        else:
            ctype = headers.get("Content-Type") or headers.get("content-type") or ""
            ctype_lower = ctype.lower()

            # Explicit JSON content-type
            if "application/json" in ctype_lower:
                try:
                    body = json.loads(raw)
                    body_mode = "json"
                except Exception:
                    body = raw
                    body_mode = "raw"

            # Explicit urlencoded form content-type
            elif "application/x-www-form-urlencoded" in ctype_lower:
                pairs = [(str(k), str(v)) for (k, v) in parse_qsl(raw, keep_blank_values=True)]
                if pairs:
                    body = pairs
                    body_mode = "form"
                else:
                    body = raw
                    body_mode = "raw"

            else:
                stripped = raw.strip()

                # JSON-looking payload
                if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
                    try:
                        body = json.loads(raw)
                        body_mode = "json"
                    except Exception:
                        body = raw
                        body_mode = "raw"

                # Heuristic: k=v style payloads are usually form-encoded
                elif "=" in raw:
                    pairs = [(str(k), str(v)) for (k, v) in parse_qsl(raw, keep_blank_values=True)]
                    if pairs:
                        body = pairs
                        body_mode = "form"
                    else:
                        body = raw
                        body_mode = "raw"

                else:
                    body = raw
                    body_mode = "raw"

    return HttpRequestSpec(
        method=inferred_method,  # type: ignore[arg-type]
        url=url,
        headers=headers,
        params=params,
        body=body,
        body_mode=body_mode,
        auth=auth,
        timeout_s=timeout_s,
        follow_redirects=follow_redirects,
        verify_tls=verify_tls,
    )


# ----------------------------
# GPT parse (docs -> blueprint -> tool)
# ----------------------------

# ----------------------------
# GPT parse (docs -> blueprint -> tool)
# ----------------------------

class KVPair(BaseModel):
    key: str
    value: str

    # Important for OpenAI strict JSON schema:
    # disallow unknown keys -> additionalProperties: false
    model_config = {"extra": "forbid"}


class CurlToolBlueprint(BaseModel):
    """
    NOTE: This schema MUST remain "closed" for OpenAI structured outputs.
    Avoid dict[str, ...] and Any, because they produce JSON schemas with
    additionalProperties != false (rejected by the API).
    """
    model_config = {"extra": "forbid"}

    name: str = Field(..., description="Short tool name.")
    description: str = Field(..., description="User-facing description of what the tool does.")
    method: HttpMethod
    url: str

    # Use KV pairs instead of dicts (required by strict schema rules)
    headers: list[KVPair] = Field(default_factory=list)
    params: list[KVPair] = Field(default_factory=list)

    body_mode: BodyMode = "json"

    # Body representation:
    # - for json/raw: provide body_text (string). If json, we'll try json.loads.
    # - for form: prefer form_fields (list of KVPair). body_text may be used as raw "a=1&b=2".
    body_text: Optional[str] = None
    form_fields: list[KVPair] = Field(default_factory=list)

    # Basic Auth (optional)
    basic_auth_username: Optional[str] = None
    basic_auth_password: Optional[str] = None

    follow_redirects: bool = False
    verify_tls: bool = True
    timeout_s: Optional[float] = 30.0

    required_env: list[str] = Field(default_factory=list)
    templating_notes: Optional[str] = None


def _redact_probable_secrets(text: str) -> str:
    """
    Best-effort redaction to reduce risk of sending live secrets to GPT.
    Users should still avoid pasting real tokens when possible.
    """
    # Authorization: Bearer <token>
    text = re.sub(
        r"(Authorization:\s*Bearer)\s+([A-Za-z0-9\-\._~\+/]+=*)",
        r"\1 {{env:API_TOKEN}}",
        text,
        flags=re.IGNORECASE,
    )
    # Basic "api_key=..." patterns
    text = re.sub(
        r"(\bapi[_-]?key\b\s*[:=]\s*)([A-Za-z0-9\-\._~\+/]+=*)",
        r"\1{{env:API_KEY}}",
        text,
        flags=re.IGNORECASE,
    )
    return text


class CurlToolCompiler:
    """
    Main entrypoint.

    - parse(curl_text): deterministic parsing
    - gpt_parse(docs): GPT-assisted extraction of a tool blueprint, guarded by token/cost ceilings
    - request_schema(...): direct spec construction
    """

    def __init__(
        self,
        *,
        secrets: Optional[SecretResolver] = None,
        openai_api_key: Optional[str] = None,
        auto_dotenv: bool = True,
        dotenv_path: Optional[str] = None,
        dotenv_override: bool = False,
        max_chat_input_tokens: int = 600,
        max_chat_output_tokens: int = 1200,
        default_cost_limit: Optional[float] = None,
        validate_model_name: bool = True,
    ):
        if auto_dotenv:
            load_dotenv(dotenv_path=dotenv_path, override=dotenv_override)

        self.secrets = secrets or SecretResolver(auto_dotenv=False)

        self._openai_client: Optional[AsyncOpenAI]
        self._model_ids: list[str]

        api_key = openai_api_key or os.getenv("OPENAI_API_KEY")
        if not api_key:
            self._openai_client = None
            self._model_ids = []
        else:
            self._openai_client = AsyncOpenAI(api_key=api_key)
            self._model_ids = []
            if validate_model_name:
                try:
                    self._model_ids = [m.id for m in openai.models.list().data]
                except Exception:
                    # Fail-open: do not block gpt_parse if model listing fails
                    self._model_ids = []

        self.max_chat_input_tokens = max_chat_input_tokens
        self.max_chat_output_tokens = max_chat_output_tokens
        self.default_cost_limit = default_cost_limit
        self.validate_model_name = validate_model_name

    def set_budget(
        self,
        *,
        max_chat_input_tokens: Optional[int] = None,
        max_chat_output_tokens: Optional[int] = None,
        default_cost_limit: Optional[float] = None,
    ) -> None:
        if max_chat_input_tokens is not None:
            self.max_chat_input_tokens = max_chat_input_tokens
        if max_chat_output_tokens is not None:
            self.max_chat_output_tokens = max_chat_output_tokens
        if default_cost_limit is not None:
            self.default_cost_limit = default_cost_limit

    def parse(
        self,
        curl_text: str,
        *,
        description: Optional[str] = None,
        input_model: Optional[Type[BaseModel]] = None,
        output_model: Optional[Type[BaseModel]] = None,
    ) -> HttpTool:
        spec = parse_curl_command(curl_text)
        spec.description = description
        spec.input_model = input_model
        spec.output_model = output_model
        return HttpTool(spec, secrets=self.secrets)

    def request_schema(
        self,
        *,
        method: HttpMethod,
        url: str,
        headers: Optional[dict[str, str]] = None,
        params: Optional[dict[str, str]] = None,
        body: Optional[Any] = None,
        body_mode: BodyMode = "json",
        auth: Optional[BasicAuthSpec] = None,
        timeout_s: Optional[float] = 30.0,
        follow_redirects: bool = False,
        verify_tls: bool = True,
        description: Optional[str] = None,
        input_model: Optional[Type[BaseModel]] = None,
        output_model: Optional[Type[BaseModel]] = None,
    ) -> HttpTool:
        spec = HttpRequestSpec(
            method=method,
            url=url,
            headers=headers or {},
            params=params or {},
            body=body,
            body_mode=body_mode,
            auth=auth,
            timeout_s=timeout_s,
            follow_redirects=follow_redirects,
            verify_tls=verify_tls,
            description=description,
            input_model=input_model,
            output_model=output_model,
        )
        return HttpTool(spec, secrets=self.secrets)

    def request_schema_from_dict(self, d: Mapping[str, Any]) -> HttpTool:
        """
        Deterministically rehydrate a tool spec produced by HttpTool.to_dict().
        """
        dd = dict(d)

        auth = dd.get("auth")
        auth_spec: Optional[BasicAuthSpec] = None
        if isinstance(auth, dict) and auth.get("username") is not None and auth.get("password") is not None:
            auth_spec = BasicAuthSpec(username=str(auth["username"]), password=str(auth["password"]))

        body_mode = dd.get("body_mode", "json")
        body = dd.get("body", None)
        if body_mode == "form":
            body = _rehydrate_form_body(body)

        return self.request_schema(
            method=dd["method"],
            url=dd["url"],
            headers=dd.get("headers") or {},
            params=dd.get("params") or {},
            body=body,
            body_mode=body_mode,
            auth=auth_spec,
            timeout_s=dd.get("timeout_s", 30.0),
            follow_redirects=bool(dd.get("follow_redirects", False)),
            verify_tls=bool(dd.get("verify_tls", True)),
            description=dd.get("description"),
        )

    async def gpt_parse(
        self,
        docs: str,
        *,
        model_name: str = "gpt-4o-mini",
        cost_limit: Optional[float] = None,
        debug: bool = False,
    ) -> HttpTool:
        if self._openai_client is None:
            raise RuntimeError("OPENAI_API_KEY not configured, cannot use gpt_parse().")

        if self.validate_model_name and self._model_ids:
            if model_name not in self._model_ids:
                raise ValueError(
                    f"Invalid model_name '{model_name}'. "
                    f"Available models are: {', '.join(self._model_ids)}"
                )

        safe_docs = _redact_probable_secrets(docs)
        prompt = self._build_gpt_prompt(safe_docs)

        messages: list[dict[str, str]] = [{"role": "user", "content": prompt}]
        prompt_tokens = count_chat_tokens(messages, model_name)

        if debug:
            print(
                f"\033[96mPrompt tokens: {prompt_tokens} > {self.max_chat_input_tokens}? "
                f"{prompt_tokens > self.max_chat_input_tokens}\033[0m"
            )

        est_cost = estimate_chat_request_cost(model_name, prompt_tokens, self.max_chat_output_tokens)
        if debug:
            print(
                f"\033[95m[gpt_parse] Estimated cost (for {self.max_chat_output_tokens} output tokens): "
                f"${est_cost:.6f}\033[0m"
            )

        if prompt_tokens >= self.max_chat_input_tokens:
            raise ValueError("gpt_parse: prompt token ceiling exceeded")

        effective_cost_limit = cost_limit if cost_limit is not None else self.default_cost_limit
        if effective_cost_limit is not None and est_cost > effective_cost_limit:
            raise ValueError("gpt_parse: estimated cost exceeds limit")

        response = await self._openai_client.responses.parse(
            input=messages,
            model=model_name,
            max_output_tokens=self.max_chat_output_tokens,
            text_format=CurlToolBlueprint,
        )

        usage = get_usage_from_response(response)
        if usage and debug:
            pprint(usage.to_dict())
            act_cost = actual_chat_request_cost(model_name, usage.prompt_tokens, usage.completion_tokens)
            print(f"\033[95m[gpt_parse] Actual cost: ${act_cost:.6f}\033[0m")

        blueprint: CurlToolBlueprint = response.output[0].content[0].parsed

        # Convert KV lists to dicts (last wins)
        headers_dict: dict[str, str] = {}
        for kv in blueprint.headers:
            headers_dict[kv.key] = kv.value

        params_dict: dict[str, str] = {}
        for kv in blueprint.params:
            params_dict[kv.key] = kv.value

        # Auth
        auth_spec: Optional[BasicAuthSpec] = None
        if blueprint.basic_auth_username and blueprint.basic_auth_password:
            auth_spec = BasicAuthSpec(
                username=blueprint.basic_auth_username,
                password=blueprint.basic_auth_password,
            )

        # Body
        body: Optional[Any] = None
        if blueprint.body_mode == "form":
            if blueprint.form_fields:
                body = [(kv.key, kv.value) for kv in blueprint.form_fields]
            elif blueprint.body_text:
                # raw "a=1&b=2" form string
                body = blueprint.body_text
            else:
                body = None

        elif blueprint.body_mode == "json":
            if blueprint.body_text is not None:
                # try parse JSON, else keep as raw string
                try:
                    body = json.loads(blueprint.body_text)
                except Exception:
                    body = blueprint.body_text
            else:
                body = None

        else:  # raw
            body = blueprint.body_text

        spec = HttpRequestSpec(
            method=blueprint.method,
            url=blueprint.url,
            headers=headers_dict,
            params=params_dict,
            body=body,
            body_mode=blueprint.body_mode,
            auth=auth_spec,
            timeout_s=blueprint.timeout_s,
            follow_redirects=blueprint.follow_redirects,
            verify_tls=blueprint.verify_tls,
            description=blueprint.description,
        )

        return HttpTool(spec, secrets=self.secrets)

    def _build_gpt_prompt(self, docs: str) -> str:
        return (
            "You are converting API documentation and/or a cURL snippet into a callable HTTP tool.\n"
            "Output a structured object that matches the CurlToolBlueprint schema.\n\n"
            "Hard constraints:\n"
            "1) Never include real secrets. Always use placeholders like {{env:NAME}}.\n"
            "2) If the docs show '$TOKEN' or '${TOKEN}', preserve it as {{env:TOKEN}}.\n"
            "3) Do not guess endpoints, headers, or parameters that are not present.\n"
            "4) Prefer minimal correct output over speculative completeness.\n\n"
            "Templating rules:\n"
            "- Secrets: {{env:NAME}}\n"
            "- Runtime inputs: {{var}}\n\n"
            "Headers and params:\n"
            "- Put headers into headers=[{key,value}, ...]\n"
            "- Put query parameters into params=[{key,value}, ...]\n\n"
            "Auth:\n"
            "- If Basic Auth is used (curl -u user:pass), set basic_auth_username and basic_auth_password.\n\n"
            "Body encoding:\n"
            "- If the request is application/x-www-form-urlencoded or uses --data-urlencode:\n"
            "  - set body_mode='form'\n"
            "  - fill form_fields=[{key,value}, ...]\n"
            "  - use body_text only if the docs give a raw 'a=1&b=2' string\n"
            "- If the request body is JSON:\n"
            "  - set body_mode='json'\n"
            "  - put the JSON as a string in body_text (we will parse it)\n"
            "- If the request body is raw text:\n"
            "  - set body_mode='raw'\n"
            "  - put the raw payload in body_text\n\n"
            "Docs:\n"
            f"{docs}\n"
        )

