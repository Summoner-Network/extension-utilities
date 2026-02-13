import sys, os
target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
if target_path not in sys.path:
    sys.path.insert(0, target_path)

import asyncio
import pytest
from dotenv import load_dotenv

from tooling.curl_tools import CurlToolCompiler, SecretResolver, parse_curl_command

load_dotenv()

TWILIO_CURL = r"""
curl 'https://api.twilio.com/2010-04-01/Accounts/$TWILIO_ACCOUNT_SID/Messages.json' -X POST \
  --data-urlencode 'To=+18777804236' \
  -u $TWILIO_ACCOUNT_SID:$TWILIO_AUTH_TOKEN
"""


def test_sanity_twilio_parse_form_and_auth():
    spec = parse_curl_command(TWILIO_CURL)

    assert spec.method == "POST"
    assert spec.body_mode == "form"
    assert spec.auth is not None
    assert spec.auth.username == "{{env:TWILIO_ACCOUNT_SID}}"
    assert spec.auth.password == "{{env:TWILIO_AUTH_TOKEN}}"

    # Your parser currently returns --data-urlencode fields as list[tuple[str, str]]
    assert isinstance(spec.body, list)
    assert ("To", "+18777804236") in spec.body

    # Convenience view if you want dict-style access (safe when keys are unique)
    body_dict = dict(spec.body)
    assert body_dict["To"] == "+18777804236"


def test_sanity_userpass_split_happens_before_placeholder_conversion():
    spec = parse_curl_command(
        r"curl https://example.com -u $TWILIO_ACCOUNT_SID:$TWILIO_AUTH_TOKEN"
    )
    assert spec.auth is not None
    assert spec.auth.username == "{{env:TWILIO_ACCOUNT_SID}}"
    assert spec.auth.password == "{{env:TWILIO_AUTH_TOKEN}}"


def test_sanity_tool_call_returns_report_on_error():
    compiler = CurlToolCompiler(
        secrets=SecretResolver(mapping={"DUMMY": "x"}),
        auto_dotenv=False,
    )

    tool = compiler.request_schema(
        method="POST",
        url="http://127.0.0.1:1/this-will-fail",  # port 1 should fail quickly
        body_mode="form",
        # Use list-of-pairs to match your "form" representation robustly
        body=[("a", "1"), ("b", "2")],
    )

    report = asyncio.run(tool.call({}))

    assert report is not None
    assert report.status_code == 0
    assert report.ok is False
    assert report.response_text is not None
    assert "Request error" in report.response_text
