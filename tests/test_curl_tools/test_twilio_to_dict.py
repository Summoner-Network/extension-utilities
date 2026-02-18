import json
import os
import pytest
from dotenv import load_dotenv

load_dotenv()  # <-- ensure OPENAI_API_KEY is loaded from .env before skipif

TWILIO_DOCS = r"""
Twilio Messages API

Auth:
Basic Auth with Account SID + Auth Token.

Env:
TWILIO_ACCOUNT_SID=...
TWILIO_AUTH_TOKEN=...

Example: Create message (form)
POST https://api.twilio.com/2010-04-01/Accounts/{AccountSid}/Messages.json

curl --request POST \
  --url 'https://api.twilio.com/2010-04-01/Accounts/$TWILIO_ACCOUNT_SID/Messages.json' \
  --user '$TWILIO_ACCOUNT_SID:$TWILIO_AUTH_TOKEN' \
  --data-urlencode 'To=+15551234567' \
  --data-urlencode 'From=+15557654321' \
  --data-urlencode 'Body=Hello from Summoner'
"""


def _assert_json_roundtrip(d: dict) -> None:
    s = json.dumps(d, sort_keys=True)
    assert isinstance(s, str) and len(s) > 0


def _assert_has_env_placeholder(d: dict) -> None:
    blob = json.dumps(d)
    assert "{{env:" in blob


def test_twilio_to_dict_roundtrip_from_curl_parse(compiler):
    curl = r"""
    curl --request POST \
      --url 'https://api.twilio.com/2010-04-01/Accounts/$TWILIO_ACCOUNT_SID/Messages.json' \
      --user '$TWILIO_ACCOUNT_SID:$TWILIO_AUTH_TOKEN' \
      --data-urlencode 'To=+15551234567' \
      --data-urlencode 'From=+15557654321' \
      --data-urlencode 'Body=Hello from Summoner'
    """.strip()

    tool = compiler.parse(curl, description="Twilio: Create message (form)")
    d1 = tool.to_dict()

    _assert_json_roundtrip(d1)
    _assert_has_env_placeholder(d1)

    tool2 = compiler.request_schema_from_dict(d1)
    d2 = tool2.to_dict()

    assert d2 == d1

    # Extra sanity: ensure form body is preserved as list-of-tuples in the rehydrated spec
    assert tool2.spec.body_mode == "form"
    assert isinstance(tool2.spec.body, list)
    assert all(isinstance(x, tuple) and len(x) == 2 for x in tool2.spec.body)


pytestmark = pytest.mark.skipif(
    not os.getenv("OPENAI_API_KEY"),
    reason="OPENAI_API_KEY not set (skipping gpt_parse to_dict test)",
)


@pytest.mark.asyncio
async def test_twilio_to_dict_roundtrip_from_gpt_parse(compiler):
    tool = await compiler.gpt_parse(
        TWILIO_DOCS,
        model_name="gpt-4o-mini",
        cost_limit=0.02,
        debug=False,
    )
    d1 = tool.to_dict()

    _assert_json_roundtrip(d1)
    _assert_has_env_placeholder(d1)

    tool2 = compiler.request_schema_from_dict(d1)
    d2 = tool2.to_dict()

    assert d2 == d1
