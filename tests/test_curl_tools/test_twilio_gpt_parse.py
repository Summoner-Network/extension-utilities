import os
import asyncio
import pytest
from dotenv import load_dotenv

load_dotenv()  # <-- ensure OPENAI_API_KEY is loaded from .env before skipif

pytestmark = pytest.mark.skipif(
    not os.getenv("OPENAI_API_KEY"),
    reason="OPENAI_API_KEY not set (not found in env or .env)"
)

TWILIO_DOCS = r"""
Twilio setup:
- TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER in .env

Example request:
curl 'https://api.twilio.com/2010-04-01/Accounts/$TWILIO_ACCOUNT_SID/Messages.json' -X POST \
  --data-urlencode 'To=+18777804236' \
  --data-urlencode 'From=$TWILIO_FROM_NUMBER' \
  --data-urlencode 'Body=Hello' \
  -u $TWILIO_ACCOUNT_SID:$TWILIO_AUTH_TOKEN
"""

def test_twilio_gpt_parse_builds_tool(compiler):
    tool = asyncio.run(
        compiler.gpt_parse(
            TWILIO_DOCS,
            model_name="gpt-4o-mini",
            cost_limit=0.01,
            debug=False,
        )
    )

    assert tool.spec.method in ("POST", "GET")
    assert "twilio.com" in tool.spec.url
