import os
import asyncio
import pytest
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()  # <-- allow RUN_TWILIO_INTEGRATION and TWILIO_* vars to come from .env

import sys
import os as _os
target_path = _os.path.abspath(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "../.."))
if target_path not in sys.path:
    sys.path.insert(0, target_path)

from tooling.curl_tools import BasicAuthSpec

class TwilioSendSMSInput(BaseModel):
    to: str
    body: str

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_TWILIO_INTEGRATION") != "1",
    reason="Set RUN_TWILIO_INTEGRATION=1 (env or .env) to run live Twilio test"
)

def test_twilio_send_sms_live(compiler, has_twilio_env):
    if not has_twilio_env:
        pytest.skip("Missing TWILIO_ACCOUNT_SID/TWILIO_AUTH_TOKEN/TWILIO_FROM_NUMBER")

    to_number = os.getenv("TWILIO_TO_NUMBER")
    body = os.getenv("TWILIO_MESSAGE_BODY")
    if not to_number or not body:
        pytest.skip("Missing TWILIO_TO_NUMBER or TWILIO_MESSAGE_BODY")

    tool = compiler.request_schema(
        method="POST",
        url="https://api.twilio.com/2010-04-01/Accounts/{{env:TWILIO_ACCOUNT_SID}}/Messages.json",
        auth=BasicAuthSpec(
            username="{{env:TWILIO_ACCOUNT_SID}}",
            password="{{env:TWILIO_AUTH_TOKEN}}",
        ),
        body_mode="form",
        body={
            "To": "{{to}}",
            "From": "{{env:TWILIO_FROM_NUMBER}}",
            "Body": "{{body}}",
        },
        input_model=TwilioSendSMSInput,
        description="Send an SMS via Twilio (live integration test)",
    )

    report = asyncio.run(tool.call({"to": to_number, "body": body}))

    assert report.status_code in (200, 201)
    assert report.ok is True
    assert report.response_json is not None
    assert "sid" in report.response_json
