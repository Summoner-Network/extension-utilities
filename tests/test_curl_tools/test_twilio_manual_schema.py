import pytest
from pydantic import BaseModel

import sys, os
target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
if target_path not in sys.path:
    sys.path.insert(0, target_path)

from tooling.curl_tools import BasicAuthSpec

class TwilioSendSMSInput(BaseModel):
    to: str
    body: str

def test_twilio_request_schema_by_hand(compiler):
    """
    This is the hand-written equivalent of the Twilio cURL:
      - URL contains the Account SID path segment
      - Basic Auth uses Account SID + Auth Token
      - Body is form-encoded: To, From, Body
    """

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
        description="Send an SMS via Twilio",
        input_model=TwilioSendSMSInput,
    )

    # This test does not call Twilio.
    # It ensures the tool is constructed and templates are well-formed.
    assert tool.spec.method == "POST"
    assert tool.spec.body_mode == "form"
    assert tool.spec.auth is not None
    assert tool.spec.body["To"] == "{{to}}"
