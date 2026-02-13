import sys, os
target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
if target_path not in sys.path:
    sys.path.insert(0, target_path)

from tooling.curl_tools import parse_curl_command

TWILIO_CURL = r"""
curl 'https://api.twilio.com/2010-04-01/Accounts/$TWILIO_ACCOUNT_SID/Messages.json' -X POST \
  --data-urlencode 'To=+18777804236' \
  --data-urlencode 'From=$TWILIO_FROM_NUMBER' \
  --data-urlencode 'Body=Hello from curl_tool_compiler' \
  -u $TWILIO_ACCOUNT_SID:$TWILIO_AUTH_TOKEN
"""

def test_parse_twilio_curl_basic_auth_and_form():
    spec = parse_curl_command(TWILIO_CURL)

    assert spec.method == "POST"
    assert spec.url == "https://api.twilio.com/2010-04-01/Accounts/{{env:TWILIO_ACCOUNT_SID}}/Messages.json"

    # Twilio uses Basic Auth: username=Account SID, password=Auth Token
    assert spec.auth is not None
    assert spec.auth.username == "{{env:TWILIO_ACCOUNT_SID}}"
    assert spec.auth.password == "{{env:TWILIO_AUTH_TOKEN}}"

    # Twilio message creation uses form encoding
    assert spec.body_mode == "form"

    # Robust representation: list of (key, value) pairs (supports repeated keys)
    assert isinstance(spec.body, list)

    # Exact expected form fields
    assert ("To", "+18777804236") in spec.body
    assert ("From", "{{env:TWILIO_FROM_NUMBER}}") in spec.body
    assert ("Body", "Hello from curl_tool_compiler") in spec.body

    # Convenience view as dict (safe here because keys are unique)
    body_dict = dict(spec.body)
    assert body_dict["To"] == "+18777804236"
    assert body_dict["From"] == "{{env:TWILIO_FROM_NUMBER}}"
    assert body_dict["Body"] == "Hello from curl_tool_compiler"
