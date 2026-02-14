import sys, os
target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
if target_path not in sys.path:
    sys.path.insert(0, target_path)

from tooling.curl_tools import parse_curl_command
from dotenv import load_dotenv
import pytest

load_dotenv() 


HEYREACH_CHECK_KEY_CURL = r"""
curl --location 'https://api.heyreach.io/api/public/auth/CheckApiKey' \
  --header 'X-API-KEY: $HEYREACH_API_KEY'
"""

HEYREACH_GET_ALL_CAMPAIGNS_CURL = r"""
curl --location 'https://api.heyreach.io/api/public/campaign/GetAll' \
  --header 'X-API-KEY: $HEYREACH_API_KEY' \
  --header 'Content-Type: application/json' \
  --header 'Accept: text/plain' \
  --data '{
    "offset": 0,
    "keyword": "",
    "statuses": [],
    "accountIds": [],
    "limit": 1
  }'
"""


def test_parse_heyreach_check_api_key():
    spec = parse_curl_command(HEYREACH_CHECK_KEY_CURL)
    assert spec.method == "GET"
    assert spec.url == "https://api.heyreach.io/api/public/auth/CheckApiKey"
    assert spec.headers["X-API-KEY"] == "{{env:HEYREACH_API_KEY}}"
    assert spec.body is None


def test_parse_heyreach_campaign_get_all_json_body():
    spec = parse_curl_command(HEYREACH_GET_ALL_CAMPAIGNS_CURL)
    assert spec.method == "POST"
    assert spec.url == "https://api.heyreach.io/api/public/campaign/GetAll"
    assert spec.headers["X-API-KEY"] == "{{env:HEYREACH_API_KEY}}"
    assert spec.headers["Content-Type"].lower() == "application/json"
    assert spec.body_mode == "json"
    assert isinstance(spec.body, dict)
    assert spec.body["offset"] == 0
    assert spec.body["limit"] == 1
