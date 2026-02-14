import pytest


HUBSPOT_CURL_LIST_COMPANIES = r"""
curl --request GET \
  --url 'https://api.hubapi.com/crm/v3/objects/companies?limit=10' \
  --header 'Authorization: Bearer $HUBSPOT_ACCESS_TOKEN'
"""


def test_hubspot_parse_curl_companies_list(compiler):
    tool = compiler.parse(HUBSPOT_CURL_LIST_COMPANIES, description="HubSpot: list companies (curl parse)")

    assert tool.spec.method == "GET"
    assert tool.spec.url.startswith("https://api.hubapi.com/crm/v3/objects/companies")
    assert "limit=10" in tool.spec.url

    # Header should be templated from $HUBSPOT_ACCESS_TOKEN -> {{env:HUBSPOT_ACCESS_TOKEN}}
    assert "Authorization" in tool.spec.headers
    assert tool.spec.headers["Authorization"] == "Bearer {{env:HUBSPOT_ACCESS_TOKEN}}"
