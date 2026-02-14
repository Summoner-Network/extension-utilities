def test_hubspot_manual_schema_companies_list(compiler):
    tool = compiler.request_schema(
        method="GET",
        url="https://api.hubapi.com/crm/v3/objects/companies",
        headers={
            "Authorization": "Bearer {{env:HUBSPOT_ACCESS_TOKEN}}",
            "Accept": "application/json",
        },
        params={
            "limit": "{{limit}}",
        },
        body_mode="raw",
        body=None,
        description="HubSpot: list companies (manual schema)",
    )

    assert tool.spec.method == "GET"
    assert tool.spec.url == "https://api.hubapi.com/crm/v3/objects/companies"
    assert tool.spec.params.get("limit") == "{{limit}}"
    assert tool.spec.headers.get("Authorization") == "Bearer {{env:HUBSPOT_ACCESS_TOKEN}}"
