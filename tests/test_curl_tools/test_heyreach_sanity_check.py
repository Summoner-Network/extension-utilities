import sys, os
target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
if target_path not in sys.path:
    sys.path.insert(0, target_path)

from tooling.curl_tools import CurlToolCompiler, SecretResolver
from dotenv import load_dotenv
import pytest

load_dotenv() 


def test_sanity_tool_call_returns_report_on_error():
    compiler = CurlToolCompiler(secrets=SecretResolver(mapping={"DUMMY": "x"}), auto_dotenv=False)

    tool = compiler.request_schema(
        method="GET",
        url="http://127.0.0.1:1/this-will-fail",  # port 1 should fail quickly
        headers={"X-API-KEY": "{{env:DUMMY}}"},
        body_mode="raw",
        body=None,
    )

    # pytest-asyncio is installed, but keep this test sync to match your older style.
    import asyncio
    report = asyncio.run(tool.call({}))

    assert report is not None
    assert report.status_code == 0
    assert report.ok is False
    assert report.response_text is not None
    assert "Request error" in report.response_text
