import os
import pytest
from dotenv import load_dotenv

import sys, os
target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
if target_path not in sys.path:
    sys.path.insert(0, target_path)

from tooling.curl_tools import CurlToolCompiler, SecretResolver

@pytest.fixture(scope="session")
def compiler() -> CurlToolCompiler:
    # Load .env once for all tests
    load_dotenv()

    # Secrets resolve via env by default
    secrets = SecretResolver(auto_dotenv=False)

    return CurlToolCompiler(
        secrets=secrets,
        auto_dotenv=False,
        max_chat_input_tokens=800,
        max_chat_output_tokens=1200,
        default_cost_limit=None,
    )

@pytest.fixture(scope="session")
def has_env() -> bool:
    # Used for optional integration test
    needed = ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM_NUMBER",
              "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
              "HEYREACH_API_KEY", "HUBSPOT_ACCESS_TOKEN"]
    return all(os.getenv(k) for k in needed)
