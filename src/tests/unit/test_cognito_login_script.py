"""Static secrecy checks for the local Cognito PKCE test harness (Phase 11 task 14)."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

SCRIPT = Path(__file__).resolve().parents[3] / "deploy/docker/cognito-login.sh"
COMPOSE_FILE = Path(__file__).resolve().parents[3] / "deploy/docker/docker-compose.yml"
SENSITIVE_VARIABLES = ("ACCESS_TOKEN", "CODE_VERIFIER", "STATE", "AUTH_CODE")
VARIABLE_REFERENCE = re.compile(r"\$\{?(?:" + "|".join(SENSITIVE_VARIABLES) + r")\}?")
OUTPUT_COMMAND = re.compile(r"\b(?:echo|printf|cat|tee)\b")
SHELL_REDIRECT = re.compile(r"(?<![<>=])>{1,2}\s*(?!&[12]\b|/dev/null\b)")


@pytest.fixture(scope="module")
def script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_google_provider_is_forwarded_to_the_authorize_url() -> None:
    """``--provider Google`` must not silently fall back to email/password."""
    environment = os.environ | {
        "FEEDNOW_LOGIN_ENV_FILE": "/dev/null",
        "FEEDNOW_COGNITO_CLIENT_ID": "local-client-id",
        "FEEDNOW_COGNITO_DOMAIN": "https://cognito.example.invalid",
    }
    result = subprocess.run(
        ["bash", str(SCRIPT), "--no-open", "--provider", "Google"],
        input="http://localhost:8000/oauth/callback?code=unused&state=wrong\n",
        text=True,
        capture_output=True,
        env=environment,
        check=False,
    )

    assert result.returncode != 0
    url = next(line for line in result.stderr.splitlines() if line.startswith("https://"))
    query = parse_qs(urlparse(url).query)
    assert query["identity_provider"] == ["Google"]
    assert query["response_type"] == ["code"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["state"]
    assert "unused" not in result.stderr


def test_local_compose_initializes_sqlite_volume_for_the_non_root_app() -> None:
    """The local named volume is writable when the app provisions its first user."""
    compose = COMPOSE_FILE.read_text(encoding="utf-8")

    assert "data-init:" in compose
    assert 'user: "0:0"' in compose
    assert "chown -R 1000:1000 /data" in compose
    assert "condition: service_completed_successfully" in compose


def test_sensitive_values_are_not_printed_or_written_as_output(script: str) -> None:
    """Only curl argument arrays may directly carry the sensitive values."""
    array = re.search(r"(?ms)^TOKEN_CURL_ARGS=\(\n.*?^\)", script)
    assert array is not None, "the token exchange must keep its arguments in the named array"
    outside_curl_arguments = script[: array.start()] + script[array.end() :]

    for line in outside_curl_arguments.splitlines():
        if not VARIABLE_REFERENCE.search(line):
            continue
        # The verifier is piped directly into the SHA-256 challenge derivation;
        # its raw bytes are not sent to the terminal or a file.
        if "CODE_VERIFIER" in line and OUTPUT_COMMAND.search(line):
            assert "| openssl dgst -sha256 -binary" in line
            assert not SHELL_REDIRECT.search(line), f"verifier is redirected: {line}"
            continue
        assert not OUTPUT_COMMAND.search(line), f"sensitive value reaches output command: {line}"
        assert not SHELL_REDIRECT.search(line), f"sensitive value is redirected: {line}"


def test_access_token_is_used_only_for_the_v1_me_response(script: str) -> None:
    uses = [line for line in script.splitlines() if "${ACCESS_TOKEN}" in line]
    assert len(uses) == 1
    assert '"${API_URL}/v1/me"' in script
    assert '"Authorization: Bearer ${ACCESS_TOKEN}"' in uses[0]
    assert "${ACCESS_TOKEN}" not in script.replace(uses[0], "")


def test_token_response_is_not_persisted(script: str) -> None:
    assert not re.search(r"(?m)^\s*tee\b", script)

    for line in script.splitlines():
        if "TOKEN_RESPONSE" not in line:
            continue
        assert not SHELL_REDIRECT.search(line), f"token response is redirected: {line}"
        assert not re.search(r"\btee\b", line), f"token response is piped to tee: {line}"
