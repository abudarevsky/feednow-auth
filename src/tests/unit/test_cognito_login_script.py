"""Static secrecy checks for the local Cognito PKCE test harness (Phase 11 task 14)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[3] / "deploy/docker/cognito-login.sh"
SENSITIVE_VARIABLES = ("ACCESS_TOKEN", "CODE_VERIFIER", "STATE", "AUTH_CODE")
VARIABLE_REFERENCE = re.compile(r"\$\{?(?:" + "|".join(SENSITIVE_VARIABLES) + r")\}?")
OUTPUT_COMMAND = re.compile(r"\b(?:echo|printf|cat|tee)\b")
SHELL_REDIRECT = re.compile(r"(?<![<>=])>{1,2}\s*(?!&[12]\b|/dev/null\b)")


@pytest.fixture(scope="module")
def script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


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
    uses = [line.strip() for line in script.splitlines() if "${ACCESS_TOKEN}" in line]

    assert uses == ['curl -fsS "${API_URL}/v1/me" -H "Authorization: Bearer ${ACCESS_TOKEN}"']


def test_token_response_is_not_persisted(script: str) -> None:
    assert not re.search(r"(?m)^\s*tee\b", script)

    for line in script.splitlines():
        if "TOKEN_RESPONSE" not in line:
            continue
        assert not SHELL_REDIRECT.search(line), f"token response is redirected: {line}"
        assert not re.search(r"\btee\b", line), f"token response is piped to tee: {line}"
