"""Focused offline checks for the local Cognito login launcher."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from urllib.parse import parse_qs, urlparse


REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "deploy" / "docker" / "cognito-login.sh"
COMPOSE_FILE = REPO_ROOT / "deploy" / "docker" / "docker-compose.yml"


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
