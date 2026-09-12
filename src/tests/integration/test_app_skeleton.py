"""Integration tests for the Phase 01 task-6 app skeleton.

Covers the task's verify lines:

1. ``TestClient`` GET ``/health`` with the four AWS credential/config
   variables removed from the environment (no AWS, no DB to boot).
2. Subprocess-isolated ``boto3``-free import of ``app.main`` — a fresh
   interpreter, so test order can never skew the result (planner decision;
   an in-process ``sys.modules`` assertion would false-fail in Phase 06).
3. Validation-error envelope shape asserted field-for-field, plus the
   HTTPException/unhandled-exception mappings from ``app.api.errors``.
4. The ``create_app`` router extension point works and Phase 01 mounts no
   §14 routers.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi import APIRouter, HTTPException
from fastapi.testclient import TestClient
from pydantic import Field

from app.api.schemas.common import ApiSchema
from app.api.schemas.manifest import ENDPOINTS
from app.main import app, create_app

#: The four AWS identity/config variables that must be absent for the
#: no-AWS boot proof (task 6 verify line).
AWS_ENV_VARS = (
    "AWS_PROFILE",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
)

#: Repository root, so the subprocess check imports the same ``app`` package.
REPO_ROOT = Path(__file__).resolve().parents[3]
SRC_ROOT = REPO_ROOT / "src"


@pytest.fixture
def aws_free_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every AWS credential/config variable from the test environment."""
    for name in AWS_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


class _EchoPayload(ApiSchema):
    """Throwaway request schema used to trigger RequestValidationError."""

    name: str = Field(min_length=1)
    count: int


_test_router = APIRouter()


@_test_router.post("/_test/echo", status_code=201)
async def _echo(payload: _EchoPayload) -> _EchoPayload:
    return payload


@_test_router.get("/_test/forbidden")
async def _forbidden() -> None:
    raise HTTPException(status_code=403, detail="Missing required scope: org:members:read")


@_test_router.get("/_test/boom")
async def _boom() -> None:
    raise RuntimeError("connection string leaked: password=hunter2")


# ---------------------------------------------------------------------------
# 1. Health boots with no AWS configuration and no database
# ---------------------------------------------------------------------------


def test_health_returns_200_json_without_aws_environment(aws_free_env: None) -> None:
    client = TestClient(create_app())
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {"status": "ok"}


def test_module_level_app_boots_and_serves_health(aws_free_env: None) -> None:
    # ``with`` runs the lifespan: proves the uvicorn target needs no setup.
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200


# ---------------------------------------------------------------------------
# 2. boto3-free import, proven in an isolated interpreter
# ---------------------------------------------------------------------------


def test_importing_app_main_never_pulls_in_boto3(aws_free_env: None) -> None:
    env = {k: v for k, v in os.environ.items() if k not in AWS_ENV_VARS}
    env["PYTHONPATH"] = str(SRC_ROOT)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys, app.main; assert 'boto3' not in sys.modules; print('clean')",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"subprocess import check failed: {result.stderr}"
    assert result.stdout.strip() == "clean"


# ---------------------------------------------------------------------------
# 3. Error envelope mappings (app.api.errors)
# ---------------------------------------------------------------------------


def test_request_validation_error_maps_to_error_envelope() -> None:
    client = TestClient(create_app(routers=[_test_router]))
    response = client.post(
        "/_test/echo",
        json={"name": "", "count": "not-an-int"},
        headers={"X-Request-ID": "req_test_1"},
    )
    assert response.status_code == 422
    payload = response.json()
    # Frozen shape and key order (mirrors tests/unit/test_errors.py).
    assert list(payload) == ["code", "message", "field_errors", "request_id"]
    assert payload["code"] == "validation_error"
    assert payload["message"] == "Request validation failed"
    assert payload["request_id"] == "req_test_1"
    assert [entry["field"] for entry in payload["field_errors"]] == ["body.name", "body.count"]
    assert all(list(entry) == ["field", "message"] for entry in payload["field_errors"])
    # No-secret rule: submitted values are never echoed back.
    assert "not-an-int" not in response.text


def test_raised_http_exception_maps_status_to_stable_code() -> None:
    client = TestClient(create_app(routers=[_test_router]))
    response = client.get("/_test/forbidden")
    assert response.status_code == 403
    payload = response.json()
    assert list(payload) == ["code", "message", "field_errors", "request_id"]
    assert payload["code"] == "forbidden"
    assert payload["message"] == "Missing required scope: org:members:read"
    assert payload["field_errors"] == []


def test_unmatched_route_returns_not_found_envelope() -> None:
    client = TestClient(create_app())
    response = client.get("/v1/me")
    assert response.status_code == 404
    assert response.json() == {
        "code": "not_found",
        "message": "Not Found",
        "field_errors": [],
        "request_id": None,
    }


def test_unhandled_exception_returns_500_without_leaking_detail() -> None:
    client = TestClient(create_app(routers=[_test_router]), raise_server_exceptions=False)
    response = client.get("/_test/boom")
    assert response.status_code == 500
    payload = response.json()
    assert payload["code"] == "internal_error"
    assert payload["message"] == "Internal server error"
    assert payload["field_errors"] == []
    assert "hunter2" not in response.text


# ---------------------------------------------------------------------------
# 4. Mount extension point; Phase 01 mounts no §14 routers
# ---------------------------------------------------------------------------


def test_create_app_mounts_supplied_routers_in_order() -> None:
    first = APIRouter()
    second = APIRouter()

    @first.get("/_test/order")
    async def _first() -> dict[str, str]:
        return {"winner": "first"}

    @second.get("/_test/order")
    async def _second() -> dict[str, str]:
        return {"winner": "second"}

    client = TestClient(create_app(routers=[first, second]))
    assert client.get("/_test/order").json() == {"winner": "first"}  # earlier router wins
    echo = TestClient(create_app(routers=[_test_router]))
    response = echo.post("/_test/echo", json={"name": "widget", "count": 2})
    assert response.status_code == 201
    assert response.json() == {"name": "widget", "count": 2}


def test_phase_01_app_mounts_no_manifest_routers() -> None:
    # OpenAPI paths are the flattened view of everything mounted; manifest
    # paths use the same ``{param}`` syntax, so they compare 1:1.
    mounted_paths = set(create_app().openapi()["paths"])
    assert mounted_paths == {"/health"}
    for spec in ENDPOINTS:
        assert spec.path not in mounted_paths
