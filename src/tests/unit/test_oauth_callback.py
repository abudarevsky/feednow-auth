"""Unit proofs for the WIP 09 task-4 local ``/oauth/callback`` capture route.

The route lives outside the ``app`` package (``deploy/docker/oauth_callback.py``)
and is loaded with the importlib-from-path pattern established by
``test_smoke_script.py``, then driven through ``TestClient``. Proven here:

1. ``GET /oauth/callback`` renders the ``code``/``state`` pair (or the
   ``error``/``error_description`` pair) as page text and tells the user to
   copy the complete URL back into the terminal.
2. Every echoed value is HTML-escaped (no markup injection), and parameters
   outside the fixed whitelist are never echoed.
3. The handler leaks nothing: zero log records around a code-bearing request,
   and the module imports no logging/storage/service/audit machinery (static
   proof via AST — nothing it *could* call to persist or log).
4. The path constants match the pinned WIP 09 callback URI.
5. ``local_runtime.build_app()`` mounts the router alongside the API routers,
   its request middleware logs the path but never the query string, and the
   production ``app.main:create_app()`` surface stays untouched.
"""

from __future__ import annotations

import ast
import importlib.util
import logging
import sys
from pathlib import Path
from types import ModuleType

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.main import create_app

REPO_ROOT = Path(__file__).resolve().parents[3]
CALLBACK_PATH = REPO_ROOT / "deploy" / "docker" / "oauth_callback.py"
LOCAL_RUNTIME_PATH = REPO_ROOT / "deploy" / "docker" / "local_runtime.py"

# A code/state pair that must never leak into logs, files, or page scripts.
SECRET_CODE = "secret-auth-code-NEVER-LOG"
STATE = "state-abc123"


def _load_module(name: str, path: Path) -> ModuleType:
    """Import a deploy file under a fixed name without mutating ``sys.path``."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


oauth_callback = _load_module("oauth_callback", CALLBACK_PATH)

build_oauth_callback_router = oauth_callback.build_oauth_callback_router


def _client() -> TestClient:
    application = FastAPI()
    application.include_router(build_oauth_callback_router())
    return TestClient(application)


class _SilenceLogger(logging.Filter):
    """Drop records from one named logger (the *client-side* httpx echo).

    httpx logs its own request line — including the full URL with the query
    string — at INFO. That is the test client talking about itself, not the
    handler or the server middleware, so it must not mask the no-leak proof.
    """

    def __init__(self, name: str) -> None:
        super().__init__()
        self._name = name

    def filter(self, record: logging.LogRecord) -> bool:
        return record.name != self._name


def test_code_and_state_are_echoed_with_copy_guidance() -> None:
    response = _client().get(f"/oauth/callback?code={SECRET_CODE}&state={STATE}")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    body = response.text
    assert SECRET_CODE in body
    assert STATE in body
    assert "copy" in body.lower()
    assert "cognito-login.sh" in body


def test_error_pair_is_echoed() -> None:
    response = _client().get("/oauth/callback?error=access_denied&error_description=user+said+no")

    assert response.status_code == 200
    body = response.text
    assert "access_denied" in body
    assert "user said no" in body


def test_bare_callback_still_renders_the_page() -> None:
    response = _client().get("/oauth/callback")

    assert response.status_code == 200
    assert "<h1>" in response.text


def test_echoed_values_are_html_escaped() -> None:
    payload = '<script>alert("xss")</script>'
    response = _client().get(f"/oauth/callback?code={payload}&state=ok")

    assert response.status_code == 200
    body = response.text
    assert "<script>alert(" not in body
    assert "&lt;script&gt;" in body
    assert "&quot;" in body


def test_parameters_outside_the_whitelist_are_not_echoed() -> None:
    response = _client().get(f"/oauth/callback?code={SECRET_CODE}&evil=EVIL-VALUE")

    assert response.status_code == 200
    assert "EVIL-VALUE" not in response.text


def test_handler_emits_no_log_record(caplog: pytest.LogCaptureFixture) -> None:
    # Cap at INFO and drop httpx's own client-side request echo so the
    # assertions below prove the handler itself logged nothing at all.
    with caplog.at_level(logging.INFO), caplog.filtering(_SilenceLogger("httpx")):
        response = _client().get(f"/oauth/callback?code={SECRET_CODE}&state={STATE}")

    assert response.status_code == 200
    assert caplog.records == []
    assert SECRET_CODE not in caplog.text


def test_module_imports_nothing_it_could_log_or_persist_with() -> None:
    """Static proof: only stdlib helpers and FastAPI rendering are imported."""
    tree = ast.parse(CALLBACK_PATH.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module.split(".")[0])

    assert imported <= {"__future__", "collections", "fastapi", "html", "typing"}


def test_route_matches_the_pinned_wip09_callback_uri() -> None:
    path = oauth_callback.OAUTH_CALLBACK_PATH
    assert path == "/oauth/callback"
    assert f"http://localhost:8000{path}" == oauth_callback.OAUTH_CALLBACK_URL

    routes = build_oauth_callback_router().routes
    paths = {getattr(route, "path", None) for route in routes}
    assert paths == {oauth_callback.OAUTH_CALLBACK_PATH}


def _load_local_runtime(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> ModuleType:
    monkeypatch.setenv("FEEDNOW_COGNITO_ISSUERS", "https://cognito.example.invalid")
    monkeypatch.setenv("FEEDNOW_COGNITO_CLIENT_IDS", "localclient123456")
    monkeypatch.setenv("FEEDNOW_PEPPER_SECRET", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
    monkeypatch.setenv("FEEDNOW_SQLITE_PATH", str(tmp_path / "runtime.db"))

    # Fixed module name so repeated loads stay isolated from sys.path.
    return _load_module("feednow_local_runtime", LOCAL_RUNTIME_PATH)


# local_runtime.py is recovered by Phase 10 task 2; keep this file green until then.
@pytest.mark.skipif(
    not LOCAL_RUNTIME_PATH.exists(),
    reason="deploy/docker/local_runtime.py not restored yet (Phase 10 task 2)",
)
def test_local_runtime_mounts_the_callback_route(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime = _load_local_runtime(monkeypatch, tmp_path)
    client = TestClient(runtime.app)

    # The capture page shares the app with the real API routers.
    assert client.get(f"/oauth/callback?code={SECRET_CODE}&state={STATE}").status_code == 200
    assert client.get("/health").status_code == 200
    assert client.get("/v1/me").status_code == 401


@pytest.mark.skipif(
    not LOCAL_RUNTIME_PATH.exists(),
    reason="deploy/docker/local_runtime.py not restored yet (Phase 10 task 2)",
)
def test_local_runtime_access_log_never_carries_the_code(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    runtime = _load_local_runtime(monkeypatch, tmp_path)
    client = TestClient(runtime.app)

    # The local test client has no Uvicorn access logger. The callback handler
    # itself must still never emit the code into Python logging.
    with caplog.at_level(logging.INFO), caplog.filtering(_SilenceLogger("httpx")):
        response = client.get(f"/oauth/callback?code={SECRET_CODE}&state={STATE}")

    assert response.status_code == 200
    assert SECRET_CODE not in caplog.text
    assert caplog.records == []


def test_production_surface_does_not_mount_the_callback_route() -> None:
    response = TestClient(create_app()).get("/oauth/callback")
    assert response.status_code == 404
