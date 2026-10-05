"""Local Docker composition wiring for organization onboarding dispatch."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

import app.api.oauth as oauth_api
from app.models.ids import OrganizationId

REPO_ROOT = Path(__file__).resolve().parents[3]
LOCAL_RUNTIME_PATH = REPO_ROOT / "deploy" / "docker" / "local_runtime.py"


def _load_local_runtime(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, LOCAL_RUNTIME_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_local_runtime_dispatches_to_host_published_vispector_api(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("FEEDNOW_COGNITO_ISSUERS", "https://cognito.example.invalid")
    monkeypatch.setenv("FEEDNOW_COGNITO_CLIENT_IDS", "localclient123456")
    monkeypatch.setenv("FEEDNOW_COGNITO_CLIENT_ID", "localclient123456")
    monkeypatch.setenv("FEEDNOW_COGNITO_DOMAIN", "https://local.auth.example.test")
    monkeypatch.setenv("FEEDNOW_PEPPER_SECRET", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
    monkeypatch.setenv("FEEDNOW_SQLITE_PATH", str(tmp_path / "runtime.db"))
    monkeypatch.setenv("FEEDNOW_VISPECTOR_URL", "http://localhost:5173")
    monkeypatch.setenv("FEEDNOW_VISPECTOR_SERVICE_SECRET", "local-service-secret")
    monkeypatch.delenv("FEEDNOW_VISPECTOR_DISPATCH_URL", raising=False)
    monkeypatch.syspath_prepend(str(LOCAL_RUNTIME_PATH.parent))

    captured: dict[str, object] = {}
    original_builder = oauth_api.build_oauth_router

    def capture_oauth_builder(*args: object, **kwargs: object):
        captured.update(kwargs)
        return original_builder(*args, **kwargs)

    monkeypatch.setattr(oauth_api, "build_oauth_router", capture_oauth_builder)
    runtime = _load_local_runtime("feednow_local_runtime_onboarding_test")

    dispatcher = captured["onboarding_dispatch"]
    assert callable(dispatcher)

    dispatch_calls: list[tuple[object, object, dict[str, object]]] = []

    def capture_dispatch(storage: object, organization_id: object, **kwargs: object) -> None:
        dispatch_calls.append((storage, organization_id, kwargs))

    monkeypatch.setattr(runtime, "dispatch_organization_onboarding", capture_dispatch)
    organization_id = OrganizationId("org_local_runtime_test")
    dispatcher(organization_id)

    assert len(dispatch_calls) == 1
    assert dispatch_calls[0][1] == organization_id
    assert dispatch_calls[0][2] == {
        "base_url": "http://host.docker.internal:8080",
        "service_credential": "local-service-secret",
    }
