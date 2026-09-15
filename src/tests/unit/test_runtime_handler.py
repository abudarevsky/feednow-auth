"""Unit proofs for the Phase 07 task-5 runtime packaging and composition root.

Covers the task's verify lines:

1. ``deploy/aws/lambda-requirements.txt`` pins exactly the Lambda payload set
   (and nothing that belongs to the synth path or the test tooling).
2. Importing ``deploy/aws/runtime/handler.py`` performs **no** ``FEEDNOW_*``
   environment read and **no** AWS SDK call, and leaves the application
   uncomposed.
3. :class:`RuntimeConfig.from_environ` reads the five documented keys,
   normalizes the comma-separated Cognito allowlists, and fails naming only
   the missing keys (never their values).
4. ``build_app()`` with injected fakes mounts exactly the frozen manifest
   routes (plus the Phase 01 ``/health``), forces the single pepper read at
   cold start, and never touches ``os.environ`` when a config is supplied.
5. :class:`SecretsManagerPepper` fetches ``GetSecretValue`` exactly once,
   parses the ``pepper`` JSON field, enforces the ≥ 32-byte floor, and never
   renders the value in ``repr``/``str`` or in any error message.

The deploy modules are loaded with importlib (they live outside the ``app``
package); ``secrets_pepper`` is registered under its own name first so
``handler``'s top-level ``from secrets_pepper import ...`` resolves through
``sys.modules`` — the pattern the CDK proofs already establish.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import boto3
import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from mangum import Mangum

from app.api.schemas.manifest import ENDPOINTS
from app.auth.pepper import MIN_PEPPER_BYTES, PepperSource, StaticPepper

RUNTIME_DIR = Path(__file__).resolve().parents[3] / "deploy" / "aws" / "runtime"
LAMBDA_REQUIREMENTS = RUNTIME_DIR.parent / "lambda-requirements.txt"

#: 48 alphanumeric bytes — what the task-4 CDK ``GenerateSecretString`` yields.
PEPPER = b"a" * 48

#: ASCII value used wherever a leak would be detectable in a rendered string.
#: 40 bytes: it must clear the 32-byte floor to be accepted at all.
MARKED_PEPPER = b"leak-check-marked-pepper-value-40-bytes!!"

#: Every ``FEEDNOW_*`` key the composition root is allowed to read.
CONFIG_KEYS = (
    "FEEDNOW_DYNAMODB_REGION",
    "FEEDNOW_TABLE_PREFIX",
    "FEEDNOW_COGNITO_ISSUERS",
    "FEEDNOW_COGNITO_CLIENT_IDS",
    "FEEDNOW_PEPPER_SECRET_ID",
)

ISSUER = "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_AAAAAAAAA"

FAKE_ENV: dict[str, str] = {
    "FEEDNOW_DYNAMODB_REGION": "eu-north-1",
    "FEEDNOW_TABLE_PREFIX": "feednow-auth-dev-",
    "FEEDNOW_COGNITO_ISSUERS": ISSUER,
    "FEEDNOW_COGNITO_CLIENT_IDS": "devclient1",
    "FEEDNOW_PEPPER_SECRET_ID": "feednow-auth/dev/api-pepper",
}

SECRET_ID = FAKE_ENV["FEEDNOW_PEPPER_SECRET_ID"]


def _load_module(name: str, path: Path) -> ModuleType:
    """Import a deploy file under a fixed name without touching ``sys.path``."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


secrets_pepper = _load_module("secrets_pepper", RUNTIME_DIR / "secrets_pepper.py")
runtime_handler = _load_module("feednow_runtime_handler", RUNTIME_DIR / "handler.py")

SecretsManagerPepper = secrets_pepper.SecretsManagerPepper
RuntimeConfig = runtime_handler.RuntimeConfig


@pytest.fixture(autouse=True)
def _clean_runtime_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Never inherit a developer's shell values for the runtime inputs."""
    for name in CONFIG_KEYS:
        monkeypatch.delenv(name, raising=False)
    yield


def _assert_no_value(rendered: str, value: bytes) -> None:
    """No rendering may carry the pepper, raw or repr'd."""
    assert value.decode("ascii") not in rendered
    assert repr(value) not in rendered


# --- 1. Lambda payload packaging ---------------------------------------------


def test_lambda_requirements_pin_the_payload_dependencies() -> None:
    pins = {
        line.split("=")[0].split("<")[0].split(">")[0].split("[")[0].strip()
        for line in LAMBDA_REQUIREMENTS.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    assert pins == {"boto3", "fastapi", "mangum", "pydantic", "pyjwt"}


def test_lambda_requirements_exclude_synth_and_test_packages() -> None:
    requirements = [
        line.strip()
        for line in LAMBDA_REQUIREMENTS.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    text = " ".join(requirements).lower()
    for forbidden in ("aws-cdk", "constructs", "uvicorn", "pytest", "httpx"):
        assert forbidden not in text


# --- 2. Import safety ---------------------------------------------------------


class _RecordingEnviron(dict[str, str]):
    """``os.environ`` stand-in that records every ``FEEDNOW_*`` read."""

    def __init__(self, source: dict[str, str]) -> None:
        super().__init__(source)
        self.reads: list[str] = []

    def get(self, key: str, default: Any = None) -> Any:  # type: ignore[override]
        if key.startswith("FEEDNOW_"):
            self.reads.append(key)
        return super().get(key, default)

    def __getitem__(self, key: str) -> str:
        if key.startswith("FEEDNOW_"):
            self.reads.append(key)
        return super().__getitem__(key)


def test_importing_handler_reads_no_config_and_touches_no_aws(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Import is boot-safe: no configuration read, no AWS client, no app build."""
    guard = _RecordingEnviron(dict(os.environ))
    monkeypatch.setattr(os, "environ", guard)  # type: ignore[arg-type]

    def _boom(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError(f"AWS I/O attempted during import: {args} {kwargs}")

    monkeypatch.setattr(boto3, "client", _boom)
    monkeypatch.setattr(boto3, "resource", _boom)

    module = _load_module("feednow_runtime_import_probe", RUNTIME_DIR / "handler.py")

    assert guard.reads == []
    assert module.app.built is False
    assert isinstance(module.handler, Mangum)
    assert module.API_STAGE == "$default"


# --- 3. Runtime configuration -------------------------------------------------


def test_runtime_config_reads_every_required_key() -> None:
    config = RuntimeConfig.from_environ(FAKE_ENV)
    assert config.region == "eu-north-1"
    assert config.table_prefix == "feednow-auth-dev-"
    assert config.cognito_issuers == (ISSUER,)
    assert config.cognito_client_ids == ("devclient1",)
    assert config.pepper_secret_id == SECRET_ID


def test_runtime_config_normalizes_comma_separated_allowlists() -> None:
    config = RuntimeConfig.from_environ(
        {
            **FAKE_ENV,
            "FEEDNOW_COGNITO_ISSUERS": f" {ISSUER} ,{ISSUER},,",
            "FEEDNOW_COGNITO_CLIENT_IDS": " c1 , c2 , c1 ",
        }
    )
    assert config.cognito_issuers == (ISSUER,)
    assert config.cognito_client_ids == ("c1", "c2")


@pytest.mark.parametrize("missing", CONFIG_KEYS)
def test_runtime_config_failure_names_only_the_missing_key(missing: str) -> None:
    environ = {key: value for key, value in FAKE_ENV.items() if key != missing}
    with pytest.raises(RuntimeError) as excinfo:
        RuntimeConfig.from_environ(environ)
    assert missing in str(excinfo.value)
    assert "feednow-auth-dev-" not in str(excinfo.value)


@pytest.mark.parametrize("blank_key", ["FEEDNOW_COGNITO_ISSUERS", "FEEDNOW_COGNITO_CLIENT_IDS"])
def test_runtime_config_rejects_a_blank_allowlist_value(blank_key: str) -> None:
    """A present-but-empty list fails here, not inside the JWKS source/verifier."""
    with pytest.raises(RuntimeError) as excinfo:
        RuntimeConfig.from_environ({**FAKE_ENV, blank_key: " , , "})
    assert blank_key in str(excinfo.value)


def test_runtime_config_defaults_to_the_process_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key, value in FAKE_ENV.items():
        monkeypatch.setenv(key, value)
    assert RuntimeConfig.from_environ().table_prefix == "feednow-auth-dev-"


# --- 4. Composition root ------------------------------------------------------


class _FakeComponent:
    """Factory double: records the config it received, returns a fixed product."""

    def __init__(self, product: Any) -> None:
        self.product = product
        self.configs: list[Any] = []

    def __call__(self, config: Any, **kwargs: Any) -> Any:
        self.configs.append(config)
        return self.product


class _CountingPepper:
    """``PepperSource`` double counting ``current()`` — the cold-start read."""

    def __init__(self) -> None:
        self._inner = StaticPepper(PEPPER)
        self.calls = 0

    def current(self) -> bytes:
        self.calls += 1
        return self._inner.current()


def _build_with_fakes(**overrides: Any) -> FastAPI:
    """Run the real ``build_app`` with all three component seams faked out."""
    fakes = {
        "storage_factory": _FakeComponent(object()),
        "verifier_factory": _FakeComponent(object()),
        "pepper_factory": _FakeComponent(_CountingPepper()),
        "environ": FAKE_ENV,
    }
    fakes.update(overrides)
    return runtime_handler.build_app(**fakes)


def _mounted_routes(application: FastAPI) -> set[tuple[str, str]]:
    """Every ``(method, path)`` the application answers, unwrapping mounted routers.

    FastAPI ≥0.141 keeps ``include_router`` results as wrapper routes, so the
    walk has to descend instead of reading ``app.routes`` flat.
    """

    def walk(routes: Any) -> Iterator[tuple[str, str]]:
        for route in routes:
            if isinstance(route, APIRoute):
                for method in set(route.methods or ()) - {"HEAD"}:
                    yield (method, route.path)
            else:
                inner = getattr(route, "original_router", None)
                children = getattr(inner, "routes", None) or getattr(route, "routes", None)
                if children is not None:
                    yield from walk(children)

    return set(walk(application.routes))


def test_build_app_mounts_exactly_the_manifest_routes() -> None:
    app = _build_with_fakes()
    expected = {(spec.method, spec.path) for spec in ENDPOINTS} | {("GET", "/health")}
    assert _mounted_routes(app) == expected


def test_build_app_wires_the_resolved_config_into_every_factory() -> None:
    storage = _FakeComponent(object())
    verifier = _FakeComponent(object())
    pepper = _FakeComponent(_CountingPepper())
    app = _build_with_fakes(
        storage_factory=storage, verifier_factory=verifier, pepper_factory=pepper
    )
    resolved = RuntimeConfig.from_environ(FAKE_ENV)
    assert storage.configs == [resolved]
    assert verifier.configs == [resolved]
    assert pepper.configs == [resolved]
    assert isinstance(app, FastAPI)


def test_build_app_reads_the_pepper_once_at_cold_start() -> None:
    pepper = _CountingPepper()
    _build_with_fakes(pepper_factory=lambda _config: pepper)
    assert pepper.calls == 1


def test_build_app_with_config_injected_never_touches_environ(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = _RecordingEnviron({})
    monkeypatch.setattr(os, "environ", guard)  # type: ignore[arg-type]
    _build_with_fakes(config=RuntimeConfig.from_environ(FAKE_ENV), environ=None)
    assert guard.reads == []


def test_default_verifier_factory_builds_a_cognito_verifier() -> None:
    config = RuntimeConfig.from_environ(FAKE_ENV)
    verifier = runtime_handler._default_verifier(config)
    assert verifier.allowed_issuers == frozenset(config.cognito_issuers)
    assert verifier.allowed_client_ids == frozenset(config.cognito_client_ids)


def test_default_storage_factory_builds_the_prefixed_adapter() -> None:
    config = RuntimeConfig.from_environ(FAKE_ENV)
    storage = runtime_handler._default_storage(config, dynamodb_resource=object())
    assert storage.table_prefix == config.table_prefix


def test_lazy_app_composes_once_and_forwards_every_request() -> None:
    builds = 0
    seen: list[Any] = []

    async def stub_app(scope: Any, receive: Any, send: Any) -> None:
        seen.append(scope)

    def factory() -> Any:
        nonlocal builds
        builds += 1
        return stub_app

    lazy = runtime_handler._LazyApp(factory)
    assert lazy.built is False
    asyncio.run(lazy({"type": "http"}, None, None))
    asyncio.run(lazy({"type": "http"}, None, None))
    assert builds == 1
    assert lazy.built is True
    assert len(seen) == 2


def test_module_handler_is_a_mangum_adapter_over_the_lazy_app() -> None:
    assert isinstance(runtime_handler.handler, Mangum)
    assert runtime_handler.handler.app is runtime_handler.app
    assert runtime_handler.app.built is False


# --- 5. Secrets Manager pepper source ----------------------------------------


class _FakeSecretsClient:
    """``secretsmanager`` double: counts calls, returns a canned payload."""

    def __init__(self, payload: dict[str, Any] | None = None, error: Exception | None = None):
        self.payload: dict[str, Any] = payload if payload is not None else _string_payload(PEPPER)
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def get_secret_value(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.payload


def _string_payload(value: bytes) -> dict[str, Any]:
    return {"SecretString": json.dumps({"pepper": value.decode("ascii")})}


def _source(payload: dict[str, Any] | None = None, *, client: Any | None = None) -> Any:
    return SecretsManagerPepper(
        SECRET_ID, client=client if client is not None else _FakeSecretsClient(payload)
    )


def test_pepper_source_satisfies_the_published_protocol() -> None:
    assert isinstance(_source(), PepperSource)


def test_construction_performs_no_io() -> None:
    client = _FakeSecretsClient()
    source = SecretsManagerPepper(SECRET_ID, client=client)
    assert client.calls == []
    assert repr(source) == "SecretsManagerPepper(<redacted>)"


def test_secret_id_is_read_from_the_environment() -> None:
    source = SecretsManagerPepper(client=_FakeSecretsClient(), environ={CONFIG_KEYS[4]: SECRET_ID})
    assert source.secret_id == SECRET_ID


def test_missing_secret_id_fails_naming_the_key() -> None:
    with pytest.raises(ValueError) as excinfo:
        SecretsManagerPepper(client=_FakeSecretsClient(), environ={})
    assert CONFIG_KEYS[4] in str(excinfo.value)


def test_current_parses_the_pepper_json_field() -> None:
    assert _source(_string_payload(PEPPER)).current() == PEPPER


def test_get_secret_value_is_issued_exactly_once() -> None:
    client = _FakeSecretsClient(_string_payload(PEPPER))
    source = SecretsManagerPepper(SECRET_ID, client=client)
    assert source.current() == PEPPER
    assert source.current() == PEPPER
    assert client.calls == [{"SecretId": SECRET_ID}]


def test_binary_payload_is_accepted() -> None:
    client = _FakeSecretsClient({"SecretBinary": json.dumps({"pepper": "b" * 40}).encode()})
    assert SecretsManagerPepper(SECRET_ID, client=client).current() == b"b" * 40


def test_floor_is_enforced_and_the_value_is_not_leaked() -> None:
    short = MARKED_PEPPER[: MIN_PEPPER_BYTES - 1]
    source = _source(_string_payload(short))
    with pytest.raises(ValueError) as excinfo:
        source.current()
    assert str(MIN_PEPPER_BYTES) in str(excinfo.value)
    _assert_no_value(str(excinfo.value), short)


@pytest.mark.parametrize(
    "payload",
    [
        {"SecretString": f"not json {MARKED_PEPPER.decode()}"},
        {"SecretString": json.dumps({"pepper": 42})},
        {"SecretString": json.dumps({"other": MARKED_PEPPER.decode()})},
        {"SecretString": ""},
        {"SecretBinary": b"\xff\xfe"},
        {},
    ],
)
def test_malformed_payloads_fail_closed_without_leaking(payload: dict[str, Any]) -> None:
    source = _source(payload)
    with pytest.raises(ValueError) as excinfo:
        source.current()
    assert SECRET_ID in str(excinfo.value)  # the name is configuration, safe to render
    _assert_no_value(str(excinfo.value), MARKED_PEPPER)
    assert excinfo.value.__cause__ is None  # no chained payload document


def test_transport_failure_is_reclassified_without_details() -> None:
    client = _FakeSecretsClient(error=RuntimeError("AccessDeniedException on something"))
    source = _source(client=client)
    with pytest.raises(ValueError) as excinfo:
        source.current()
    assert "not readable" in str(excinfo.value)


def test_repr_and_str_are_redacted() -> None:
    source = _source(_string_payload(MARKED_PEPPER))
    assert source.current() == MARKED_PEPPER  # fetch first: the cache must hide too
    for rendered in (repr(source), str(source), f"{source}", f"{source!r}"):
        assert rendered == "SecretsManagerPepper(<redacted>)"
    assert MARKED_PEPPER not in source.__dict__.values()
    assert MARKED_PEPPER.decode() not in repr(source.__dict__)
    assert repr(source.__dict__["_static"]) == "StaticPepper(<redacted>)"
