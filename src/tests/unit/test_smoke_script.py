"""Unit proofs for the Phase 07 task-7 non-production deployed smoke script.

The script's three seams (``cognito_client``, ``http_get``,
``dynamodb_resource``) are faked here so the whole §5/§6 proof path runs
hermetically. The proofs:

1. The happy path issues the **exact call sequence** — sign_up →
   admin_confirm_sign_up → initiate_auth(USER_PASSWORD_AUTH) → GET /v1/me →
   GetItem ``unique_constraints`` (``external_identity#cognito#<sub>#``) →
   GetItem ``users`` → Query the ``memberships`` ``by-user`` GSI → GetItem the
   ``(organization_id, user_id)`` pair — with the documented keys, prefixes,
   and bearer header, and prints only ids plus a pass line (capsys proves no
   token/password literal appears anywhere in the output).
2. ``prod`` is refused before a single seam call, and only an explicit
   ``--force`` lets it through.
3. Every assertion failure (bad status, foreign id, missing row, wrong
   membership count/role/status) raises a :class:`SmokeError` whose message
   echoes no values.
4. ``main`` maps the prod refusal to exit code 1 without touching AWS (the
   guard runs before any seam binds).

The smoke module lives outside the ``app`` package and is loaded with
importlib — the pattern the CDK/runtime proofs establish.
"""

from __future__ import annotations

import importlib.util
import re
import string
import sys
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SMOKE_PATH = REPO_ROOT / "deploy" / "aws" / "smoke" / "smoke.py"


def _load_module(name: str, path: Path) -> ModuleType:
    """Import a deploy file under a fixed name without mutating ``sys.path``."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


smoke = _load_module("feednow_smoke_script", SMOKE_PATH)

SmokeConfig = smoke.SmokeConfig
SmokeError = smoke.SmokeError
ProdNotForcedError = smoke.ProdNotForcedError
SmokeResult = smoke.SmokeResult
run_smoke = smoke.run_smoke

ENV = "dev"
REGION = "eu-north-1"
USER_POOL_ID = "eu-north-1_Phase07Smoke"
CLIENT_ID = "devclient123456789"
API_BASE = "https://api.example.invalid"
TABLE_PREFIX = "feednow-auth-dev-"

SUB = "11111111-2222-3333-4444-555555555555"
USER_ID = "usr_01SMOKEUSER"
ORG_ID = "org_01SMOKEORG"
MEMBERSHIP_ID = "mem_01SMOKEMEM"
CONSTRAINT_PK = f"external_identity#cognito#{SUB}#"

#: Literal that must never surface in stdout/stderr or an exception message.
ACCESS_TOKEN = "super-secret-access-token-NEVER-PRINT"

CONFIG = SmokeConfig(
    env=ENV,
    region=REGION,
    user_pool_id=USER_POOL_ID,
    client_id=CLIENT_ID,
    api_base_url=API_BASE,
    table_prefix=TABLE_PREFIX,
)

MEMBERSHIP_ROW: dict[str, Any] = {
    "organization_id": ORG_ID,
    "user_id": USER_ID,
    "id": MEMBERSHIP_ID,
    "role": "owner",
    "status": "active",
}


class Harness:
    """Recording seams over a canned deployed state (happy path by default)."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.me_status = 200
        self.me_body: dict[str, Any] = {"id": USER_ID, "display_name": "Smoke"}
        self.constraint_item: dict[str, Any] | None = {
            "pk": CONSTRAINT_PK,
            "kind": "external_identity",
            "entity_id": "eid_01SMOKE",
            "user_id": USER_ID,
        }
        self.user_item: dict[str, Any] | None = {"pk": USER_ID, "email": "smoke@example.invalid"}
        self.membership_rows: list[dict[str, Any]] = [dict(MEMBERSHIP_ROW)]
        self.pair_item: dict[str, Any] | None = dict(MEMBERSHIP_ROW)

    @property
    def names(self) -> list[str]:
        return [name for name, _ in self.calls]

    def kwargs(self, name: str) -> dict[str, Any]:
        matches = [kwargs for seen, kwargs in self.calls if seen == name]
        assert matches, f"no call named {name!r} in {self.names}"
        return matches[-1]

    # -- seams ---------------------------------------------------------------

    def cognito_client(self, region: str) -> _FakeCognito:
        self.calls.append(("cognito_client", {"region": region}))
        return _FakeCognito(self)

    def http_get(self, url: str, headers: Mapping[str, str]) -> tuple[int, dict[str, Any]]:
        self.calls.append(("http_get", {"url": url, "headers": dict(headers)}))
        return self.me_status, dict(self.me_body)

    def dynamodb_resource(self, region: str) -> _FakeResource:
        self.calls.append(("dynamodb_resource", {"region": region}))
        return _FakeResource(self)

    def run(self, config: SmokeConfig = CONFIG, *, force: bool = False) -> SmokeResult:
        return run_smoke(
            config,
            cognito_client=self.cognito_client,
            http_get=self.http_get,
            dynamodb_resource=self.dynamodb_resource,
            force=force,
        )


class _FakeCognito:
    def __init__(self, harness: Harness) -> None:
        self._h = harness

    def sign_up(self, **kwargs: Any) -> dict[str, Any]:
        self._h.calls.append(("sign_up", kwargs))
        return {"UserSub": SUB}

    def admin_confirm_sign_up(self, **kwargs: Any) -> dict[str, Any]:
        self._h.calls.append(("admin_confirm_sign_up", kwargs))
        return {}

    def initiate_auth(self, **kwargs: Any) -> dict[str, Any]:
        self._h.calls.append(("initiate_auth", kwargs))
        return {"AuthenticationResult": {"AccessToken": ACCESS_TOKEN}}


class _FakeResource:
    def __init__(self, harness: Harness) -> None:
        self._h = harness

    def Table(self, name: str) -> _FakeTable:
        return _FakeTable(self._h, name)


class _FakeTable:
    def __init__(self, harness: Harness, name: str) -> None:
        self._h = harness
        self._name = name

    def get_item(self, **kwargs: Any) -> dict[str, Any]:
        self._h.calls.append((f"get_item:{self._name}", kwargs))
        if self._name.endswith("unique_constraints"):
            item = self._h.constraint_item
        elif self._name.endswith("users"):
            item = self._h.user_item
        else:
            item = self._h.pair_item
        return {} if item is None else {"Item": dict(item)}

    def query(self, **kwargs: Any) -> dict[str, Any]:
        self._h.calls.append((f"query:{self._name}", kwargs))
        return {"Items": [dict(row) for row in self._h.membership_rows]}


EXPECTED_SEQUENCE: list[str] = [
    "cognito_client",
    "sign_up",
    "admin_confirm_sign_up",
    "initiate_auth",
    "http_get",
    "dynamodb_resource",
    f"get_item:{TABLE_PREFIX}unique_constraints",
    f"get_item:{TABLE_PREFIX}users",
    f"query:{TABLE_PREFIX}memberships",
    f"get_item:{TABLE_PREFIX}memberships",
]


# --- 1. happy path: exact call sequence and safe output ----------------------


def test_happy_path_issues_the_exact_proof_sequence(capsys: pytest.CaptureFixture[str]) -> None:
    harness = Harness()
    result = harness.run()

    assert harness.names == EXPECTED_SEQUENCE
    assert harness.kwargs("cognito_client") == {"region": REGION}
    assert harness.kwargs("dynamodb_resource") == {"region": REGION}

    sign_up = harness.kwargs("sign_up")
    assert sign_up["UserPoolId"] == USER_POOL_ID
    assert sign_up["ClientId"] == CLIENT_ID
    email = sign_up["Username"]
    assert re.fullmatch(r"smoke\+\d+@example\.com", email)
    assert sign_up["AttributeList"] == [{"Name": "email", "Value": email}]
    password = sign_up["Password"]
    assert isinstance(password, str) and len(password) >= 16
    assert any(char in string.ascii_uppercase for char in password)
    assert any(char in string.ascii_lowercase for char in password)
    assert any(char in string.digits for char in password)
    assert any(char in "!@#$%^&*" for char in password)

    confirm = harness.kwargs("admin_confirm_sign_up")
    assert confirm == {"UserPoolId": USER_POOL_ID, "Username": email}

    auth = harness.kwargs("initiate_auth")
    assert auth["AuthFlow"] == "USER_PASSWORD_AUTH"
    assert auth["ClientId"] == CLIENT_ID
    assert auth["AuthParameters"] == {"USERNAME": email, "PASSWORD": password}

    http = harness.kwargs("http_get")
    assert http["url"] == f"{API_BASE}/v1/me"
    assert http["headers"] == {"Authorization": f"Bearer {ACCESS_TOKEN}"}

    constraint = harness.kwargs(f"get_item:{TABLE_PREFIX}unique_constraints")
    assert constraint["Key"] == {"pk": CONSTRAINT_PK}
    assert constraint["ConsistentRead"] is True

    user = harness.kwargs(f"get_item:{TABLE_PREFIX}users")
    assert user["Key"] == {"pk": USER_ID}

    query = harness.kwargs(f"query:{TABLE_PREFIX}memberships")
    assert query["IndexName"] == "by-user"
    expression = query["KeyConditionExpression"]
    assert USER_ID in expression.get_expression()["values"]

    pair = harness.kwargs(f"get_item:{TABLE_PREFIX}memberships")
    assert pair["Key"] == {"organization_id": ORG_ID, "user_id": USER_ID}

    assert result == SmokeResult(
        cognito_sub=SUB,
        user_id=USER_ID,
        organization_id=ORG_ID,
        membership_id=MEMBERSHIP_ID,
    )

    out = capsys.readouterr().out
    assert f"SMOKE PASS env={ENV}" in out
    for safe_id in (SUB, USER_ID, ORG_ID, MEMBERSHIP_ID):
        assert safe_id in out
    # The safety contract: no token, no password, ever.
    assert ACCESS_TOKEN not in out
    assert password not in out


# --- 2. prod guard ------------------------------------------------------------


def test_prod_is_refused_before_any_seam_call(capsys: pytest.CaptureFixture[str]) -> None:
    harness = Harness()
    prod = SmokeConfig(**{**CONFIG.__dict__, "env": "prod"})

    with pytest.raises(ProdNotForcedError):
        harness.run(prod)

    assert harness.calls == []
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_prod_runs_only_with_explicit_force() -> None:
    harness = Harness()
    prod = SmokeConfig(**{**CONFIG.__dict__, "env": "prod"})

    result = harness.run(prod, force=True)

    assert result.user_id == USER_ID
    assert harness.names == EXPECTED_SEQUENCE


def test_staging_is_accepted_without_force() -> None:
    harness = Harness()
    staging = SmokeConfig(**{**CONFIG.__dict__, "env": "staging"})

    assert harness.run(staging).user_id == USER_ID


# --- 3. assertion failures: fixed messages, no echoed values ------------------


def test_non_200_from_v1_me_fails_without_leaking_the_token() -> None:
    harness = Harness()
    harness.me_status = 401

    with pytest.raises(SmokeError) as excinfo:
        harness.run()

    assert "401" in str(excinfo.value)
    assert ACCESS_TOKEN not in str(excinfo.value)


def test_foreign_id_in_me_response_is_rejected() -> None:
    harness = Harness()
    harness.me_body = {"id": "org_pretender"}

    with pytest.raises(SmokeError, match="usr_"):
        harness.run()


def test_missing_identity_constraint_item_fails() -> None:
    harness = Harness()
    harness.constraint_item = None

    with pytest.raises(SmokeError, match="unique_constraints"):
        harness.run()


def test_constraint_item_pointing_at_another_user_fails() -> None:
    harness = Harness()
    assert harness.constraint_item is not None
    harness.constraint_item = {**harness.constraint_item, "user_id": "usr_01SOMEONEELSE"}

    with pytest.raises(SmokeError, match="different user"):
        harness.run()


def test_membership_query_must_resolve_exactly_one_default_org() -> None:
    for rows in ([], [dict(MEMBERSHIP_ROW), {**MEMBERSHIP_ROW, "organization_id": "org_02"}]):
        harness = Harness()
        harness.membership_rows = rows

        with pytest.raises(SmokeError, match="exactly one"):
            harness.run()


def test_default_membership_pair_must_be_active_owner() -> None:
    for broken in (
        {**MEMBERSHIP_ROW, "role": "member"},
        {**MEMBERSHIP_ROW, "status": "inactive"},
        None,
    ):
        harness = Harness()
        harness.pair_item = broken

        with pytest.raises(SmokeError):
            harness.run()


# --- 4. CLI surface -----------------------------------------------------------


def test_main_maps_prod_refusal_to_exit_code_one(
    capsys: pytest.CaptureFixture[str],
) -> None:
    argv = [
        "--env",
        "prod",
        "--region",
        REGION,
        "--user-pool-id",
        USER_POOL_ID,
        "--client-id",
        CLIENT_ID,
        "--api-url",
        API_BASE,
        "--table-prefix",
        TABLE_PREFIX,
    ]

    assert smoke.main(argv) == 1
    captured = capsys.readouterr()
    assert "SMOKE FAIL" in captured.err
    assert captured.out == ""


def test_main_rejects_unknown_environment() -> None:
    with pytest.raises(SystemExit) as excinfo:
        smoke.main(["--env", "qa", "--region", REGION])
    assert excinfo.value.code == 2
