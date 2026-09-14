"""Secrecy acceptance sweeps (Phase 05 task 7, part a).

One full Phase 05 battery over HTTP — create (both environments), list,
revoke (twice), every denial class (``insufficient_role``, ``no_membership``,
``human_only``, ``insufficient_scope``, ``organization_mismatch``,
``inactive_organization``, unknown-org), every authentication failure class,
and the 400/404/422 error paths — with ``caplog`` armed at **every** level,
followed by direct reads of **every** ``api_keys`` and ``audit_events`` row
and every captured response/error body. The AGENTS.md rule ("no plaintext API
secret, password, JWT, refresh token, or Cognito token may be persisted or
written to logs/audit metadata") is then checked mechanically against the
credential material this battery minted:

- the full literal appears in **exactly one** response body per key (its own
  201) and in nothing else — not a list, not an error, not a log record;
- the secret appears in no response other than that one 201, in no audit
  row, in no log record, and in no raw database byte; the §8 key-id segment
  (non-secret by design, decision 2) additionally appears in no response
  field other than the owning 201's literal and the masked ``key_prefix``
  values it is designed to live in;
- the pepper appears nowhere at all (the row stores only
  ``HMAC-SHA256(pepper, secret)``);
- the key-id segment's only persistence is the ``api_keys.key_id`` /
  ``key_prefix`` columns it is designed to live in (non-secret by §8);
- the human JWTs and the ``Bearer`` marker never reach audit metadata.

The hygiene half of the sweep pins the §16 vocabulary for this phase: every
action is inside the §16 set, every ``metadata`` key set is exactly the
decision-9/10/7 pinned shape (including the three new denial reasons), and
every actor carries the matching ``actor_type``.
"""

# No ``from __future__ import annotations``: the probe handler's
# ``Annotated[..., Depends(scope_dep)]`` references a closure local (the
# ``keys.py`` precedent).

import json
import logging
import sqlite3
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient
from support.cognito import JwksTestServer, TestKey, generate_test_key, sign_token

from app.api.keys import build_api_keys_router
from app.auth.cognito import CognitoAccessTokenVerifier
from app.auth.credentials import hash_secret, parse_literal
from app.auth.jwks import CognitoJwksSource
from app.auth.organization_access import PrincipalAccess, build_organization_scope_dependency
from app.auth.pepper import StaticPepper
from app.main import create_app
from app.models.api_key import ApiKey
from app.models.enums import (
    ApiKeyEnvironment,
    ApiKeyStatus,
    IdentityProvider,
    MembershipRole,
    OrganizationStatus,
    OrganizationType,
    UserStatus,
)
from app.models.errors import Error
from app.models.external_identity import ExternalIdentity
from app.models.ids import (
    ApiKeyId,
    ExternalIdentityId,
    MembershipId,
    OrganizationId,
    UserId,
)
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.user import User
from app.services.api_key_service import build_key_prefix
from app.storage.sqlite import CURSOR_SCOPE_MEMBERSHIPS, SQLiteStorage, encode_cursor

ALLOWED_CLIENT = "secrecy-app-client"
_T0 = datetime(2026, 9, 14, 15, 0, 0, tzinfo=UTC)

#: 38-byte fixed test pepper (never production, never a real secret).
PEPPER = b"integration-secrecy-pepper-0123456789ab"

RUN_SCOPE = "vispector:inspection:run"
READ_SCOPE = "vispector:inspection:read"
PROBE_SCOPE = RUN_SCOPE
PROBE_OPERATION = "run_inspection"

SEG_LIVE = "01JXYZ7KA20MB63PCQ8VNDWFTG"
SEG_TEST = "01JXYZ7KA20MB63PCQ8VNDWFTH"
SEG_NOSCOPE = "01JXYZ7KA20MB63PCQ8VNDWFTJ"
SEG_OUTSIDE = "01JXYZ7KA20MB63PCQ8VNDWFTK"
SEED_SECRET = "aE-W-K9J0KCdH1pnlK_BGZGEcs8xWSr3tTiSKGVPFXo"

#: §16 action vocabulary (the whole set; Phase 05 adds the two api_key actions).
_SPEC_16_ACTIONS = {
    "user.created",
    "organization.created",
    "membership.created",
    "membership.removed",
    "api_key.created",
    "api_key.revoked",
    "authorization.denied",
}

#: Decision-9/10/7 pinned metadata key sets, per action.
_PINNED_METADATA_KEYS: dict[str, set[str]] = {
    "user.created": {"provider"},
    "organization.created": {"type"},
    "membership.created": {"role"},
    "membership.removed": {"role"},
    "api_key.created": {"environment", "scopes"},
    "api_key.revoked": set(),
    "authorization.denied": {"reason", "operation"},
}

#: The seven denial reasons of the extended vocabulary (decision 7).
_DENIAL_REASONS = {
    "no_membership",
    "insufficient_role",
    "inactive_membership",
    "inactive_organization",
    "human_only",
    "organization_mismatch",
    "insufficient_scope",
}


# ---------------------------------------------------------------------------
# Row readers (direct SQLite — no audit read surface exists)
# ---------------------------------------------------------------------------


def rows(db_path: Path, table: str) -> list[dict[str, Any]]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in conn.execute(f"SELECT * FROM {table}").fetchall()]
    finally:
        conn.close()


def _without_key_prefixes(node: Any) -> Any:
    """Return a copy of decoded ``node`` with every ``key_prefix`` value removed.

    Decision 2 pins ``key_prefix`` to ``fn_<env>_<key-id>_<6-char head>...``:
    the §8 key-id segment is **non-secret** and legitimately lives inside the
    masked display prefix (the ``api_keys.key_id``/``key_prefix`` columns are
    its designed home — see this module's docstring). The response sweeps
    therefore scan segment material against this prefix-stripped view, while
    literal/secret/pepper bytes keep being scanned against the raw body.
    """
    if isinstance(node, dict):
        return {
            key: _without_key_prefixes(value) for key, value in node.items() if key != "key_prefix"
        }
    if isinstance(node, list):
        return [_without_key_prefixes(item) for item in node]
    return node


def _segment_scannable(body: bytes) -> bytes:
    """``body`` with JSON ``key_prefix`` values stripped (segment-scan view)."""
    try:
        decoded = json.loads(body)
    except ValueError:
        return body
    return json.dumps(_without_key_prefixes(decoded)).encode()


def _is_segment_material(name: str) -> bool:
    """True for the sweep's §8 key-id-segment entries (``*.segment``,
    ``seeded.segment.*``).

    The segment is non-secret by §8 design (decision 2): it legitimately
    lives in the ``api_keys.key_id``/``key_prefix`` columns and, through the
    masked display prefix, in list responses. The sweeps exempt it *there*
    and nowhere else — literal, secret, and pepper bytes keep the strict
    rule everywhere.
    """
    return "segment" in name.split(".")


# ---------------------------------------------------------------------------
# Seeding
# ---------------------------------------------------------------------------


def seed_user(storage: SQLiteStorage, *, user_id: str, sub: str, email: str) -> None:
    storage.create_user(
        User(
            id=UserId(user_id),
            display_name=f"seed {user_id}",
            email=email,
            status=UserStatus.ACTIVE,
            created_at=_T0,
            updated_at=_T0,
        )
    )
    storage.create_external_identity(
        ExternalIdentity(
            id=ExternalIdentityId(f"extid_{user_id.removeprefix('usr_')}"),
            user_id=UserId(user_id),
            provider=IdentityProvider.COGNITO,
            provider_subject=sub,
            provider_tenant=None,
            created_at=_T0,
        )
    )


def seed_org(
    storage: SQLiteStorage,
    *,
    organization_id: str,
    slug: str,
    status: OrganizationStatus = OrganizationStatus.ACTIVE,
) -> None:
    storage.create_organization(
        Organization(
            id=OrganizationId(organization_id),
            name=f"seed {organization_id}",
            slug=slug,
            type=OrganizationType.CUSTOMER,
            status=status,
            created_at=_T0,
            updated_at=_T0,
        )
    )


def seed_membership(
    storage: SQLiteStorage,
    *,
    organization_id: str,
    user_id: str,
    role: MembershipRole,
    membership_id: str,
) -> None:
    storage.create_membership(
        Membership(
            id=MembershipId(membership_id),
            organization_id=OrganizationId(organization_id),
            user_id=UserId(user_id),
            role=role,
            status="active",
            created_at=_T0,
        )
    )


def seed_key(
    storage: SQLiteStorage,
    *,
    api_key_id: str,
    organization_id: str,
    key_id_segment: str,
    scopes: list[str],
    environment: ApiKeyEnvironment = ApiKeyEnvironment.LIVE,
) -> str:
    """Seed one active key row directly; return its full literal."""
    storage.create_api_key(
        ApiKey(
            id=ApiKeyId(api_key_id),
            organization_id=OrganizationId(organization_id),
            created_by_user_id=UserId("usr_owner"),
            name=f"seeded {api_key_id}",
            key_id=key_id_segment,
            key_prefix=build_key_prefix(environment, key_id_segment, SEED_SECRET),
            secret_hash=hash_secret(PEPPER, SEED_SECRET),
            environment=environment,
            scopes=scopes,
            status=ApiKeyStatus.ACTIVE,
            created_at=_T0,
        )
    )
    from app.auth.credentials import build_literal

    return build_literal(environment, key_id_segment, SEED_SECRET)


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------


class _SecrecyEnv:
    """Shipped keys router + a scope probe, real SQLite, signed human tokens.

    Every response is retained (label + raw bytes) so the sweeps can assert
    against the complete HTTP surface, not just the happy path.
    """

    def __init__(self, db_path: Path, server: JwksTestServer, key: TestKey) -> None:
        self.db_path = db_path
        self.storage = SQLiteStorage(db_path)
        self.pepper = StaticPepper(PEPPER)
        issuer = server.issuer("pool-a")
        verifier = CognitoAccessTokenVerifier(
            CognitoJwksSource([issuer]),
            allowed_issuers=[issuer],
            allowed_client_ids=[ALLOWED_CLIENT],
        )
        scope_dep = build_organization_scope_dependency(
            self.storage, verifier, self.pepper, PROBE_SCOPE, PROBE_OPERATION
        )

        probe = APIRouter()

        def scope_probe(
            organization_id: OrganizationId,
            access: Annotated[PrincipalAccess, Depends(scope_dep)],
        ) -> dict[str, str]:
            """Product-shaped probe: only reached on a granted key/human."""
            return {"actor": str(access.principal.context.actor_id)}

        probe.add_api_route("/v1/probe/scope/{organization_id}", scope_probe, methods=["GET"])
        app = create_app(
            routers=[build_api_keys_router(self.storage, verifier, self.pepper), probe]
        )
        self.client = TestClient(app, raise_server_exceptions=False)
        self.issuer = issuer
        self.key = key
        self.bodies: dict[str, bytes] = {}
        self.tokens: dict[str, str] = {}

    # -- HTTP with recording -------------------------------------------------

    def call(self, label: str, method: str, path: str, **kwargs: Any) -> Any:
        """Issue one request, record its raw body under ``label``, return it."""
        response = getattr(self.client, method)(path, **kwargs)
        assert label not in self.bodies, f"duplicate label {label!r}"
        self.bodies[label] = response.content
        return response

    # -- Bearers -------------------------------------------------------------

    def human(self, name: str) -> dict[str, str]:
        """Signed Cognito bearer for ``name`` (recorded for the JWT sweep)."""
        if name not in self.tokens:
            now = int(time.time())
            self.tokens[name] = sign_token(
                {
                    "sub": f"{name}-sub",
                    "email": f"{name}@example.test",
                    "username": f"user-{name}",
                    "client_id": ALLOWED_CLIENT,
                    "iss": self.issuer,
                    "token_use": "access",
                    "exp": now + 3600,
                    "iat": now,
                },
                kid=self.key.kid,
                key=self.key,
            )
        return {"Authorization": f"Bearer {self.tokens[name]}"}

    def bearer(self, literal: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {literal}"}

    def close(self) -> None:
        self.storage.close()


@pytest.fixture(scope="module")
def key() -> TestKey:
    return generate_test_key("secrecy-key-1")


@pytest.fixture
def env(tmp_path: Path, key: TestKey) -> Iterator[_SecrecyEnv]:
    with JwksTestServer({"pool-a": [key]}) as server:
        built = _SecrecyEnv(tmp_path / "secrecy.sqlite", server, key)
        seed_user(built.storage, user_id="usr_owner", sub="owner-sub", email="owner@example.test")
        seed_user(
            built.storage, user_id="usr_member", sub="member-sub", email="member@example.test"
        )
        seed_user(
            built.storage,
            user_id="usr_outsider",
            sub="outsider-sub",
            email="outsider@example.test",
        )
        seed_org(built.storage, organization_id="org_team", slug="team-org")
        seed_org(built.storage, organization_id="org_outside", slug="outside-org")
        seed_org(
            built.storage,
            organization_id="org_disabled",
            slug="disabled-org",
            status=OrganizationStatus.DISABLED,
        )
        seed_membership(
            built.storage,
            organization_id="org_team",
            user_id="usr_owner",
            role=MembershipRole.OWNER,
            membership_id="mem_owner",
        )
        seed_membership(
            built.storage,
            organization_id="org_team",
            user_id="usr_member",
            role=MembershipRole.MEMBER,
            membership_id="mem_member",
        )
        seed_membership(
            built.storage,
            organization_id="org_outside",
            user_id="usr_outsider",
            role=MembershipRole.OWNER,
            membership_id="mem_outside",
        )
        # Seeded keys anchor the probe denials (no API path for these shapes).
        seed_key(
            built.storage,
            api_key_id="key_noscope",
            organization_id="org_team",
            key_id_segment=SEG_NOSCOPE,
            scopes=[READ_SCOPE],
        )
        seed_key(
            built.storage,
            api_key_id="key_outside",
            organization_id="org_outside",
            key_id_segment=SEG_OUTSIDE,
            scopes=[RUN_SCOPE],
        )
        yield built
        built.close()


# ---------------------------------------------------------------------------
# The battery (module-scoped fixture would hide the sweeps' evidence, so each
# test runs it on its own fresh environment)
# ---------------------------------------------------------------------------


def run_battery(env: _SecrecyEnv) -> dict[str, dict[str, str]]:
    """Exercise every Phase 05 HTTP outcome; return the created-key material.

    Each created key's ``{literal, secret, segment}`` is recorded so the sweeps
    can prove where it did and did not travel.
    """
    created: dict[str, dict[str, str]] = {}

    def record(label: str, literal: str) -> None:
        parsed = parse_literal(literal)
        created[label] = {
            "literal": literal,
            "secret": parsed.secret,
            "segment": parsed.key_id,
        }

    response = env.call(
        "create_live",
        "post",
        "/v1/organizations/org_team/api-keys",
        headers=env.human("owner"),
        json={"name": "ci runner", "environment": "live", "scopes": [RUN_SCOPE, READ_SCOPE]},
    )
    assert response.status_code == 201
    record("create_live", response.json()["key"])
    live_id = response.json()["id"]

    response = env.call(
        "create_test",
        "post",
        "/v1/organizations/org_team/api-keys",
        headers=env.human("owner"),
        json={"name": "sandbox", "environment": "test", "scopes": [RUN_SCOPE]},
    )
    assert response.status_code == 201
    record("create_test", response.json()["key"])

    # Reads and lifecycle.
    assert (
        env.call(
            "list", "get", "/v1/organizations/org_team/api-keys", headers=env.human("owner")
        ).status_code
        == 200
    )
    assert (
        env.call(
            "revoke_first",
            "delete",
            f"/v1/organizations/org_team/api-keys/{live_id}",
            headers=env.human("owner"),
        ).status_code
        == 204
    )
    assert (
        env.call(
            "revoke_second",
            "delete",
            f"/v1/organizations/org_team/api-keys/{live_id}",
            headers=env.human("owner"),
        ).status_code
        == 204
    )

    # Denials (human rank + tenancy + unknown org).
    env.call(
        "denied_role",
        "post",
        "/v1/organizations/org_team/api-keys",
        headers=env.human("member"),
        json={"name": "sneaky", "environment": "live", "scopes": [RUN_SCOPE]},
    )
    env.call(
        "denied_membership",
        "get",
        "/v1/organizations/org_team/api-keys",
        headers=env.human("outsider"),
    )
    env.call(
        "denied_unknown_org",
        "get",
        "/v1/organizations/org_ghost/api-keys",
        headers=env.human("owner"),
    )

    # Denials (key actors: human_only, scope, mismatch, disabled org).
    env.call(
        "denied_human_only",
        "get",
        "/v1/organizations/org_team/api-keys",
        headers=env.bearer(created["create_test"]["literal"]),
    )
    env.call(
        "denied_scope",
        "get",
        "/v1/probe/scope/org_team",
        headers=env.bearer(seed_noscope_literal()),
    )
    env.call(
        "denied_mismatch",
        "get",
        "/v1/probe/scope/org_outside",
        headers=env.bearer(created["create_test"]["literal"]),
    )
    env.call(
        "denied_inactive_org",
        "get",
        "/v1/probe/scope/org_disabled",
        headers=env.bearer(created["create_test"]["literal"]),
    )

    # Authentication failures (uniform 401 class).
    env.call(
        "auth_revoked",
        "get",
        "/v1/organizations/org_team/api-keys",
        headers=env.bearer(created["create_live"]["literal"]),
    )
    env.call(
        "auth_malformed",
        "get",
        "/v1/organizations/org_team/api-keys",
        headers=env.bearer("fn_live_" + SEG_LIVE[:20] + "_" + created["create_live"]["secret"]),
    )
    env.call(
        "auth_unknown",
        "get",
        "/v1/organizations/org_team/api-keys",
        headers=env.bearer("fn_live_" + "7" * 26 + "_" + created["create_live"]["secret"]),
    )

    # Error envelope paths.
    env.call(
        "not_found",
        "delete",
        "/v1/organizations/org_team/api-keys/key_never_issued",
        headers=env.human("owner"),
    )
    foreign_cursor = encode_cursor(CURSOR_SCOPE_MEMBERSHIPS, _T0, "mem_owner")
    env.call(
        "bad_cursor",
        "get",
        f"/v1/organizations/org_team/api-keys?cursor={foreign_cursor}",
        headers=env.human("owner"),
    )
    env.call(
        "invalid_scope",
        "post",
        "/v1/organizations/org_team/api-keys",
        headers=env.human("owner"),
        json={"name": "wildcard", "environment": "live", "scopes": ["vispector:*"]},
    )
    env.call(
        "invalid_environment",
        "post",
        "/v1/organizations/org_team/api-keys",
        headers=env.human("owner"),
        json={"name": "wrong", "environment": "staging", "scopes": []},
    )
    return created


def seed_noscope_literal() -> str:
    """Literal of the seeded read-only key (fixture-seeded, ``SEED_SECRET``)."""
    from app.auth.credentials import build_literal

    return build_literal(ApiKeyEnvironment.LIVE, SEG_NOSCOPE, SEED_SECRET)


# ---------------------------------------------------------------------------
# Sweep 1: the literal crosses into exactly one response, per key
# ---------------------------------------------------------------------------


def test_full_battery_leaks_no_credential_material(
    env: _SecrecyEnv, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    caplog.handler.setLevel(logging.DEBUG)
    created = run_battery(env)

    # Every minted/seeded secret and segment this battery can speak of.
    materials: dict[str, bytes] = {"pepper": PEPPER}
    for label, parts in created.items():
        materials[f"{label}.literal"] = parts["literal"].encode()
        materials[f"{label}.secret"] = parts["secret"].encode()
        materials[f"{label}.segment"] = parts["segment"].encode()
    materials["seeded.secret"] = SEED_SECRET.encode()
    materials["seeded.segment.noscope"] = SEG_NOSCOPE.encode()
    materials["seeded.segment.outside"] = SEG_OUTSIDE.encode()

    # (1) Response bodies: the literal appears in its own 201 and nowhere else.
    for label, body in env.bodies.items():
        segment_view = _segment_scannable(body)
        for name, material in materials.items():
            if name == "pepper":
                assert material not in body, f"{name} reached response {label!r}"
                continue
            owner = name.split(".")[0]
            if owner in {"create_live", "create_test"} and label == owner:
                continue  # the single, sanctioned crossing point
            if _is_segment_material(name):
                # Non-secret by §8: may ride masked key_prefix values only.
                assert material not in segment_view, f"{name} reached response {label!r}"
                continue
            assert material not in body, f"{name} reached response {label!r}"
    assert len(env.bodies["create_live"]) > 0
    assert materials["create_live.literal"] in env.bodies["create_live"]
    assert materials["create_test.literal"] in env.bodies["create_test"]
    # Each 201 carries only its own credential.
    assert materials["create_test.literal"] not in env.bodies["create_live"]
    assert materials["create_live.literal"] not in env.bodies["create_test"]

    # (2) Audit rows: identification and lifecycle only, never credentials.
    audit_rows = rows(env.db_path, "audit_events")
    assert audit_rows, "the battery must have audited"
    serialized_audits = json.dumps(audit_rows)
    for name, material in materials.items():
        assert material not in serialized_audits.encode(), f"{name} reached audit metadata"
    for token in env.tokens.values():
        assert token not in serialized_audits, "a JWT reached an audit row"
    assert "bearer" not in serialized_audits.lower()
    assert "eyJ" not in serialized_audits

    # (3) Log records: the service emits nothing at all on these paths, and no
    # record (app or library) carries credential material.
    app_records = [record for record in caplog.records if record.name.startswith("app")]
    assert app_records == [], "feednow-auth must not log on key paths"
    captured = caplog.text  # the fully formatted report, exception blocks included
    for name, material in materials.items():
        assert material.decode() not in captured, f"{name} reached the log"

    # (4) Persisted key rows: only the peppered HMAC is derived material.
    key_rows = rows(env.db_path, "api_keys")
    for row in key_rows:
        for name, material in materials.items():
            if _is_segment_material(name):
                continue  # key_id/key_prefix legitimately carry the segment
            assert material not in json.dumps(row).encode(), f"{name} reached an api_keys row"
        assert len(row["secret_hash"]) == 64
        assert row["secret_hash"] == row["secret_hash"].lower()
        # The segment lives in exactly the two columns §8 designed it into.
        segment = row["key_id"]
        for column, value in row.items():
            if column in {"key_id", "key_prefix"}:
                continue
            assert segment not in str(value), f"segment leaked into api_keys.{column}"

    # (5) Raw database files — the main file **and** the WAL/shm sidecars the
    # adapter keeps open (journal_mode=WAL, so recent writes, including the
    # pre-revoke row versions, live in the -wal file until checkpoint): no
    # plaintext, no pepper, anywhere in the file set.
    db_files = sorted(env.db_path.parent.glob(f"{env.db_path.name}*"))
    assert db_files, "the SQLite file set must exist while the battery runs"
    raw = b"".join(path.read_bytes() for path in db_files)
    # Positive control: the scan above is not vacuous — the segments really
    # are present in the persisted file set (that is where they live).
    assert any(
        material in raw for name, material in materials.items() if _is_segment_material(name)
    ), "the file-set scan saw no persisted key material at all"
    for name, material in materials.items():
        if _is_segment_material(name):
            continue  # legitimately persisted in api_keys.key_id
        assert material not in raw, f"{name} reached the database files"


# ---------------------------------------------------------------------------
# Sweep 2: §16 vocabulary and pinned metadata for the Phase 05 battery
# ---------------------------------------------------------------------------


def test_battery_audits_stay_in_vocabulary_with_pinned_metadata(
    env: _SecrecyEnv,
) -> None:
    created = run_battery(env)
    audit_rows = rows(env.db_path, "audit_events")
    actions = {row["action"] for row in audit_rows}
    assert actions <= _SPEC_16_ACTIONS, f"off-vocabulary actions: {actions - _SPEC_16_ACTIONS}"
    assert actions == {
        "api_key.created",
        "api_key.revoked",
        "authorization.denied",
    }
    for row in audit_rows:
        metadata = json.loads(row["metadata"])
        assert set(metadata) == _PINNED_METADATA_KEYS[row["action"]], row
        assert str(row["organization_id"]).startswith("org_")
        # Actor identity/type agreement for both actor kinds (decision 7).
        if row["actor_type"] == "user":
            assert str(row["actor_id"]).startswith("usr_")
        else:
            assert row["actor_type"] == "api_key"
            assert str(row["actor_id"]).startswith("key_")

    created_rows = [row for row in audit_rows if row["action"] == "api_key.created"]
    assert len(created_rows) == 2
    assert all(str(row["target_id"]).startswith("key_") for row in created_rows)
    assert {json.loads(row["metadata"])["environment"] for row in created_rows} == {
        "live",
        "test",
    }
    assert json.loads(created_rows[0]["metadata"])["scopes"] == [READ_SCOPE, RUN_SCOPE]
    assert json.loads(created_rows[1]["metadata"])["scopes"] == [RUN_SCOPE]
    assert all(row["actor_type"] == "user" for row in created_rows)

    revoked_rows = [row for row in audit_rows if row["action"] == "api_key.revoked"]
    assert len(revoked_rows) == 2  # duplicate revoke: one truthful audit each
    # Decision 10: ``api_key.revoked`` metadata is exactly ``{}`` — the action
    # and target are the whole record (checked as dicts; sets cannot hold one).
    assert [json.loads(row["metadata"]) for row in revoked_rows] == [{}, {}]

    denial_meta = [
        json.loads(row["metadata"]) for row in audit_rows if row["action"] == "authorization.denied"
    ]
    reasons = {item["reason"] for item in denial_meta}
    assert reasons <= _DENIAL_REASONS
    assert reasons == {
        "insufficient_role",
        "no_membership",
        "human_only",
        "insufficient_scope",
        "organization_mismatch",
        "inactive_organization",
    }
    # Unknown organization: the §16 structural exception — no FK target, so
    # provably no row for it (the denial still answered 403).
    assert all(row["organization_id"] != "org_ghost" for row in audit_rows)
    # Every denial operation is a real route operation id, and the key-actor
    # denials are audited under the key identity, never a borrowed usr_.
    key_denials = [
        row
        for row in audit_rows
        if row["action"] == "authorization.denied" and row["actor_type"] == "api_key"
    ]
    assert {json.loads(row["metadata"])["reason"] for row in key_denials} == {
        "human_only",
        "insufficient_scope",
        "organization_mismatch",
        "inactive_organization",
    }
    # The ``insufficient_scope`` denial belongs to the seeded read-only key;
    # the other three to the battery's freshly minted ``test`` key.
    test_key_id = next(
        row["target_id"]
        for row in created_rows
        if json.loads(row["metadata"])["environment"] == "test"
    )
    assert {row["actor_id"] for row in key_denials} == {"key_noscope", test_key_id}
    assert created["create_live"]["literal"] not in json.dumps(audit_rows)


# ---------------------------------------------------------------------------
# Sweep 3: every error body is a frozen envelope with a fixed, safe message
# ---------------------------------------------------------------------------


def test_every_error_body_uses_the_frozen_envelope_and_echoes_nothing(
    env: _SecrecyEnv,
) -> None:
    created = run_battery(env)
    statuses = {
        "denied_role": 403,
        "denied_membership": 403,
        "denied_unknown_org": 403,
        "denied_human_only": 403,
        "denied_scope": 403,
        "denied_mismatch": 403,
        "denied_inactive_org": 403,
        "auth_revoked": 401,
        "auth_malformed": 401,
        "auth_unknown": 401,
        "not_found": 404,
        "bad_cursor": 400,
        "invalid_scope": 422,
        "invalid_environment": 422,
    }
    assert set(statuses) <= set(env.bodies)
    for label, status in statuses.items():
        body = env.bodies[label]
        envelope = Error.model_validate(json.loads(body))
        assert envelope.code in {
            "forbidden",
            "unauthenticated",
            "not_found",
            "validation_error",
            "conflict",
        }, label
        assert status in {400, 401, 403, 404, 422}, label
        # No submitted credential material rides any message.
        for parts in created.values():
            assert parts["literal"].encode() not in body, label
            assert parts["secret"].encode() not in body, label
            assert parts["segment"].encode() not in body, label
        assert PEPPER not in body, label
    # The 403 class is one byte-identical body across all seven denials, and
    # the 401 class across all three auth failures (no per-branch message).
    forbidden = {env.bodies[label] for label in statuses if statuses[label] == 403}
    assert len(forbidden) == 1
    unauthenticated = {env.bodies[label] for label in statuses if statuses[label] == 401}
    assert len(unauthenticated) == 1
    # The 422 handler never echoes the submitted value (only the field path).
    assert b"vispector:*" not in env.bodies["invalid_scope"]
    assert b"staging" not in env.bodies["invalid_environment"]


# ---------------------------------------------------------------------------
# Sweep 4: cursor round-trip bodies stay masked (list is the read surface)
# ---------------------------------------------------------------------------


def test_paged_list_bodies_carry_only_masked_prefixes(env: _SecrecyEnv) -> None:
    created = run_battery(env)
    headers = env.human("owner")
    first = env.client.get("/v1/organizations/org_team/api-keys?limit=1", headers=headers)
    assert first.status_code == 200
    page = first.json()
    assert page["limit"] == 1
    assert page["next_cursor"] is not None
    second = env.client.get(
        f"/v1/organizations/org_team/api-keys?limit=1&cursor={page['next_cursor']}", headers=headers
    )
    assert second.status_code == 200
    seen = json.dumps(first.json()) + json.dumps(second.json())
    stripped = json.dumps(_without_key_prefixes(first.json())) + json.dumps(
        _without_key_prefixes(second.json())
    )
    for parts in created.values():
        assert parts["literal"] not in seen
        assert parts["secret"] not in seen
        # The segment rides masked prefixes only (decision 2).
        assert parts["segment"] not in stripped
    for item in first.json()["items"] + second.json()["items"]:
        assert item["key_prefix"].endswith("...")
        assert "secret_hash" not in item
        # Per item: no field other than the masked prefix carries any segment.
        for field_name, value in item.items():
            if field_name == "key_prefix":
                continue
            for parts in created.values():
                assert parts["segment"] not in str(value), f"{field_name} carries a segment"
