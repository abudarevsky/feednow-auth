"""Verification-matrix acceptance proofs over HTTP (Phase 05 task 7, part b).

The decision-4 pipeline proven in task 3's unit suite, now exercised through
the **real HTTP seam**: a probe route mounted with
:func:`~app.auth.organization_access.build_organization_scope_dependency`
(probe routers live in the test module per decision 12 — the shipped routers
register manifest entries only, and the scope dependency is the Phase 06/07/08
product seam this matrix certifies).

Every authentication failure case answers the **one uniform 401**
(``unauthenticated`` + :data:`~app.auth.api_key_auth.API_KEY_AUTHENTICATION_MESSAGE`)
with a **byte-identical body**, and provably:

- mutates nothing (a recording storage proxy counts every protocol write and a
  direct SQLite dump compares the full ``api_keys``/``audit_events`` contents
  before and after each request);
- appends zero audit rows (decision 12: auth failures are not
  ``authorization.denied`` and §16 requires no auth-failure event);
- echoes no key-id/secret/pepper fragment.

Cases: malformed-each-way (bad shape, empty segments, oversized, invalid
Crockford chars), unknown key-id, wrong secret (single-character change),
environment skew (stored ``live``, presented ``test``), revoked, expired
(seeded ``expires_at`` in the past — no API path sets expiry, decision 9),
plus the 200 anchors (active key, and an active key with a future expiry —
which also proves verification is **read-only**: no ``last_used_at`` write).
The dispatch boundary stays a separate class on purpose: a bearer that never
looks like a credential (``fn_prod_…`` / ``eyJ…``) is not sent to the key seam
at all (zero point lookups recorded) and answers the Phase 03 JWT 401 — same
status and code, different fixed message, which is decision 6's pinned
boundary rather than an oracle inside the key class.
"""

# No ``from __future__ import annotations`` here on purpose (the ``keys.py``
# precedent): the probe handler's ``Annotated[..., Depends(scope_dep)]``
# references a closure local that PEP 563 stringification could not resolve,
# which would silently turn the access dependency into a required query param.

import sqlite3
import time
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient
from support.cognito import JwksTestServer, TestKey, generate_test_key, sign_token

from app.api.keys import build_api_keys_router
from app.auth.api_key_auth import API_KEY_AUTHENTICATION_MESSAGE
from app.auth.cognito import CognitoAccessTokenVerifier
from app.auth.credentials import build_literal, hash_secret
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
from app.storage.sqlite import SQLiteStorage

ALLOWED_CLIENT = "matrix-app-client"
_T0 = datetime(2026, 9, 14, 12, 0, 0, tzinfo=UTC)

# Same fixed 32-byte test pepper as the task-1..6 suites (never production).
PEPPER = b"integration-matrix-pepper-0123456789ab"  # 38 bytes, never production

RUN_SCOPE = "vispector:inspection:run"
READ_SCOPE = "vispector:inspection:read"

# 26-char Crockford segments (underscore-free by charset, decision 2).
SEG_VALID = "01JXYZ7KA20MB63PCQ8VNDWFTG"
SEG_REVOKED = "01JXYZ7KA20MB63PCQ8VNDWFTH"
SEG_EXPIRED = "01JXYZ7KA20MB63PCQ8VNDWFTJ"
SEG_FUTURE = "01JXYZ7KA20MB63PCQ8VNDWFTK"
SEG_NOSCOPE = "01JXYZ7KA20MB63PCQ8VNDWFTM"
SEG_UNKNOWN = "01JXYZ7KA20MB63PCQ8VNDWZZZ"  # well-formed, never seeded
SECRET = "aE-W-K9J0KCdH1pnlK_BGZGEcs8xWSr3tTiSKGVPFXo"
#: Single-character change of ``SECRET``: a wrong secret that is otherwise a
#: perfectly shaped 43-char base64url string.
WRONG_SECRET = SECRET[:-1] + ("A" if SECRET[-1] != "A" else "B")

#: Probe wiring (task-5 seam): ``run_inspection`` is a product operation id,
#: never a manifest management entry.
PROBE_SCOPE = RUN_SCOPE
PROBE_OPERATION = "run_inspection"

#: The frozen §8 point-lookup segment must never ride a response body.
CREDENTIAL_MATERIAL = (SECRET.encode(), PEPPER, SEG_VALID.encode(), SEG_UNKNOWN.encode())


# ---------------------------------------------------------------------------
# Recording storage: every protocol write is counted (zero-mutation proofs)
# ---------------------------------------------------------------------------


class RecordingStorage:
    """Delegates to real SQLite while counting §12 writes and §8 lookups.

    ``__getattr__`` forwards everything else verbatim, so the app under test
    sees the complete contract; only the mutating methods and the credential
    point lookup are wrapped — exactly what "authentication mutates nothing"
    and "format failure precedes any storage read" need to be observable.
    """

    def __init__(self, inner: SQLiteStorage) -> None:
        self._inner = inner
        self.writes: Counter[str] = Counter()
        self.key_lookups = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def create_api_key(self, api_key: ApiKey) -> ApiKey:
        self.writes["create_api_key"] += 1
        return self._inner.create_api_key(api_key)

    def revoke_api_key(self, api_key_id: ApiKeyId, *, revoked_at: datetime) -> ApiKey:
        self.writes["revoke_api_key"] += 1
        return self._inner.revoke_api_key(api_key_id, revoked_at=revoked_at)

    def append_audit_event(self, audit_event: Any) -> None:
        self.writes["append_audit_event"] += 1
        self._inner.append_audit_event(audit_event)

    def get_api_key_by_key_id(self, key_id: str) -> ApiKey:
        self.key_lookups += 1
        return self._inner.get_api_key_by_key_id(key_id)

    def close(self) -> None:
        self._inner.close()


# ---------------------------------------------------------------------------
# Direct-read helpers
# ---------------------------------------------------------------------------


def table_dump(db_path: Path, table: str) -> list[tuple[Any, ...]]:
    """Full verbatim contents of one table, for before/after equality."""
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()
    finally:
        conn.close()


def seed_key(
    storage: SQLiteStorage,
    *,
    api_key_id: str,
    key_id_segment: str,
    scopes: list[str],
    organization_id: str = "org_team",
    environment: ApiKeyEnvironment = ApiKeyEnvironment.LIVE,
    status: ApiKeyStatus = ApiKeyStatus.ACTIVE,
    revoked_at: datetime | None = None,
    expires_at: datetime | None = None,
    secret: str = SECRET,
) -> None:
    """Write one complete key row with the peppered HMAC of ``secret``."""
    storage.create_api_key(
        ApiKey(
            id=ApiKeyId(api_key_id),
            organization_id=OrganizationId(organization_id),
            created_by_user_id=UserId("usr_owner"),
            name=f"seeded {api_key_id}",
            key_id=key_id_segment,
            key_prefix=build_key_prefix(environment, key_id_segment, secret),
            secret_hash=hash_secret(PEPPER, secret),
            environment=environment,
            scopes=scopes,
            status=status,
            created_at=_T0,
            revoked_at=revoked_at,
            expires_at=expires_at,
        )
    )


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------


@dataclass
class ProbeOutcome:
    """One probe request plus the mutation/lookup evidence around it."""

    response: Any
    lookups: int
    writes: int
    keys_unchanged: bool
    audits_unchanged: bool
    audit_rows: list[dict[str, Any]] = field(default_factory=list)


class _MatrixEnv:
    """Keys router + a scope-probe route, real SQLite, signed human tokens."""

    def __init__(self, db_path: Path, server: JwksTestServer, key: TestKey) -> None:
        self.db_path = db_path
        self.inner = SQLiteStorage(db_path)
        self.storage = RecordingStorage(self.inner)
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
            """Reached only when authentication *and* authorization pass."""
            return {"actor": str(access.principal.context.actor_id)}

        probe.add_api_route("/v1/probe/scope/{organization_id}", scope_probe, methods=["GET"])
        app = create_app(
            routers=[build_api_keys_router(self.storage, verifier, self.pepper), probe]
        )
        self.client = TestClient(app, raise_server_exceptions=False)
        self.issuer = issuer
        self.key = key

    def seed_cast(self) -> None:
        """One seeded user + org so the human dispatch path has a real target."""
        self.inner.create_user(
            User(
                id=UserId("usr_owner"),
                display_name="seed owner",
                email="owner@example.test",
                status=UserStatus.ACTIVE,
                created_at=_T0,
                updated_at=_T0,
            )
        )
        self.inner.create_external_identity(
            ExternalIdentity(
                id=ExternalIdentityId("extid_owner"),
                user_id=UserId("usr_owner"),
                provider=IdentityProvider.COGNITO,
                provider_subject="owner-sub",
                provider_tenant=None,
                created_at=_T0,
            )
        )
        self.inner.create_organization(
            Organization(
                id=OrganizationId("org_team"),
                name="seed org_team",
                slug="team-org",
                type=OrganizationType.CUSTOMER,
                status=OrganizationStatus.ACTIVE,
                created_at=_T0,
                updated_at=_T0,
            )
        )
        self.inner.create_membership(
            Membership(
                id=MembershipId("mem_owner"),
                organization_id=OrganizationId("org_team"),
                user_id=UserId("usr_owner"),
                role=MembershipRole.OWNER,
                status="active",
                created_at=_T0,
            )
        )

    def token(self, sub: str, email: str) -> str:
        now = int(time.time())
        return sign_token(
            {
                "sub": sub,
                "email": email,
                "username": f"user-{sub}",
                "client_id": ALLOWED_CLIENT,
                "iss": self.issuer,
                "token_use": "access",
                "exp": now + 3600,
                "iat": now,
            },
            kid=self.key.kid,
            key=self.key,
        )

    def auth(self, bearer: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {bearer}"}

    def probe(self, bearer: str, organization_id: str = "org_team") -> ProbeOutcome:
        """Fire one probe request and capture the surrounding evidence."""
        self.storage.key_lookups = 0
        writes_before = sum(self.storage.writes.values())
        keys_before = table_dump(self.db_path, "api_keys")
        audits_before = table_dump(self.db_path, "audit_events")
        response = self.client.get(f"/v1/probe/scope/{organization_id}", headers=self.auth(bearer))
        return ProbeOutcome(
            response=response,
            lookups=self.storage.key_lookups,
            writes=sum(self.storage.writes.values()) - writes_before,
            keys_unchanged=table_dump(self.db_path, "api_keys") == keys_before,
            audits_unchanged=table_dump(self.db_path, "audit_events") == audits_before,
            audit_rows=_audit_rows(self.db_path),
        )

    def close(self) -> None:
        self.storage.close()


def _audit_rows(db_path: Path) -> list[dict[str, Any]]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in conn.execute("SELECT * FROM audit_events").fetchall()]
    finally:
        conn.close()


@pytest.fixture(scope="module")
def key() -> TestKey:
    return generate_test_key("matrix-key-1")


@pytest.fixture
def env(tmp_path: Path, key: TestKey) -> Iterator[_MatrixEnv]:
    with JwksTestServer({"pool-a": [key]}) as server:
        built = _MatrixEnv(tmp_path / "auth_matrix.sqlite", server, key)
        built.seed_cast()
        now = datetime.now(UTC)
        seed_key(
            built.inner,
            api_key_id="key_valid",
            key_id_segment=SEG_VALID,
            scopes=[RUN_SCOPE],
        )
        seed_key(
            built.inner,
            api_key_id="key_future",
            key_id_segment=SEG_FUTURE,
            scopes=[RUN_SCOPE],
            expires_at=now + timedelta(hours=1),
        )
        seed_key(
            built.inner,
            api_key_id="key_revoked",
            key_id_segment=SEG_REVOKED,
            scopes=[RUN_SCOPE],
            status=ApiKeyStatus.REVOKED,
            revoked_at=_T0 + timedelta(minutes=5),
        )
        seed_key(
            built.inner,
            api_key_id="key_expired",
            key_id_segment=SEG_EXPIRED,
            scopes=[RUN_SCOPE],
            expires_at=now - timedelta(minutes=5),
        )
        seed_key(
            built.inner,
            api_key_id="key_noscope",
            key_id_segment=SEG_NOSCOPE,
            scopes=[READ_SCOPE],
        )
        yield built
        built.close()


# ---------------------------------------------------------------------------
# 200 anchors (the negative cases below must differ from these, not from each
# other)
# ---------------------------------------------------------------------------


def test_valid_key_grants_probe_and_writes_nothing(env: _MatrixEnv) -> None:
    literal = build_literal(ApiKeyEnvironment.LIVE, SEG_VALID, SECRET)
    outcome = env.probe(literal)
    assert outcome.response.status_code == 200
    assert outcome.response.json() == {"actor": "key_valid"}
    # Authentication resolved the key through exactly one §8 point lookup...
    assert outcome.lookups == 1
    # ...and the whole request is read-only: no audit, no row rewrite (the
    # documented ``last_used_at`` limitation — no write path exists).
    assert outcome.writes == 0
    assert outcome.keys_unchanged
    assert outcome.audits_unchanged
    assert outcome.audit_rows == []


def test_key_with_future_expiry_still_grants(env: _MatrixEnv) -> None:
    literal = build_literal(ApiKeyEnvironment.LIVE, SEG_FUTURE, SECRET)
    outcome = env.probe(literal)
    assert outcome.response.status_code == 200
    assert outcome.writes == 0
    assert outcome.audit_rows == []


def test_authenticated_key_without_required_scope_is_403_not_401(env: _MatrixEnv) -> None:
    # The class boundary: authentication succeeded (one lookup, no 401), the
    # scope denial is the uniform audited 403 (decision 6).
    literal = build_literal(ApiKeyEnvironment.LIVE, SEG_NOSCOPE, SECRET)
    outcome = env.probe(literal)
    assert outcome.response.status_code == 403
    assert Error.model_validate(outcome.response.json()).code == "forbidden"
    assert [row["action"] for row in outcome.audit_rows] == ["authorization.denied"]
    assert outcome.keys_unchanged


# ---------------------------------------------------------------------------
# The decision-4 matrix: one byte-identical 401, zero mutation, zero audit
# ---------------------------------------------------------------------------


def _malformed_literals() -> list[tuple[str, str]]:
    """Every shape violation, still ``fn_``-prefixed so it reaches the seam."""
    return [
        ("key_id_too_short", f"fn_live_{SEG_VALID[:25]}_{SECRET}"),
        ("key_id_too_long", f"fn_live_{SEG_VALID}X_{SECRET}"),
        ("key_id_empty", f"fn_live__{SECRET}"),
        ("secret_empty", f"fn_live_{SEG_VALID}_"),
        ("separator_missing", f"fn_live_{SEG_VALID}"),
        (
            "key_id_invalid_crockford",
            f"fn_live_{'I' * 26}_{SECRET}",
        ),  # I/L/O/U excluded from the alphabet
        ("key_id_lowercase", f"fn_live_{SEG_VALID.lower()}_{SECRET}"),
        ("oversized_literal", f"fn_live_{SEG_VALID}_" + "a" * 600),
        ("empty_bearer", "fn_live_"),
    ]


@pytest.mark.parametrize(
    "literal",
    [pytest.param(lit, id=name) for name, lit in _malformed_literals()],
)
def test_malformed_credentials_answer_the_uniform_401(env: _MatrixEnv, literal: str) -> None:
    outcome = env.probe(literal)
    assert outcome.response.status_code == 401
    envelope = Error.model_validate(outcome.response.json())
    assert envelope.code == "unauthenticated"
    assert envelope.message == API_KEY_AUTHENTICATION_MESSAGE
    # Format failure precedes any storage touch (decision 4 step (a)).
    assert outcome.lookups == 0
    assert outcome.writes == 0
    assert outcome.keys_unchanged
    assert outcome.audits_unchanged
    assert outcome.audit_rows == []


def test_unknown_key_id_wrong_secret_and_lifecycle_states_share_one_401(
    env: _MatrixEnv,
) -> None:
    cases = {
        "unknown_key_id": build_literal(ApiKeyEnvironment.LIVE, SEG_UNKNOWN, SECRET),
        "wrong_secret": build_literal(ApiKeyEnvironment.LIVE, SEG_VALID, WRONG_SECRET),
        "env_prefix_mismatch": build_literal(ApiKeyEnvironment.TEST, SEG_VALID, SECRET),
        "revoked": build_literal(ApiKeyEnvironment.LIVE, SEG_REVOKED, SECRET),
        "expired": build_literal(ApiKeyEnvironment.LIVE, SEG_EXPIRED, SECRET),
    }
    outcomes = {name: env.probe(literal) for name, literal in cases.items()}
    assert [o.response.status_code for o in outcomes.values()] == [401] * len(cases)
    # Oracle-freedom on the message axis: one byte-identical body everywhere.
    bodies = {name: o.response.content for name, o in outcomes.items()}
    assert len(set(bodies.values())) == 1, bodies
    for name, outcome in outcomes.items():
        envelope = Error.model_validate(outcome.response.json())
        assert envelope.code == "unauthenticated", name
        assert envelope.message == API_KEY_AUTHENTICATION_MESSAGE, name
        # Each case reached the seam (one point lookup) and mutated nothing.
        assert outcome.lookups == 1, name
        assert outcome.writes == 0, name
        assert outcome.keys_unchanged, name
        assert outcome.audits_unchanged, name
        assert outcome.audit_rows == [], name
    # No credential fragment rides any body.
    for material in CREDENTIAL_MATERIAL:
        assert material not in outcomes["unknown_key_id"].response.content
        assert material not in outcomes["wrong_secret"].response.content


def test_malformed_and_lifecycle_failures_are_indistinguishable(env: _MatrixEnv) -> None:
    # The whole failure set — shape, unknown, wrong secret, skew, revoked,
    # expired — collapses to one body: nothing distinguishes *which* segment
    # or *which* lifecycle check failed (AC 2).
    failing = [lit for _name, lit in _malformed_literals()] + [
        build_literal(ApiKeyEnvironment.LIVE, SEG_UNKNOWN, SECRET),
        build_literal(ApiKeyEnvironment.LIVE, SEG_VALID, WRONG_SECRET),
        build_literal(ApiKeyEnvironment.TEST, SEG_VALID, SECRET),
        build_literal(ApiKeyEnvironment.LIVE, SEG_REVOKED, SECRET),
        build_literal(ApiKeyEnvironment.LIVE, SEG_EXPIRED, SECRET),
    ]
    contents = {env.probe(literal).response.content for literal in failing}
    assert len(contents) == 1, contents


def test_management_routes_answer_the_same_uniform_401(env: _MatrixEnv) -> None:
    # Same authentication class on the *shipped* routes (pepper wired, so key
    # bearers dispatch to the seam rather than the JWT path).
    revoked = build_literal(ApiKeyEnvironment.LIVE, SEG_REVOKED, SECRET)
    malformed = f"fn_live_{SEG_VALID[:20]}_{SECRET}"
    responses = [
        env.client.get("/v1/organizations/org_team/api-keys", headers=env.auth(revoked)),
        env.client.get("/v1/organizations/org_team/api-keys", headers=env.auth(malformed)),
        env.client.post(
            "/v1/organizations/org_team/api-keys",
            headers=env.auth(revoked),
            json={"name": "nope", "environment": "live", "scopes": [RUN_SCOPE]},
        ),
        env.client.delete(
            "/v1/organizations/org_team/api-keys/key_valid", headers=env.auth(revoked)
        ),
    ]
    assert [response.status_code for response in responses] == [401] * 4
    assert len({response.content for response in responses}) == 1
    envelope = Error.model_validate(responses[0].json())
    assert envelope.code == "unauthenticated"
    assert envelope.message == API_KEY_AUTHENTICATION_MESSAGE
    # Zero mutation and zero audit across all four 401s.
    assert env.storage.writes == {}
    assert _audit_rows(env.db_path) == []


# ---------------------------------------------------------------------------
# Dispatch boundary: non-key bearers never reach the credential seam
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bearer",
    [
        pytest.param("fn_prod_" + SEG_VALID + "_" + SECRET, id="unknown_environment"),
        pytest.param("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fake.signature", id="jwt_shaped"),
        pytest.param(SEG_VALID + "_" + SECRET, id="prefix_missing"),
    ],
)
def test_non_key_bearers_skip_the_credential_seam(env: _MatrixEnv, bearer: str) -> None:
    outcome = env.probe(bearer)
    assert outcome.response.status_code == 401
    envelope = Error.model_validate(outcome.response.json())
    assert envelope.code == "unauthenticated"
    # The Phase 03 JWT class, not the key class: same status/code, and the
    # key seam provably never ran (zero §8 lookups, zero writes, zero audits).
    assert envelope.message != API_KEY_AUTHENTICATION_MESSAGE
    assert outcome.lookups == 0
    assert outcome.writes == 0
    assert outcome.audit_rows == []
