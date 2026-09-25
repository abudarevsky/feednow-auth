"""Unit proofs for internal JWT generation and application-role validation.

The module under test (``src/app/auth/tokens.py``) is proven with real
PyJWT round trips on both halves:

1. Round trip: ``issue`` mints an ``HS256`` JWT whose registered claims are
   the configured ``iss``/``aud``, the internal ``usr_`` ``sub``, and
   ``exp = iat + ttl`` with a fresh ``jti``; ``JwtTokenVerifier.verify``
   accepts exactly those tokens and projects typed claims.
2. Role-based claims: ``application_role`` mirrors the user's global
   :class:`ApplicationRole`; ``roles`` carries the caller-supplied
   organization-local :class:`MembershipRole` values deduplicated and in
   declaration order; the two vocabularies never mix (an
   ``ApplicationRole.ADMIN`` is rejected as a membership role) — and on the
   verification side **application roles are validated, never trusted**:
   anything outside the closed vocabularies rejects with a fixed reason.
3. Identity/secrecy in claims: email, display name, and provider material
   never appear in the token; the pinned ``alg`` is always ``HS256``;
   forgeries (wrong key, foreign algorithm/issuer/audience, expiry) reject.
4. Constructor validation: short/blank/zero-ttl/bad-leeway config fails fast
   with fixed messages that echo no key material; a wrong key cannot decode.
5. Secrecy: the module imports no logging (AST proof) and emits zero log
   records across issuance and verification (caplog proof), like the
   session module.
"""

from __future__ import annotations

import ast
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

import jwt
import pytest

import app.auth.tokens as tokens_module
from app.auth.errors import TokenValidationError
from app.auth.tokens import (
    APPLICATION_ROLE_CLAIM,
    APPLICATION_ROLE_CLAIM_INVALID_MESSAGE,
    APPLICATION_ROLE_CLAIM_MISSING_MESSAGE,
    AUDIENCE_CLAIM_MESSAGE,
    AUDIENCE_MESSAGE,
    DEFAULT_JWT_LEEWAY_SECONDS,
    DEFAULT_JWT_TTL_SECONDS,
    ISSUER_CLAIM_MESSAGE,
    ISSUER_MESSAGE,
    JWT_ALGORITHM,
    LEEWAY_MESSAGE,
    MEMBERSHIP_ROLES_MESSAGE,
    ROLES_CLAIM,
    ROLES_CLAIM_INVALID_MESSAGE,
    ROLES_CLAIM_MISSING_MESSAGE,
    SIGNING_KEY_TOO_SHORT_MESSAGE,
    TOKEN_ALGORITHM_MESSAGE,
    TOKEN_EXPIRED_MESSAGE,
    TOKEN_MALFORMED_MESSAGE,
    TOKEN_SIGNATURE_MESSAGE,
    TOKEN_TYPE_MESSAGE,
    TTL_MESSAGE,
    USER_TYPE_MESSAGE,
    JwtClaims,
    JwtTokenIssuer,
    JwtTokenVerifier,
)
from app.models.enums import ApplicationRole, MembershipRole, UserStatus
from app.models.ids import UserId
from app.models.user import User

SIGNING_KEY: Final = "unit-test-signing-key-0123456789abcdef-32b+"
OTHER_KEY: Final = "a-completely-different-signing-key-xyz"
ISSUER: Final = "https://auth.feednow.test"
AUDIENCE: Final = "feednow-api"

_NOW: Final = datetime(2026, 9, 24, 12, 0, 0, tzinfo=UTC)


def _user(role: ApplicationRole = ApplicationRole.USER) -> User:
    return User(
        id=UserId("usr_token_owner"),
        display_name="Token Owner",
        email="owner@example.com",
        status=UserStatus.ACTIVE,
        application_role=role,
        created_at=_NOW,
        updated_at=_NOW,
    )


def _issuer(ttl_seconds: int = DEFAULT_JWT_TTL_SECONDS) -> JwtTokenIssuer:
    return JwtTokenIssuer(
        signing_key=SIGNING_KEY,
        issuer=ISSUER,
        audience=AUDIENCE,
        ttl_seconds=ttl_seconds,
    )


def _decode(token: str, key: str = SIGNING_KEY) -> dict[str, object]:
    return jwt.decode(token, key, algorithms=[JWT_ALGORITHM], audience=AUDIENCE)


# ---------------------------------------------------------------------------
# 1. Round trip: registered claims
# ---------------------------------------------------------------------------


def test_issue_round_trips_with_expected_registered_claims() -> None:
    issuer = _issuer()
    before = int(datetime.now(UTC).timestamp())
    token = issuer.issue(_user())
    claims = _decode(token)

    assert claims["sub"] == "usr_token_owner"
    assert claims["iss"] == ISSUER
    assert claims["aud"] == AUDIENCE
    assert isinstance(claims["jti"], str) and claims["jti"]
    iat, exp = claims["iat"], claims["exp"]
    assert isinstance(iat, int) and isinstance(exp, int)
    assert before <= iat <= before + 5
    assert exp - iat == DEFAULT_JWT_TTL_SECONDS


def test_issue_pins_hs256_in_the_header() -> None:
    token = _issuer().issue(_user())
    assert jwt.get_unverified_header(token)["alg"] == JWT_ALGORITHM


def test_issue_mints_distinct_tokens_and_jtis() -> None:
    issuer = _issuer()
    tokens = [issuer.issue(_user()) for _ in range(10)]
    assert len(set(tokens)) == 10
    assert len({_decode(token)["jti"] for token in tokens}) == 10


def test_issue_honors_configured_ttl() -> None:
    claims = _decode(_issuer(ttl_seconds=60).issue(_user()))
    assert claims["exp"] - claims["iat"] == 60


def test_decoding_with_the_wrong_key_fails() -> None:
    token = _issuer().issue(_user())
    with pytest.raises(jwt.InvalidSignatureError):
        _decode(token, key=OTHER_KEY)


# ---------------------------------------------------------------------------
# 2. Role-based claims
# ---------------------------------------------------------------------------


def test_default_token_carries_user_application_role_and_no_membership_roles() -> None:
    claims = _decode(_issuer().issue(_user()))
    assert claims[APPLICATION_ROLE_CLAIM] == "user"
    assert claims[ROLES_CLAIM] == []


def test_admin_application_role_is_claimed_verbatim() -> None:
    claims = _decode(_issuer().issue(_user(ApplicationRole.ADMIN)))
    assert claims[APPLICATION_ROLE_CLAIM] == "admin"
    # The global role never leaks into the organization-local claim.
    assert claims[ROLES_CLAIM] == []


def test_membership_roles_claim_is_deduplicated_in_declaration_order() -> None:
    token = _issuer().issue(
        _user(),
        membership_roles=[
            MembershipRole.VIEWER,
            MembershipRole.MEMBER,
            MembershipRole.OWNER,
            MembershipRole.MEMBER,
        ],
    )
    claims = _decode(token)
    assert claims[ROLES_CLAIM] == ["owner", "member", "viewer"]
    # The user's global role stays independent of the supplied membership set.
    assert claims[APPLICATION_ROLE_CLAIM] == "user"


def test_exact_membership_role_strings_are_accepted_like_build_literal() -> None:
    claims = _decode(_issuer().issue(_user(), membership_roles=["admin"]))
    assert claims[ROLES_CLAIM] == ["admin"]


@pytest.mark.parametrize("foreign", [ApplicationRole.ADMIN, ApplicationRole.USER, "superadmin"])
def test_membership_roles_reject_foreign_values_with_fixed_message(foreign: object) -> None:
    # ApplicationRole members are str subclasses whose values collide with
    # MembershipRole ("admin") — they must never coerce across the boundary
    # (spec 12 invariant 1); unknown strings fail the same way.
    with pytest.raises(ValueError) as excinfo:
        _issuer().issue(_user(), membership_roles=[foreign])  # type: ignore[list-item]
    assert str(excinfo.value) == MEMBERSHIP_ROLES_MESSAGE


# ---------------------------------------------------------------------------
# 3. Identity and secrecy of claims
# ---------------------------------------------------------------------------


def test_token_never_carries_email_display_name_or_provider_material() -> None:
    user = _user()
    token = _issuer().issue(user)
    claims = _decode(token)
    assert claims["sub"] == str(user.id)
    for forbidden in (user.email, user.display_name):
        assert forbidden not in token
        assert forbidden not in str(claims)


# ---------------------------------------------------------------------------
# 4. Constructor validation (fixed, input-free messages)
# ---------------------------------------------------------------------------


def test_construction_accepts_bytes_keys_and_exposes_config() -> None:
    issuer = JwtTokenIssuer(
        signing_key=SIGNING_KEY.encode("utf-8"),
        issuer=ISSUER,
        audience=AUDIENCE,
    )
    assert issuer.issuer == ISSUER
    assert issuer.audience == AUDIENCE
    assert issuer.ttl_seconds == DEFAULT_JWT_TTL_SECONDS
    assert _decode(issuer.issue(_user()))["sub"] == "usr_token_owner"


@pytest.mark.parametrize("key", ["", "short-key", b"", b"x" * 31])
def test_short_or_empty_signing_key_rejected_without_echo(key: str | bytes) -> None:
    with pytest.raises(ValueError) as excinfo:
        JwtTokenIssuer(signing_key=key, issuer=ISSUER, audience=AUDIENCE)
    assert str(excinfo.value) == SIGNING_KEY_TOO_SHORT_MESSAGE


def test_non_text_signing_key_rejected() -> None:
    with pytest.raises(TypeError):
        JwtTokenIssuer(signing_key=12345, issuer=ISSUER, audience=AUDIENCE)  # type: ignore[arg-type]


@pytest.mark.parametrize("issuer_value", ["", "   ", None])
def test_blank_issuer_rejected(issuer_value: object) -> None:
    with pytest.raises(ValueError) as excinfo:
        JwtTokenIssuer(signing_key=SIGNING_KEY, issuer=issuer_value, audience=AUDIENCE)  # type: ignore[arg-type]
    assert str(excinfo.value) == ISSUER_MESSAGE


@pytest.mark.parametrize("audience_value", ["", "   ", None])
def test_blank_audience_rejected(audience_value: object) -> None:
    with pytest.raises(ValueError) as excinfo:
        JwtTokenIssuer(signing_key=SIGNING_KEY, issuer=ISSUER, audience=audience_value)  # type: ignore[arg-type]
    assert str(excinfo.value) == AUDIENCE_MESSAGE


@pytest.mark.parametrize("ttl_value", [0, -1, True, False, 60.0, "60"])
def test_invalid_ttl_rejected(ttl_value: object) -> None:
    with pytest.raises(ValueError) as excinfo:
        JwtTokenIssuer(
            signing_key=SIGNING_KEY,
            issuer=ISSUER,
            audience=AUDIENCE,
            ttl_seconds=ttl_value,  # type: ignore[arg-type]
        )
    assert str(excinfo.value) == TTL_MESSAGE


def test_issue_rejects_non_user_subjects() -> None:
    for subject in (None, "usr_token_owner", UserId("usr_token_owner")):
        with pytest.raises(TypeError) as excinfo:
            _issuer().issue(subject)  # type: ignore[arg-type]
        assert str(excinfo.value) == USER_TYPE_MESSAGE


# ---------------------------------------------------------------------------
# 5. Secrecy: no logging, static and dynamic
# ---------------------------------------------------------------------------


def test_tokens_module_imports_no_logging() -> None:
    """AST proof: the module has no logging import and no logger reference.

    A minted token is bearer material; the no-secrets rule forbids logging
    anywhere in the module, so this guards the boundary, not one call site.
    """
    tree = ast.parse(Path(tokens_module.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name.split(".")[0] != "logging" for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            assert root != "logging"
        elif isinstance(node, ast.Attribute):
            assert node.attr != "getLogger"


def test_issue_emits_no_log_records(caplog: pytest.LogCaptureFixture) -> None:
    issuer = _issuer()
    with caplog.at_level(logging.DEBUG):
        token = issuer.issue(_user(ApplicationRole.ADMIN), membership_roles=["owner"])
    assert caplog.records == []
    assert token not in caplog.text
    assert SIGNING_KEY not in caplog.text
