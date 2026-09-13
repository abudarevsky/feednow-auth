"""Unit tests for the Phase 03 task-3 Cognito access-token verifier.

Every case uses the sanctioned fixtures (``support.cognito``: RSA keygen,
claim-override signer, loopback JWKS test server — never a live Cognito pool)
and covers the task's verify lines:

- happy path (all claims mapped, frozen value object);
- each rejection **individually**: wrong key, expired, iat/nbf beyond the
  60-second leeway, wrong issuer **plus the prefix-trap issuer** (an
  allowlisted iss as a strict prefix), wrong client_id, ``token_use=id``,
  missing/empty ``sub``, missing ``email``, missing ``kid`` header, and
  ``alg=none`` / HS256 forgeries;
- the pinned check order is proven observably: step-0 header rejections
  (``alg``, ``kid``), issuer/kid rejections assert the JWKS server was
  **never fetched** (``request_count == 0``), and the key lookup is proven
  issuer-bound via the shared-server cross-issuer case;
- a sweep asserts no rejection message contains the token bytes.

Each test asserts the exact fixed reason string, so a failure-path that
accidentally leaks a PyJWT message (or reorders checks) breaks loudly.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import time
from collections.abc import Mapping, Sequence
from typing import Any

import jwt
import pytest
from support.cognito import JwksTestServer, TestKey, generate_test_key, sign_token

from app.auth.cognito import AccessTokenVerifier, CognitoAccessTokenVerifier, CognitoClaims
from app.auth.errors import (
    TokenProviderUnavailableError,
    TokenValidationError,
    UnknownKeyIdError,
)
from app.auth.jwks import CognitoJwksSource

ALLOWED_CLIENT = "app-client-1"
SUBJECT = "11111111-2222-3333-4444-555555555555"
EMAIL = "test-user@example.com"
USERNAME = "test-user"


# Module-scoped so the RSA-2048 keygen cost is paid once per unique key need.
@pytest.fixture(scope="module")
def key_a() -> TestKey:
    return generate_test_key("pool-a-key-1")


@pytest.fixture(scope="module")
def key_b() -> TestKey:
    return generate_test_key("pool-b-key-1")


def _now() -> int:
    return int(time.time())


#: Distinguishes "kid not passed" from "kid explicitly dropped" in :func:`_sign`.
_DEFAULT = object()

#: Removes a claim from :func:`_access_claims` entirely (PyJWT's *encoder*
#: type-checks ``iss`` and its *decoder* type-checks ``exp``/``sub``, so
#: JSON-null cannot represent a genuinely missing registered claim).
_DROP = object()


def _access_claims(issuer: str, **overrides: Any) -> dict[str, Any]:
    """Cognito-shaped access-token claims; any key may be overridden.
    ``_DROP`` removes the claim; ``None`` sets it to JSON null."""
    now = _now()
    claims: dict[str, Any] = {
        "auth_time": now,
        "client_id": ALLOWED_CLIENT,
        "exp": now + 300,
        "iat": now,
        "iss": issuer,
        "jti": "unused-jti",
        "origin_jti": "unused-origin-jti",
        "sub": SUBJECT,
        "token_use": "access",
        "username": USERNAME,
        "email": EMAIL,
        "version": 2,
    }
    for name, value in overrides.items():
        if value is _DROP:
            claims.pop(name, None)
        else:
            claims[name] = value
    return claims


def _sign(claims: Mapping[str, Any], key: TestKey, *, kid: Any = _DEFAULT) -> str:
    """Sign ``claims`` with ``key``; ``kid`` defaults to the key's own,
    ``None`` omits the ``kid`` header, and any string is published verbatim."""
    resolved_kid: str | None = key.kid if kid is _DEFAULT else kid
    return sign_token(claims, kid=resolved_kid, key=key)


def _verifier(
    server: JwksTestServer,
    *,
    segments: Sequence[str] = ("pool-a",),
    clients: Sequence[str] = (ALLOWED_CLIENT,),
    leeway_seconds: int = 60,
) -> CognitoAccessTokenVerifier:
    """Real source + verifier over the loopback server, same allowlist copies."""
    issuers = [server.issuer(segment) for segment in segments]
    source = CognitoJwksSource(issuers)
    return CognitoAccessTokenVerifier(
        source,
        allowed_issuers=issuers,
        allowed_client_ids=clients,
        leeway_seconds=leeway_seconds,
    )


def _expect_reject(
    verifier: CognitoAccessTokenVerifier,
    token: str,
    reason: str,
    *,
    error_type: type[TokenValidationError] = TokenValidationError,
) -> TokenValidationError:
    """Verify must reject with the exact fixed reason and never echo the token."""
    with pytest.raises(error_type) as excinfo:
        verifier.verify(token)
    error = excinfo.value
    assert error.reason == reason
    assert str(error) == reason
    if token:  # the empty string is trivially "contained" in every message
        assert token not in str(error)
        assert token not in error.reason
    return error


# -- happy path -----------------------------------------------------------------


def test_valid_access_token_yields_all_claims(key_a: TestKey) -> None:
    with JwksTestServer({"pool-a": [key_a]}) as server:
        issuer = server.issuer("pool-a")
        verifier = _verifier(server)
        exp = _now() + 300
        token = _sign(_access_claims(issuer, exp=exp), key_a)

        claims = verifier.verify(token)

    assert claims == CognitoClaims(
        sub=SUBJECT,
        email=EMAIL,
        username=USERNAME,
        client_id=ALLOWED_CLIENT,
        iss=issuer,
        exp=exp,
    )
    assert server.request_count == 1  # exactly one JWKS fetch, then cached


def test_username_absent_or_empty_normalizes_to_none(key_a: TestKey) -> None:
    with JwksTestServer({"pool-a": [key_a]}) as server:
        issuer = server.issuer("pool-a")
        verifier = _verifier(server)

        absent = verifier.verify(_sign(_access_claims(issuer, username=_DROP), key_a))
        empty = verifier.verify(_sign(_access_claims(issuer, username=""), key_a))

    assert absent.username is None
    assert empty.username is None
    assert absent.sub == SUBJECT  # the rest of the token is accepted


def test_time_claims_within_leeway_are_accepted(key_a: TestKey) -> None:
    """exp 30s past, iat/nbf 30s in the future: inside the 60s leeway."""
    now = _now()
    with JwksTestServer({"pool-a": [key_a]}) as server:
        verifier = _verifier(server)
        claims = verifier.verify(
            _sign(
                _access_claims(
                    server.issuer("pool-a"),
                    exp=now - 30,
                    iat=now + 30,
                    nbf=now + 30,
                ),
                key_a,
            )
        )
    assert claims.exp == now - 30


def test_claims_are_frozen_value_objects() -> None:
    claims = CognitoClaims(sub="s", email="e@x.test", username=None, client_id="c", iss="i", exp=1)
    with pytest.raises(dataclasses.FrozenInstanceError):
        claims.sub = "other"  # type: ignore[misc]


# -- signature and key failures ---------------------------------------------------


def test_wrong_key_rejected(key_a: TestKey, key_b: TestKey) -> None:
    """Signed by B's private key under A's published kid: signature fails."""
    with JwksTestServer({"pool-a": [key_a]}) as server:
        verifier = _verifier(server)
        token = _sign(_access_claims(server.issuer("pool-a")), key_b, kid=key_a.kid)
        _expect_reject(verifier, token, "token signature is invalid")


def test_unknown_kid_under_verified_issuer_is_unknown_key_id_error(key_a: TestKey) -> None:
    """Kid-mismatch after correct issuer binding is unambiguously UnknownKeyIdError."""
    with JwksTestServer({"pool-a": [key_a]}) as server:
        verifier = _verifier(server)
        token = _sign(_access_claims(server.issuer("pool-a")), key_a, kid="kid-never-published")
        error = _expect_reject(
            verifier,
            token,
            "no signing key matches the token key id",
            error_type=UnknownKeyIdError,
        )
    assert isinstance(error, TokenValidationError)  # 401-mappable in task 5


def test_key_lookup_is_bound_to_the_verified_issuer(key_a: TestKey, key_b: TestKey) -> None:
    """Pinned-order proof at the verifier level (breakdown B2).

    A token claiming issuer A with issuer B's kid must fail as
    ``UnknownKeyIdError`` **without ever fetching B's key set** — no
    cross-issuer scanning — while the same key material under its own
    issuer verifies.
    """
    with JwksTestServer({"pool-a": [key_a], "pool-b": [key_b]}) as server:
        verifier = _verifier(server, segments=("pool-a", "pool-b"))

        wrong_issuer = _sign(_access_claims(server.issuer("pool-a")), key_b, kid=key_b.kid)
        _expect_reject(
            verifier,
            wrong_issuer,
            "no signing key matches the token key id",
            error_type=UnknownKeyIdError,
        )
        assert server.requests_for("pool-b") == 0  # B's set never consulted

        right_issuer = _sign(_access_claims(server.issuer("pool-b")), key_b, kid=key_b.kid)
        assert verifier.verify(right_issuer).iss == server.issuer("pool-b")


def test_jwks_down_raises_provider_unavailable_not_validation(key_a: TestKey) -> None:
    server = JwksTestServer({"pool-a": [key_a]})
    server.start()
    issuer = server.issuer("pool-a")
    verifier = _verifier(server)
    server.stop()  # port closed: the next fetch fails

    token = _sign(_access_claims(issuer), key_a)
    with pytest.raises(TokenProviderUnavailableError) as excinfo:
        verifier.verify(token)
    assert not isinstance(excinfo.value, TokenValidationError)  # outage != bad token


# -- time failures ------------------------------------------------------------------


def test_expired_beyond_leeway_rejected(key_a: TestKey) -> None:
    with JwksTestServer({"pool-a": [key_a]}) as server:
        verifier = _verifier(server)
        token = _sign(_access_claims(server.issuer("pool-a"), exp=_now() - 120), key_a)
        _expect_reject(verifier, token, "token has expired")


def test_iat_beyond_leeway_rejected(key_a: TestKey) -> None:
    """Issued-at 120s in the future: outside the 60s leeway."""
    with JwksTestServer({"pool-a": [key_a]}) as server:
        verifier = _verifier(server)
        token = _sign(_access_claims(server.issuer("pool-a"), iat=_now() + 120), key_a)
        _expect_reject(verifier, token, "token is not yet valid")


def test_nbf_beyond_leeway_rejected(key_a: TestKey) -> None:
    with JwksTestServer({"pool-a": [key_a]}) as server:
        verifier = _verifier(server)
        token = _sign(_access_claims(server.issuer("pool-a"), nbf=_now() + 120), key_a)
        _expect_reject(verifier, token, "token is not yet valid")


# -- issuer failures (checked before any network activity) -----------------------------


def test_wrong_issuer_rejected_without_any_fetch(key_a: TestKey) -> None:
    with JwksTestServer({"pool-a": [key_a]}) as server:
        verifier = _verifier(server)
        evil = server.issuer("evil-pool")  # same host, not allowlisted
        token = _sign(_access_claims(evil), key_a)
        _expect_reject(verifier, token, "token issuer is not in the allowlist")
        assert server.request_count == 0  # the URL was never derived


def test_prefix_trap_issuer_rejected_without_any_fetch(key_a: TestKey) -> None:
    """The classic Cognito issuer-spoof: allowlisted iss as a *strict prefix*.

    Signed with the real key and the real kid, so only the prefix-spoofed
    ``iss`` is wrong — exact set-membership (not PyJWT ``issuer=``) rejects
    it before any JWKS fetch. The reverse containment (token iss is a strict
    prefix of the allowlisted one) is rejected by the same check.
    """
    with JwksTestServer({"pool-a": [key_a]}) as server:
        verifier = _verifier(server)
        issuer = server.issuer("pool-a")
        trap_token = _sign(_access_claims(f"{issuer}-evil"), key_a)
        _expect_reject(verifier, trap_token, "token issuer is not in the allowlist")

        shorter = _sign(_access_claims(issuer.removesuffix("-a")), key_a)
        _expect_reject(verifier, shorter, "token issuer is not in the allowlist")
        assert server.request_count == 0


def test_missing_issuer_claim_rejected(key_a: TestKey) -> None:
    with JwksTestServer({"pool-a": [key_a]}) as server:
        verifier = _verifier(server)
        token = _sign(_access_claims(server.issuer("pool-a"), iss=_DROP), key_a)
        _expect_reject(verifier, token, "token is missing the issuer claim")
        assert server.request_count == 0


# -- client / token_use / shape failures (post-decode) ------------------------------------


def test_wrong_client_id_rejected(key_a: TestKey) -> None:
    with JwksTestServer({"pool-a": [key_a]}) as server:
        verifier = _verifier(server)
        token = _sign(_access_claims(server.issuer("pool-a"), client_id="evil-client"), key_a)
        _expect_reject(verifier, token, "token client_id is not in the allowlist")


def test_id_token_rejected(key_a: TestKey) -> None:
    with JwksTestServer({"pool-a": [key_a]}) as server:
        verifier = _verifier(server)
        token = _sign(_access_claims(server.issuer("pool-a"), token_use="id"), key_a)
        _expect_reject(verifier, token, "token is not an access token")


def test_refresh_token_rejected(key_a: TestKey) -> None:
    with JwksTestServer({"pool-a": [key_a]}) as server:
        verifier = _verifier(server)
        token = _sign(_access_claims(server.issuer("pool-a"), token_use="refresh"), key_a)
        _expect_reject(verifier, token, "token is not an access token")


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        (_DROP, "token is missing the sub claim"),  # claim dropped
        ("", "token sub claim is invalid"),  # present but empty
        ("s" * 256, "token sub claim is invalid"),  # beyond ProviderSubject bound
    ],
    ids=["missing", "empty", "too-long"],
)
def test_sub_shape_failures_rejected(key_a: TestKey, override: Any, reason: str) -> None:
    with JwksTestServer({"pool-a": [key_a]}) as server:
        verifier = _verifier(server)
        token = _sign(_access_claims(server.issuer("pool-a"), sub=override), key_a)
        _expect_reject(verifier, token, reason)


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        (None, "token is missing the email claim"),
        ("", "token email claim is invalid"),
    ],
    ids=["missing", "empty"],
)
def test_email_required(key_a: TestKey, override: Any, reason: str) -> None:
    with JwksTestServer({"pool-a": [key_a]}) as server:
        verifier = _verifier(server)
        token = _sign(_access_claims(server.issuer("pool-a"), email=override), key_a)
        _expect_reject(verifier, token, reason)


def test_exp_missing_rejected(key_a: TestKey) -> None:
    """PyJWT only checks exp when present — the shape stage requires it."""
    with JwksTestServer({"pool-a": [key_a]}) as server:
        verifier = _verifier(server)
        token = _sign(_access_claims(server.issuer("pool-a"), exp=_DROP), key_a)
        _expect_reject(verifier, token, "token is missing the exp claim")


# -- header and algorithm forgeries ---------------------------------------------------------


def test_missing_kid_header_rejected_without_any_fetch(key_a: TestKey) -> None:
    with JwksTestServer({"pool-a": [key_a]}) as server:
        verifier = _verifier(server)
        token = _sign(_access_claims(server.issuer("pool-a")), key_a, kid=None)
        assert "kid" not in jwt.get_unverified_header(token)
        _expect_reject(verifier, token, "token header is missing the key id")

        empty_kid = _sign(_access_claims(server.issuer("pool-a")), key_a, kid="")
        _expect_reject(verifier, empty_kid, "token header is missing the key id")
        assert server.request_count == 0  # neither variant reached the network


def test_alg_none_forgery_rejected(key_a: TestKey) -> None:
    with JwksTestServer({"pool-a": [key_a]}) as server:
        verifier = _verifier(server)
        token = sign_token(
            _access_claims(server.issuer("pool-a")), kid=key_a.kid, key=key_a, alg="none"
        )
        _expect_reject(verifier, token, "token algorithm is not allowed")
        assert server.request_count == 0  # step 0 fails fast, pre-network


def test_hs256_public_key_confusion_forgery_rejected(key_a: TestKey) -> None:
    """The classic HMAC trick: sign HS256 with the *public* key as the secret.

    PyJWT refuses to HMAC-sign with an RSA key object, so the forgery is a
    static jwt.io-style HS256 token instead. Step 0 inspects the unverified
    header before touching any claim, so the rejection is content-independent
    (this payload carries no ``iss`` or ``kid`` at all) and never reaches the
    JWKS network.
    """
    with JwksTestServer({"pool-a": [key_a]}) as server:
        verifier = _verifier(server)
        fake_token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        _expect_reject(verifier, fake_token, "token algorithm is not allowed")
        assert server.request_count == 0  # step 0 fails fast, pre-network


# -- malformed tokens --------------------------------------------------------------------------


def _b64(document: Any) -> str:
    raw = json.dumps(document).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


@pytest.mark.parametrize(
    "token",
    [
        "",
        "not-a-jwt",
        "a.b",  # two segments
        "a.b.c.d",  # four segments
        f"{_b64({'alg': 'RS256'})}.{_b64([1, 2])}.sig",  # payload is not an object
        f"{_b64('header')}.{_b64({'sub': 'x'})}.sig",  # header is not an object
        "!!!.###.$$$",  # undecodable segments
    ],
    ids=["empty", "single", "two-seg", "four-seg", "list-payload", "string-header", "bad-b64"],
)
def test_malformed_tokens_rejected(token: str) -> None:
    source = CognitoJwksSource(["http://127.0.0.1:9/pool"])  # lazy: never connected
    verifier = CognitoAccessTokenVerifier(source, ["http://127.0.0.1:9/pool"], [ALLOWED_CLIENT])
    _expect_reject(verifier, token, "token is not a well-formed JWT")


def test_non_string_token_rejected() -> None:
    source = CognitoJwksSource(["http://127.0.0.1:9/pool"])
    verifier = CognitoAccessTokenVerifier(source, ["http://127.0.0.1:9/pool"], [ALLOWED_CLIENT])
    with pytest.raises(TokenValidationError, match="token must be a string"):
        verifier.verify(b"raw-bytes-not-str")  # type: ignore[arg-type]


# -- no token material in exception messages (acceptance sweep) --------------------------------


def test_no_rejection_message_contains_token_bytes(key_a: TestKey, key_b: TestKey) -> None:
    """Every rejection path: neither ``str(error)`` nor ``error.reason`` may
    carry the token (or any claim value from it) — task 5 logs these."""
    with JwksTestServer({"pool-a": [key_a]}) as server:
        issuer = server.issuer("pool-a")
        verifier = _verifier(server)
        rejections: list[tuple[str, str]] = [
            ("token signature is invalid", _sign(_access_claims(issuer), key_b, kid=key_a.kid)),
            ("token has expired", _sign(_access_claims(issuer, exp=_now() - 120), key_a)),
            ("token is not yet valid", _sign(_access_claims(issuer, nbf=_now() + 120), key_a)),
            (
                "token issuer is not in the allowlist",
                _sign(_access_claims(f"{issuer}-evil"), key_a),
            ),
            (
                "token client_id is not in the allowlist",
                _sign(_access_claims(issuer, client_id="evil-client"), key_a),
            ),
            ("token is not an access token", _sign(_access_claims(issuer, token_use="id"), key_a)),
            ("token is missing the sub claim", _sign(_access_claims(issuer, sub=_DROP), key_a)),
            ("token is missing the email claim", _sign(_access_claims(issuer, email=None), key_a)),
            ("token header is missing the key id", _sign(_access_claims(issuer), key_a, kid=None)),
            (
                "token algorithm is not allowed",
                sign_token(_access_claims(issuer), kid=key_a.kid, key=key_a, alg="none"),
            ),
        ]
        for reason, token in rejections:
            with pytest.raises(TokenValidationError) as excinfo:
                verifier.verify(token)
            error = excinfo.value
            assert error.reason == reason
            assert token not in str(error)
            assert token not in repr(error)
            assert token.split(".")[0] not in str(error)  # no header segment either
            assert SUBJECT not in str(error)
            assert EMAIL not in str(error)


# -- construction and published-interface contracts --------------------------------------------


def test_verifier_satisfies_published_protocol() -> None:
    source = CognitoJwksSource(["http://127.0.0.1:9/pool"])  # lazy: no connection
    verifier: AccessTokenVerifier = CognitoAccessTokenVerifier(
        source, ["http://127.0.0.1:9/pool"], ["client"]
    )
    assert isinstance(verifier, AccessTokenVerifier)


def test_constructor_validates_allowlists_and_leeway() -> None:
    source = CognitoJwksSource(["http://127.0.0.1:9/pool"])
    with pytest.raises(ValueError, match="allowed_issuers"):
        CognitoAccessTokenVerifier(source, [], ["client"])
    with pytest.raises(ValueError, match="allowed_client_ids"):
        CognitoAccessTokenVerifier(source, ["http://127.0.0.1:9/pool"], [])
    with pytest.raises(ValueError, match="leeway_seconds"):
        CognitoAccessTokenVerifier(source, ["http://127.0.0.1:9/pool"], ["c"], leeway_seconds=-1)


def test_allowlists_are_exact_match_copies(key_a: TestKey) -> None:
    """The verifier stores frozenset copies: mutating caller input changes nothing."""
    issuers = ["http://127.0.0.1:9/pool-a"]
    clients = ["client-1"]
    source = CognitoJwksSource(issuers)
    verifier = CognitoAccessTokenVerifier(source, issuers, clients)
    issuers.append("http://evil.test/pool")
    clients.append("evil-client")
    assert verifier.allowed_issuers == frozenset({"http://127.0.0.1:9/pool-a"})
    assert verifier.allowed_client_ids == frozenset({"client-1"})
