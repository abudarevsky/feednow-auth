"""Unit tests for the Phase 03 task-2 JWKS source and token test support.

Every case runs against the loopback :class:`~support.cognito.JwksTestServer`
(acceptance: signed fixtures or a JWKS test server, never a live Cognito pool)
and covers the task's verify lines:

1. Known ``kid`` resolves from the issuer's key set.
2. Unknown ``kid`` raises :class:`UnknownKeyIdError` (a ``TokenValidationError``).
3. Cross-issuer proof: a kid published only under issuer B is not returned
   for an (issuer A, kid) lookup — and B's endpoint is never fetched. The
   shared-kid-string case proves issuer binding, not just set membership.
4. Caching proof: the same known kid twice keeps the server fetch count at 1.
   (An *unknown* kid may trigger a version-dependent forced refetch on
   2.13+ — rotation support — so the count assertion deliberately uses the
   known-kid case only.)
5. Server down → :class:`TokenProviderUnavailableError`.

Plus the allowlist boundary (disallowed issuer is rejected without any fetch),
constructor validation, protocol conformance, and the support-module fixtures
themselves. No verifier logic is exercised: the raw ``jwt.decode`` calls prove
a resolved key is usable, not app verification behavior (none exists yet).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from jwt.algorithms import RSAAlgorithm
from jwt.exceptions import PyJWKClientConnectionError
from support.cognito import JwksTestServer, TestKey, generate_test_key, jwks_payload, sign_token

from app.auth.errors import (
    TokenProviderUnavailableError,
    TokenValidationError,
    UnknownKeyIdError,
)
from app.auth.jwks import JWKS_PATH, CognitoJwksSource, JwksSource


# Module-scoped so the RSA-2048 keygen cost is paid once per unique key need.
@pytest.fixture(scope="module")
def key_a() -> TestKey:
    return generate_test_key("pool-a-key-1")


@pytest.fixture(scope="module")
def key_b() -> TestKey:
    return generate_test_key("pool-b-key-1")


@pytest.fixture(scope="module")
def shared_a() -> TestKey:
    """Issuer A's key published under the *same* kid string as issuer B's."""
    return generate_test_key("shared-kid")


@pytest.fixture(scope="module")
def shared_b() -> TestKey:
    return generate_test_key("shared-kid")


def _public_numbers(key: TestKey) -> RSAPublicNumbers:
    return key.private_key.public_key().public_numbers()


def _claims() -> dict[str, object]:
    return {
        "sub": "00000000-0000-0000-0000-000000000001",
        "token_use": "access",
        "exp": 4_102_444_800,  # 2100-01-01: shape only; nothing verifies expiry here
    }


def _get_json(url: str) -> dict[str, object]:
    with urllib.request.urlopen(url, timeout=5) as response:  # loopback fixture URL
        return json.loads(response.read())


def _get_status(url: str) -> int:
    try:
        with urllib.request.urlopen(url, timeout=5):  # loopback fixture URL
            return 200
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        return int(code)


# -- 1. known kid resolves ------------------------------------------------------


def test_known_kid_resolves_from_local_server(key_a: TestKey) -> None:
    with JwksTestServer({"pool-a": [key_a]}) as server:
        source = CognitoJwksSource([server.issuer("pool-a")])
        signing_key = source.signing_key(server.issuer("pool-a"), key_a.kid)

    assert signing_key.key_id == key_a.kid
    assert signing_key.algorithm_name == "RS256"
    assert signing_key.key.public_numbers() == _public_numbers(key_a)
    assert server.request_count == 1


def test_resolved_key_verifies_a_token_signed_with_the_fixture_key(key_a: TestKey) -> None:
    """Chain proof: keygen -> jwks payload -> server -> source -> usable key."""
    token = sign_token(_claims(), kid=key_a.kid, key=key_a)
    with JwksTestServer({"pool-a": [key_a]}) as server:
        source = CognitoJwksSource([server.issuer("pool-a")])
        signing_key = source.signing_key(server.issuer("pool-a"), key_a.kid)

    assert jwt.get_unverified_header(token)["kid"] == key_a.kid
    claims = jwt.decode(token, signing_key.key, algorithms=["RS256"], options={"verify_aud": False})
    assert claims["sub"] == _claims()["sub"]


# -- 2. unknown kid ---------------------------------------------------------------


def test_unknown_kid_raises_unknown_key_id_error(key_a: TestKey) -> None:
    with JwksTestServer({"pool-a": [key_a]}) as server:
        source = CognitoJwksSource([server.issuer("pool-a")])
        with pytest.raises(UnknownKeyIdError) as excinfo:
            source.signing_key(server.issuer("pool-a"), "kid-never-published")

    assert isinstance(excinfo.value, TokenValidationError)
    assert excinfo.value.reason  # fixed safe reason...
    assert "kid-never-published" not in str(excinfo.value)  # ...never interpolated


# -- 3. cross-issuer proof ----------------------------------------------------------


def test_kid_only_under_issuer_b_is_not_returned_for_issuer_a(
    key_a: TestKey, key_b: TestKey
) -> None:
    with JwksTestServer({"pool-a": [key_a], "pool-b": [key_b]}) as server:
        issuer_a, issuer_b = server.issuer("pool-a"), server.issuer("pool-b")
        source = CognitoJwksSource([issuer_a, issuer_b])

        with pytest.raises(UnknownKeyIdError):
            source.signing_key(issuer_a, key_b.kid)  # kid exists only under B
        # The failed lookup never scanned B's key set:
        assert server.requests_for("pool-b") == 0

        # The kid is real — the same lookup bound to its own issuer resolves it.
        assert source.signing_key(issuer_b, key_b.kid).key_id == key_b.kid


def test_shared_kid_string_resolves_per_issuer(shared_a: TestKey, shared_b: TestKey) -> None:
    """Two issuers may legitimately reuse a kid string; binding is per issuer."""
    assert shared_a.kid == shared_b.kid
    with JwksTestServer({"pool-a": [shared_a], "pool-b": [shared_b]}) as server:
        source = CognitoJwksSource([server.issuer("pool-a"), server.issuer("pool-b")])
        from_a = source.signing_key(server.issuer("pool-a"), shared_a.kid)
        from_b = source.signing_key(server.issuer("pool-b"), shared_b.kid)

    assert from_a.key.public_numbers() == _public_numbers(shared_a)
    assert from_b.key.public_numbers() == _public_numbers(shared_b)
    assert from_a.key.public_numbers() != from_b.key.public_numbers()


# -- 4. caching proof -----------------------------------------------------------------


def test_known_kid_second_lookup_is_served_from_cache(key_a: TestKey) -> None:
    """Fetch count must stay 1 for the known-kid case.

    Deliberately *not* asserted on the unknown-kid case: PyJWKClient's
    rotation support can force a refetch there (immediate on 2.13, gated by
    the default cooldown on 2.14), so that count is version-behavior
    dependent and not pinned by the task.
    """
    with JwksTestServer({"pool-a": [key_a]}) as server:
        source = CognitoJwksSource([server.issuer("pool-a")])
        first = source.signing_key(server.issuer("pool-a"), key_a.kid)
        second = source.signing_key(server.issuer("pool-a"), key_a.kid)
        assert first is second  # per-key LRU (cache_keys=True) hit
        assert server.request_count == 1


def test_clients_are_built_lazily_one_per_issuer(key_a: TestKey, key_b: TestKey) -> None:
    with JwksTestServer({"pool-a": [key_a], "pool-b": [key_b]}) as server:
        source = CognitoJwksSource([server.issuer("pool-a"), server.issuer("pool-b")])
        assert source._clients == {}  # nothing constructed before first use
        source.signing_key(server.issuer("pool-a"), key_a.kid)
        assert set(source._clients) == {server.issuer("pool-a")}
        source.signing_key(server.issuer("pool-a"), key_a.kid)
        assert server.request_count == 1  # second lookup reused the same client


# -- 5. server down ---------------------------------------------------------------------


def test_server_down_raises_token_provider_unavailable(key_a: TestKey) -> None:
    server = JwksTestServer({"pool-a": [key_a]})
    server.start()
    issuer = server.issuer("pool-a")
    server.stop()

    source = CognitoJwksSource([issuer])  # fresh source: no cached key set to hide behind
    with pytest.raises(TokenProviderUnavailableError) as excinfo:
        source.signing_key(issuer, key_a.kid)

    assert not isinstance(excinfo.value, TokenValidationError)  # outage != bad token
    assert str(excinfo.value) == excinfo.value.reason  # fixed safe message
    assert isinstance(excinfo.value.__cause__, PyJWKClientConnectionError)


# -- allowlist boundary -------------------------------------------------------------------


def test_disallowed_issuer_is_rejected_without_any_fetch(key_a: TestKey) -> None:
    with JwksTestServer({"pool-a": [key_a]}) as server:
        source = CognitoJwksSource([server.issuer("pool-a")])
        attacker_issuer = server.issuer("evil-pool")  # same host, not allowlisted
        with pytest.raises(TokenValidationError):
            source.signing_key(attacker_issuer, key_a.kid)
        assert server.request_count == 0  # URL never derived, endpoint never hit


def test_allowlist_validation_fails_fast() -> None:
    with pytest.raises(ValueError, match="at least one issuer"):
        CognitoJwksSource([])
    for bad in ("ftp://example.com/pool", "https://127.0.0.1:1/pool/", "http:///pool"):
        with pytest.raises(ValueError, match="issuer"):
            CognitoJwksSource([bad])


def test_source_satisfies_published_protocol() -> None:
    source: JwksSource = CognitoJwksSource(["http://127.0.0.1:9/pool"])  # lazy: no connection
    assert isinstance(source, JwksSource)
    assert JWKS_PATH == "/.well-known/jwks.json"


# -- support-module fixtures ------------------------------------------------------------------


def test_sign_token_publishes_kid_and_alg_in_header(key_a: TestKey) -> None:
    claims = {**_claims(), "iss": "https://cognito-idp.example.com/pool"}
    token = sign_token(claims, kid=key_a.kid, key=key_a)
    assert jwt.get_unverified_header(token) == {"alg": "RS256", "kid": key_a.kid, "typ": "JWT"}
    decoded = jwt.decode(token, options={"verify_signature": False})
    assert decoded["iss"] == claims["iss"]


def test_sign_token_honors_claim_and_alg_overrides(key_a: TestKey) -> None:
    forged = sign_token({"sub": "x"}, kid=key_a.kid, key=key_a, alg="none")
    assert jwt.get_unverified_header(forged)["alg"] == "none"
    assert jwt.decode(forged, options={"verify_signature": False}) == {"sub": "x"}


def test_jwks_payload_round_trips_to_the_same_public_key(key_a: TestKey) -> None:
    payload = jwks_payload([key_a])
    published = RSAAlgorithm.from_jwk(json.dumps(payload["keys"][0]))
    assert published.public_numbers() == _public_numbers(key_a)
    entry = payload["keys"][0]
    assert entry["kid"] == key_a.kid
    assert entry["use"] == "sig"
    assert entry["alg"] == "RS256"
    assert entry["kty"] == "RSA"
    # No private material may ever be published (no-secrets rule):
    assert set(entry) == {"kty", "n", "e", "kid", "use", "alg"}


def test_server_counts_requests_per_segment(key_a: TestKey) -> None:
    with JwksTestServer({"pool-a": [key_a]}) as server:
        assert server.request_count == 0
        assert _get_json(server.jwks_url("pool-a")) == jwks_payload([key_a])
        assert server.request_count == 1
        assert server.requests_for("pool-a") == 1
        assert server.requests_for("pool-b") == 0
        assert _get_status(server.jwks_url("pool-b")) == 404  # unknown segment: counted
        assert server.request_count == 2
