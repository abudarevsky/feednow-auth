"""Unit tests for Phase 05 task 1 credential primitives (:mod:`app.auth.credentials`).

Verify lines covered (per the Phase 05 breakdown, task 1):

1. 10k generated key-ids are unique and match the pinned Crockford-26 ULID
   shape (timestamp chars 1-10 with first char ∈ ``01234567``, randomness
   chars 11-26).
2. The generated secret decodes to exactly 32 bytes (256 bits).
3. Literal round-trips through ``build_literal``/``parse_literal``, including
   crafted secrets containing ``_``.
4. Wrong env token, missing prefix, empty segments, and oversized inputs all
   raise :class:`ApiKeyCredentialFormatError` with one fixed message and no
   input echo (message *and* exception chain).
5. ``hash_secret`` is deterministic against an independently computed
   HMAC-SHA256 known vector with a fixed test pepper.
6. ``secret_matches`` is a correct constant-time matcher and
   ``dummy_secret_matches`` performs the same crypto work (call-count proof)
   while never authenticating.
"""

from __future__ import annotations

import ast
import base64
import dataclasses
import hashlib
import hmac
import re
import time
from pathlib import Path

import pytest

import app.auth.credentials as credentials
from app.auth.credentials import (
    CROCKFORD_ALPHABET,
    DUMMY_SECRET_HASH,
    ENVIRONMENT_PREFIX_LENGTH,
    ENVIRONMENT_PREFIXES,
    KEY_ID_LENGTH,
    KEY_ID_TIMESTAMP_CHARS,
    MALFORMED_CREDENTIAL_MESSAGE,
    MAX_CREDENTIAL_LITERAL_LENGTH,
    SECRET_ENTROPY_BYTES,
    ApiKeyCredentialFormatError,
    ParsedCredential,
    build_literal,
    dummy_secret_matches,
    generate_key_id,
    generate_secret,
    hash_secret,
    parse_literal,
    secret_matches,
)
from app.models.enums import ApiKeyEnvironment

#: Fixed pepper fixture constant (32 bytes) for the known-vector tests.
PEPPER = b"unit-test-pepper-32-bytes-fixed!"

#: Uniqueness sample size pinned by the task's verify line.
SAMPLES = 10_000

_KEY_ID_SHAPE = re.compile(rf"[{CROCKFORD_ALPHABET}]{{{KEY_ID_LENGTH}}}")


def _decode_crockford(segment: str) -> int:
    value = 0
    for char in segment:
        value = value * 32 + CROCKFORD_ALPHABET.index(char)
    return value


# -- 1. generate_key_id: ULID shape and uniqueness --------------------------


def test_key_ids_unique_over_10k_samples():
    samples = [generate_key_id() for _ in range(SAMPLES)]
    assert len(set(samples)) == SAMPLES


def test_key_id_is_26_crockford_chars():
    for _ in range(1_000):
        key_id = generate_key_id()
        assert len(key_id) == KEY_ID_LENGTH
        assert _KEY_ID_SHAPE.fullmatch(key_id) is not None


def test_key_id_never_contains_underscore():
    """The parse contract depends on the alphabet excluding ``_``."""
    for _ in range(500):
        assert "_" not in generate_key_id()


def test_key_id_first_char_within_timestamp_width():
    """130 bits over 26 chars: the 48-bit timestamp needs no alphabet widening."""
    for _ in range(1_000):
        assert generate_key_id()[0] in "01234567"


def test_key_id_encodes_current_millisecond_timestamp_in_chars_1_to_10():
    key_id = generate_key_id()
    decoded_ms = _decode_crockford(key_id[:KEY_ID_TIMESTAMP_CHARS])
    now_ms = time.time_ns() // 1_000_000
    assert abs(now_ms - decoded_ms) <= 5_000


def test_key_id_randomness_lives_in_chars_11_to_26():
    key_id = generate_key_id()
    randomness = _decode_crockford(key_id[KEY_ID_TIMESTAMP_CHARS:])
    assert 0 <= randomness < 2**80


def test_key_id_randomness_variates():
    tails = {generate_key_id()[KEY_ID_TIMESTAMP_CHARS:] for _ in range(50)}
    assert len(tails) > 1


def test_key_id_fits_the_frozen_keyid_bound():
    """The §8 segment must fit the Phase 01 ``KeyId`` ≤ 64 bound."""
    assert len(generate_key_id()) <= 64


# -- 2. generate_secret: 256-bit CSPRNG material -----------------------------


def test_secret_decodes_to_exactly_32_bytes():
    for _ in range(50):
        secret = generate_secret()
        decoded = base64.urlsafe_b64decode(secret + "=" * (-len(secret) % 4))
        assert len(decoded) == SECRET_ENTROPY_BYTES


def test_secret_is_43_base64url_chars():
    for _ in range(200):
        assert re.fullmatch(r"[A-Za-z0-9_-]{43}", generate_secret()) is not None


def test_secrets_unique_over_10k_samples():
    samples = [generate_secret() for _ in range(SAMPLES)]
    assert len(set(samples)) == SAMPLES


# -- 3. build_literal / parse_literal round-trips -----------------------------

CRAFTED_SECRETS = [
    "simplesecretwithoutunderscores",
    "_leading_underscore",
    "trailing_underscore_",
    "mid_dle",
    "a_b_c_d_e_f",
    "___",
    "_",
    "dash-and_underscore_-mix",
]


@pytest.mark.parametrize("environment", list(ApiKeyEnvironment))
@pytest.mark.parametrize("secret", CRAFTED_SECRETS)
def test_literal_round_trips_including_underscore_bearing_secrets(environment, secret):
    key_id = generate_key_id()
    literal = build_literal(environment, key_id, secret)
    parsed = parse_literal(literal)
    assert parsed == ParsedCredential(environment=environment, key_id=key_id, secret=secret)
    assert parsed.environment is environment
    assert parsed.key_id == key_id
    assert parsed.secret == secret


def test_round_trip_with_freshly_generated_pair():
    key_id = generate_key_id()
    secret = generate_secret()
    for environment in ApiKeyEnvironment:
        parsed = parse_literal(build_literal(environment, key_id, secret))
        assert (parsed.environment, parsed.key_id, parsed.secret) == (environment, key_id, secret)


@pytest.mark.parametrize(
    ("environment", "prefix"),
    [(ApiKeyEnvironment.LIVE, "fn_live_"), (ApiKeyEnvironment.TEST, "fn_test_")],
)
def test_literal_carries_the_pinned_environment_prefix(environment, prefix):
    literal = build_literal(environment, generate_key_id(), generate_secret())
    assert literal.startswith(prefix)
    assert ENVIRONMENT_PREFIXES[environment] == prefix
    assert len(prefix) == ENVIRONMENT_PREFIX_LENGTH


def test_generated_literal_has_pinned_78_char_length():
    """8 (env) + 26 (key-id) + 1 (separator) + 43 (secret) = 78 ≤ 512."""
    literal = build_literal(ApiKeyEnvironment.LIVE, generate_key_id(), generate_secret())
    assert len(literal) == 8 + KEY_ID_LENGTH + 1 + 43
    assert len(literal) <= MAX_CREDENTIAL_LITERAL_LENGTH


def test_parse_splits_at_the_first_underscore_after_the_prefix():
    key_id = generate_key_id()
    parsed = parse_literal(f"fn_test_{key_id}_a_b_c")
    assert parsed.key_id == key_id
    assert parsed.secret == "a_b_c"


def test_parsed_credential_is_frozen():
    parsed = parse_literal(build_literal(ApiKeyEnvironment.LIVE, generate_key_id(), "s3cret"))
    with pytest.raises(dataclasses.FrozenInstanceError):
        parsed.secret = "tampered"  # type: ignore[misc]


def test_parsed_credential_repr_and_str_redact_the_secret():
    secret = "top-secret-material-with_underscores"
    key_id = generate_key_id()
    parsed = parse_literal(build_literal(ApiKeyEnvironment.LIVE, key_id, secret))
    for rendered in (repr(parsed), str(parsed), f"{parsed}"):
        assert secret not in rendered
        assert "<redacted>" in rendered
        assert key_id in rendered  # key-id is non-secret by §8 design


# -- 4. Format failures: one fixed message, no input echo ---------------------

VALID_KEY_ID = "01JXYZ7K2MPQRSTVWXYGHJMNQ0"  # 26 Crockford chars, first ∈ 01234567

MALFORMED_LITERALS: list[tuple[str, tuple[str, ...]]] = [
    # (literal, fragments that must never be echoed)
    ("fn_prod_" + VALID_KEY_ID + "_secret", ("fn_prod", "secret")),  # wrong env token
    ("fn_live2_" + VALID_KEY_ID + "_secret", ("live2", "secret")),  # near-miss env token
    ("pk_live_" + VALID_KEY_ID + "_secret", ("pk_live", "secret")),  # wrong brand prefix
    (VALID_KEY_ID + "_secret", (VALID_KEY_ID, "secret")),  # missing prefix entirely
    ("fn_live__secret", ("secret",)),  # empty key-id segment
    ("fn_live_" + VALID_KEY_ID + "_", (VALID_KEY_ID,)),  # empty secret segment
    ("fn_live_" + VALID_KEY_ID, (VALID_KEY_ID,)),  # missing secret separator
    ("fn_live_" + VALID_KEY_ID[:6] + "_extra_secret", ("extra_secret",)),  # short key-id
    ("fn_live_" + VALID_KEY_ID + "X_secret", ()),  # 27-char key-id segment
    ("fn_live_" + VALID_KEY_ID.lower() + "_secret", ("secret",)),  # lowercase key-id
    ("fn_live_01JXYZ7K2MPQRSTVWXYZGHJMNQI_secret", ("secret",)),  # I not in alphabet
    ("fn_live_01JXYZ7K2MPQRSTVWXYZGHJMNQL_secret", ("secret",)),  # L not in alphabet
    ("fn_live_01JXYZ7K2MPQRSTVWXYZGHJMNQO_secret", ("secret",)),  # O not in alphabet
    ("fn_live_01JXYZ7K2MPQRSTVWXYZGHJMNQU_secret", ("secret",)),  # U not in alphabet
    ("fn_live_" + VALID_KEY_ID + "_" + "a" * 600, ("a" * 80,)),  # oversized literal
    ("", ()),  # empty
    (" fn_live_" + VALID_KEY_ID + "_secret", (VALID_KEY_ID,)),  # leading whitespace
]


@pytest.mark.parametrize(("literal", "fragments"), MALFORMED_LITERALS)
def test_parse_rejects_malformed_literals_with_one_fixed_message(literal, fragments):
    with pytest.raises(ApiKeyCredentialFormatError) as excinfo:
        parse_literal(literal)
    assert str(excinfo.value) == MALFORMED_CREDENTIAL_MESSAGE
    for fragment in fragments:
        assert fragment not in str(excinfo.value)
    # No echo anywhere in the exception chain either.
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__context__ is None


@pytest.mark.parametrize("literal", [None, 123, b"fn_live_x_y", ["fn_live_a_b"]])
def test_parse_rejects_non_string_input(literal):
    with pytest.raises(ApiKeyCredentialFormatError) as excinfo:
        parse_literal(literal)  # type: ignore[arg-type]
    assert str(excinfo.value) == MALFORMED_CREDENTIAL_MESSAGE


@pytest.mark.parametrize(
    ("environment", "key_id", "secret"),
    [
        ("prod", VALID_KEY_ID, "secret"),  # unknown env token
        (None, VALID_KEY_ID, "secret"),  # non-enum env
        ("", VALID_KEY_ID, "secret"),  # empty env
        (ApiKeyEnvironment.LIVE, "", "secret"),  # empty key-id
        (ApiKeyEnvironment.LIVE, VALID_KEY_ID.lower(), "secret"),  # lowercase key-id
        (ApiKeyEnvironment.LIVE, VALID_KEY_ID[:25], "secret"),  # 25-char key-id
        (ApiKeyEnvironment.LIVE, VALID_KEY_ID + "AA", "secret"),  # 28-char key-id
        (ApiKeyEnvironment.LIVE, VALID_KEY_ID[:25] + "_", "secret"),  # underscore in key-id
        (ApiKeyEnvironment.LIVE, VALID_KEY_ID, ""),  # empty secret
        (ApiKeyEnvironment.LIVE, VALID_KEY_ID, "a" * 600),  # oversized total
    ],
)
def test_build_literal_refuses_anything_parse_would_reject(environment, key_id, secret):
    with pytest.raises(ApiKeyCredentialFormatError) as excinfo:
        build_literal(environment, key_id, secret)  # type: ignore[arg-type]
    assert str(excinfo.value) == MALFORMED_CREDENTIAL_MESSAGE
    if key_id:
        assert key_id not in str(excinfo.value)
    if secret:
        assert secret not in str(excinfo.value)
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__context__ is None


def test_build_literal_accepts_the_environment_string_value():
    """A validated ``"live"``/``"test"`` string normalizes to the enum."""
    literal = build_literal("test", VALID_KEY_ID, "secret")
    assert parse_literal(literal).environment is ApiKeyEnvironment.TEST


# -- 5. hash_secret: pinned HMAC-SHA256(pepper, secret), lowercase hex --------


def test_hash_secret_matches_independent_known_vector():
    secret = "unit-test-secret-01JXYZ7K"
    expected = hmac.new(PEPPER, secret.encode("utf-8"), hashlib.sha256).hexdigest()
    assert hash_secret(PEPPER, secret) == expected


def test_hash_secret_is_deterministic():
    assert hash_secret(PEPPER, "same") == hash_secret(PEPPER, "same")


def test_hash_secret_is_lowercase_hex_64_chars():
    digest = hash_secret(PEPPER, generate_secret())
    assert re.fullmatch(r"[0-9a-f]{64}", digest) is not None


def test_hash_secret_diffuses_secret_and_pepper_changes():
    base = hash_secret(PEPPER, "secret-a")
    assert base != hash_secret(PEPPER, "secret-b")
    assert base != hash_secret(PEPPER + b"x", "secret-a")


def test_hash_secret_rejects_non_bytes_pepper_without_echo():
    with pytest.raises(TypeError) as excinfo:
        hash_secret("passphrase-not-bytes-32-bytes-ok!!", "secret")  # type: ignore[arg-type]
    assert "passphrase" not in str(excinfo.value)


def test_hash_secret_rejects_empty_pepper():
    with pytest.raises(ValueError):
        hash_secret(b"", "secret")


# -- 6. Constant-time matching and the dummy-compare branch -------------------


def test_secret_matches_accepts_the_true_candidate():
    secret = generate_secret()
    assert secret_matches(hash_secret(PEPPER, secret), PEPPER, secret) is True


def test_secret_matches_rejects_one_bit_flip():
    secret = generate_secret()
    stored = hash_secret(PEPPER, secret)
    flipped = secret[:-1] + ("A" if secret[-1] != "A" else "B")
    assert secret_matches(stored, PEPPER, flipped) is False


def test_secret_matches_rejects_wrong_pepper():
    secret = generate_secret()
    stored = hash_secret(PEPPER, secret)
    assert secret_matches(stored, PEPPER + b"-other", secret) is False


def test_secret_matches_pins_lowercase_hex_encoding():
    secret = generate_secret()
    uppercase = hash_secret(PEPPER, secret).upper()
    assert secret_matches(uppercase, PEPPER, secret) is False


def test_secret_matches_survives_corrupt_stored_hash():
    """A non-hex/non-ASCII stored value answers False, never raises."""
    secret = generate_secret()
    assert secret_matches("not-a-digest", PEPPER, secret) is False
    assert secret_matches("é" * 64, PEPPER, secret) is False


def test_dummy_secret_hash_has_the_shape_of_a_real_digest():
    assert re.fullmatch(r"[0-9a-f]{64}", DUMMY_SECRET_HASH) is not None


@pytest.mark.parametrize("candidate", ["", "anything", generate_secret(), generate_secret()])
def test_dummy_secret_matches_never_authenticates(candidate):
    assert dummy_secret_matches(PEPPER, candidate) is False


def test_dummy_compare_performs_the_same_crypto_work(monkeypatch):
    """Call-count proof: the unknown-key branch does one real hash_secret call."""
    calls: list[tuple[bytes, str]] = []
    real_hash_secret = credentials.hash_secret

    def counting_hash_secret(pepper: bytes, secret: str) -> str:
        calls.append((pepper, secret))
        return real_hash_secret(pepper, secret)

    monkeypatch.setattr(credentials, "hash_secret", counting_hash_secret)

    candidate = generate_secret()
    assert dummy_secret_matches(PEPPER, candidate) is False
    assert calls == [(PEPPER, candidate)]

    calls.clear()
    stored = real_hash_secret(PEPPER, candidate)
    assert secret_matches(stored, PEPPER, candidate) is True
    assert calls == [(PEPPER, candidate)]


# -- Module boundary: stdlib only, no provider/AWS coupling -------------------


def test_credentials_imports_stay_within_stdlib_and_domain():
    """Decision 3: everything Phase 05 task 1 ships is stdlib + domain models.

    An AST guard over the module body proves no AWS SDK, web framework, or
    configuration import sneaks in (the no-``boto3`` proof stays green).
    """
    tree = ast.parse(Path(credentials.__file__).read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    assert roots <= {
        "__future__",
        "app",
        "dataclasses",
        "hashlib",
        "hmac",
        "re",
        "secrets",
        "time",
        "typing",
    }
    assert "boto3" not in roots
    assert "fastapi" not in roots
