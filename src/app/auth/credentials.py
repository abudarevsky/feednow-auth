"""API-key credential primitives (Phase 05 task 1; spec §8, breakdown decision 2).

This module makes the spec's "recommended" credential format concrete and
owns it end to end: generation, literal assembly, parsing, and the peppered
hash. The pinned literal is ``fn_<live|test>_<key-id>_<secret>``:

- ``<key-id>`` — a 26-character **ULID**: 48-bit millisecond timestamp in
  chars 1-10 (first char therefore ∈ ``01234567`` — 130 bits over 26 chars,
  so no alphabet widening is needed) plus 80 bits of :mod:`secrets`-drawn
  randomness in chars 11-26, uppercase Crockford base32. The alphabet
  contains no ``_``, which is what makes parsing unambiguous. It satisfies
  the frozen ``KeyId`` ≤ 64 bound; uniqueness is ultimately arbitrated by
  the storage UNIQUE index (decision 11), not by entropy alone.
- ``<secret>`` — :func:`secrets.token_urlsafe(32)`: exactly **256 bits** of
  CSPRNG entropy, 43 base64url characters. The alphabet includes ``_``, so
  parsing strips the fixed 8-char environment prefix and splits at the
  **first** ``_`` (the key-id segment is underscore-free by charset);
  everything after is the secret.
- ``secret_hash`` — ``HMAC-SHA256(pepper, secret)`` in **lowercase hex**
  (Phase 01 left the encoding open; hex is pinned here).

Boundary rules preserved here:

- The plaintext secret exists only in transit. Nothing in this module
  persists, logs, or echoes it: :class:`ParsedCredential` redacts the
  secret from ``repr``/``str``, and every shape violation raises
  :class:`ApiKeyCredentialFormatError` with one fixed message that never
  includes any input fragment (key-id, secret, or prefix).
- The §8 credential segment lives **here**, not in
  :mod:`app.services.idgen`, so credential entropy never masquerades as
  application-ID entropy (decision 2).
- Stdlib only (``hmac``/``hashlib``/``secrets``/``time``): no AWS import, so
  the no-``boto3`` proof stays green; Phase 07 wires the real pepper source.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from dataclasses import dataclass
from typing import Final

from app.models.enums import ApiKeyEnvironment

#: Crockford base32 alphabet (excludes ``I``, ``L``, ``O``, ``U``; contains no
#: ``_`` — the property that makes the key-id/secret split unambiguous).
CROCKFORD_ALPHABET: Final = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

#: Total ULID length: 130 bits over 26 chars (timestamp chars 1-10, randomness
#: chars 11-26). Pinned by decision 2 and asserted by the task-1 shape test.
KEY_ID_LENGTH: Final = 26

#: Characters of the ULID that carry the 48-bit millisecond timestamp.
KEY_ID_TIMESTAMP_CHARS: Final = 10

#: Fixed-width environment prefixes; each is exactly 8 characters.
ENVIRONMENT_PREFIXES: Final = {
    ApiKeyEnvironment.LIVE: "fn_live_",
    ApiKeyEnvironment.TEST: "fn_test_",
}

#: Length of the fixed environment prefix (``fn_live_`` / ``fn_test_``).
ENVIRONMENT_PREFIX_LENGTH: Final = 8

#: CSPRNG entropy of the secret in bytes — 256 bits, the spec §8 floor exactly.
SECRET_ENTROPY_BYTES: Final = 32

#: Upper bound for a full literal — the frozen ``FullApiKey`` ≤ 512 transport
#: bound; oversized input is a format violation, never a silent truncation.
MAX_CREDENTIAL_LITERAL_LENGTH: Final = 512

#: The one fixed, input-echo-free message for every credential shape failure.
#: Task 3's verifier maps it (with every other authentication failure) to the
#: single uniform 401 — this module never names which segment was wrong.
MALFORMED_CREDENTIAL_MESSAGE: Final = "malformed API key credential"

#: Fixed same-shape (64 lowercase hex) digest used by the unknown-key
#: dummy-comparison branch (decision 4). It is not derived from any real
#: credential, so it can never authenticate anything.
DUMMY_SECRET_HASH: Final = "0" * 64

_KEY_ID_RE = re.compile(f"[{CROCKFORD_ALPHABET}]{{{KEY_ID_LENGTH}}}")


class ApiKeyCredentialFormatError(Exception):
    """Raised when a credential literal violates the pinned §8 shape.

    The message is always :data:`MALFORMED_CREDENTIAL_MESSAGE` — a fixed,
    log-safe description that never echoes the offending input (no key-id,
    secret, or prefix fragment appears in any exception text, cause chain,
    or context). Task 3's verification pipeline converts this into the one
    uniform 401; nothing here distinguishes *which* segment failed.
    """

    def __init__(self, message: str = MALFORMED_CREDENTIAL_MESSAGE) -> None:
        super().__init__(message)


@dataclass(frozen=True, repr=False)
class ParsedCredential:
    """A successfully parsed literal: environment, lookup segment, secret.

    ``key_id`` is the non-secret §8 point-lookup segment; ``secret`` is
    plaintext credential material and is therefore redacted from
    ``repr``/``str`` (AGENTS.md: plaintext secrets never reach logs, and a
    logged exception or collection dump must not leak them).
    """

    environment: ApiKeyEnvironment
    key_id: str
    secret: str

    def __repr__(self) -> str:
        return (
            f"ParsedCredential(environment={self.environment!r}, "
            f"key_id={self.key_id!r}, secret=<redacted>)"
        )

    __str__ = __repr__


def generate_key_id() -> str:
    """Mint a fresh 26-char Crockford-base32 ULID credential segment.

    Encoding is pinned by decision 2: 48-bit Unix-millisecond timestamp in
    chars 1-10 (two zero pad bits make the first char ∈ ``01234567``), 80
    bits of :func:`secrets.randbits` randomness in chars 11-26 — 130 bits
    over 26 characters, big-endian, five bits per character.
    """
    timestamp_ms = time.time_ns() // 1_000_000
    randomness = secrets.randbits(80)
    value = (timestamp_ms << 80) | randomness
    return "".join(
        CROCKFORD_ALPHABET[(value >> (5 * (KEY_ID_LENGTH - 1 - index))) & 0x1F]
        for index in range(KEY_ID_LENGTH)
    )


def generate_secret() -> str:
    """Mint a fresh credential secret: 256 bits of CSPRNG entropy.

    :func:`secrets.token_urlsafe(32)` yields 43 base64url characters (the
    alphabet includes ``_`` and ``-``), decoding to exactly 32 bytes.
    """
    return secrets.token_urlsafe(SECRET_ENTROPY_BYTES)


def build_literal(environment: ApiKeyEnvironment, key_id: str, secret: str) -> str:
    """Assemble ``fn_<env>_<key-id>_<secret>`` from validated components.

    Refuses anything :func:`parse_literal` would not accept back — an
    unknown environment, a key-id outside the pinned Crockford-26 shape, an
    empty secret, or a total length beyond the frozen 512 transport bound —
    with the fixed format error and no input echo.
    """
    # Membership-checked without raising: an internal ValueError would leave
    # the input value in the exception chain's ``__context__`` (echo).
    if isinstance(environment, ApiKeyEnvironment):
        resolved = environment
    elif isinstance(environment, str) and environment in {
        member.value for member in ApiKeyEnvironment
    }:
        resolved = ApiKeyEnvironment(environment)
    else:
        raise ApiKeyCredentialFormatError(MALFORMED_CREDENTIAL_MESSAGE)
    prefix = ENVIRONMENT_PREFIXES[resolved]
    if _KEY_ID_RE.fullmatch(key_id) is None:
        raise ApiKeyCredentialFormatError(MALFORMED_CREDENTIAL_MESSAGE)
    if not secret:
        raise ApiKeyCredentialFormatError(MALFORMED_CREDENTIAL_MESSAGE)
    literal = f"{prefix}{key_id}_{secret}"
    if len(literal) > MAX_CREDENTIAL_LITERAL_LENGTH:
        raise ApiKeyCredentialFormatError(MALFORMED_CREDENTIAL_MESSAGE)
    return literal


def parse_literal(literal: str) -> ParsedCredential:
    """Parse a credential literal into its three segments or fail uniformly.

    Fixed order (decision 4's step (a)): the whole literal must be a
    non-empty string within the frozen 512 bound; it must start with one of
    the two fixed 8-char environment prefixes; the remainder splits at the
    **first** ``_`` into a non-empty key-id (exact Crockford-26 shape) and a
    non-empty secret (which may itself contain ``_``). Every violation
    raises :class:`ApiKeyCredentialFormatError` with the same message, so
    callers never learn which segment failed.
    """
    if not isinstance(literal, str) or not literal or len(literal) > MAX_CREDENTIAL_LITERAL_LENGTH:
        raise ApiKeyCredentialFormatError(MALFORMED_CREDENTIAL_MESSAGE)
    for candidate, prefix in ENVIRONMENT_PREFIXES.items():
        if literal.startswith(prefix):
            environment = candidate
            break
    else:
        raise ApiKeyCredentialFormatError(MALFORMED_CREDENTIAL_MESSAGE)
    key_id, separator, secret = literal[ENVIRONMENT_PREFIX_LENGTH:].partition("_")
    if not separator or not key_id or not secret:
        raise ApiKeyCredentialFormatError(MALFORMED_CREDENTIAL_MESSAGE)
    if _KEY_ID_RE.fullmatch(key_id) is None:
        raise ApiKeyCredentialFormatError(MALFORMED_CREDENTIAL_MESSAGE)
    return ParsedCredential(environment=environment, key_id=key_id, secret=secret)


def hash_secret(pepper: bytes, secret: str) -> str:
    """Return ``HMAC-SHA256(pepper, secret)`` as lowercase hex (decision 2).

    The pepper arrives as resolved bytes — callers obtain them from a
    :class:`~app.auth.pepper.PepperSource`; ≥ 32-byte enforcement belongs to
    the source's construction (decision 3), not to this pure function. An
    empty pepper is rejected outright because it would silently degrade the
    hash to an unpeppered HMAC.
    """
    if not isinstance(pepper, (bytes, bytearray, memoryview)):
        raise TypeError("pepper must be bytes")
    if not pepper:
        raise ValueError("pepper must be non-empty")
    return hmac.new(bytes(pepper), secret.encode("utf-8"), hashlib.sha256).hexdigest()


def secret_matches(stored_hash: str, pepper: bytes, candidate: str) -> bool:
    """Constant-time check of ``candidate`` against the stored digest.

    Recomputes :func:`hash_secret` and compares with
    :func:`hmac.compare_digest` over encoded bytes, so a malformed (e.g.
    non-ASCII) stored value cannot raise a distinguishable ``TypeError``
    either — a corrupt row simply never matches.
    """
    computed = hash_secret(pepper, candidate).encode("ascii")
    return hmac.compare_digest(computed, stored_hash.encode("utf-8"))


def dummy_secret_matches(pepper: bytes, candidate: str) -> bool:
    """Timing-equalized no-op comparison for the unknown-key-id branch.

    Performs the same HMAC + constant-time-comparison work as
    :func:`secret_matches` against :data:`DUMMY_SECRET_HASH` so that "key id
    not found" and "secret mismatch" take indistinguishable time (decision
    4: oracle-freedom on the timing axis, not just the message axis). The
    fixed digest is not derived from any real credential, so the result is
    always ``False`` for any achievable input; callers must fail the
    authentication regardless.
    """
    return secret_matches(DUMMY_SECRET_HASH, pepper, candidate)


__all__ = [
    "CROCKFORD_ALPHABET",
    "DUMMY_SECRET_HASH",
    "ENVIRONMENT_PREFIXES",
    "ENVIRONMENT_PREFIX_LENGTH",
    "KEY_ID_LENGTH",
    "KEY_ID_TIMESTAMP_CHARS",
    "MALFORMED_CREDENTIAL_MESSAGE",
    "MAX_CREDENTIAL_LITERAL_LENGTH",
    "SECRET_ENTROPY_BYTES",
    "ApiKeyCredentialFormatError",
    "ParsedCredential",
    "build_literal",
    "dummy_secret_matches",
    "generate_key_id",
    "generate_secret",
    "hash_secret",
    "parse_literal",
    "secret_matches",
]
