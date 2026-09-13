"""Token-error hierarchy owned by Phase 03 (the auth boundary's error contract).

Three exceptions cover every failure the JWKS source and (from task 3) the
access-token verifier can raise:

- :class:`TokenValidationError` is the base for **claim/signature failures** —
  a token that the service will never accept. Producers pass a fixed, safe
  ``reason`` string; reasons must never embed token material, keys, or raw
  provider payloads (AGENTS.md no-secrets rule; task 3 pins the reason set).
- :class:`UnknownKeyIdError` is the specific claim-side failure "no signing
  key matched the (issuer, kid) pair". It subclasses ``TokenValidationError``
  so callers that only care about "this token is invalid" catch the base.
- :class:`TokenProviderUnavailableError` covers the **infrastructure** case:
  the provider's key set could not be fetched. It is deliberately *not* a
  ``TokenValidationError`` subclass — a provider outage is not the caller's
  bad token, and task 5 maps ``TokenValidationError`` → HTTP 401 while
  ``TokenProviderUnavailableError`` → HTTP 503. Sharing the base would let a
  naive ``except TokenValidationError`` (401) handler swallow outages unless
  catch order were pinned; the sibling shape keeps that mapping order-free.

HTTP mapping itself lives in ``app/api`` (task 5), exactly like the Phase 01
split between ``app.models.errors`` (codes) and ``app.api.errors`` (status).
"""

from __future__ import annotations


class TokenValidationError(Exception):
    """Base for token claim/signature failures that must never be accepted.

    ``reason`` is a fixed, human-readable, log-safe description chosen by the
    raising site — never interpolated token, key, or secret material.
    """

    def __init__(self, reason: str) -> None:
        if not reason.strip():
            raise ValueError("TokenValidationError reason must be a non-empty, safe string")
        self.reason = reason
        super().__init__(reason)


class UnknownKeyIdError(TokenValidationError):
    """No signing key in the issuer's key set matched the requested ``kid``.

    The default reason is fixed (no ``kid`` interpolation) so exception text
    stays a stable, safe description across raising sites.
    """

    def __init__(self, reason: str = "no signing key matches the token key id") -> None:
        super().__init__(reason)


class TokenProviderUnavailableError(Exception):
    """The identity provider's key set could not be fetched (outage, not a bad token).

    Task 5 maps this to HTTP 503; see the module docstring for why it is a
    sibling of :class:`TokenValidationError` rather than a subclass.
    """

    def __init__(self, reason: str = "identity provider key set is unavailable") -> None:
        if not reason.strip():
            raise ValueError("TokenProviderUnavailableError reason must be non-empty")
        self.reason = reason
        super().__init__(reason)


__all__ = ["TokenProviderUnavailableError", "TokenValidationError", "UnknownKeyIdError"]
