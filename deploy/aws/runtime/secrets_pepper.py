"""Secrets Manager pepper source for the AWS runtime (Phase 07 task 5).

The Phase 05 seam (:class:`app.auth.pepper.PepperSource`) mandates that the
AWS implementation live at the *deployment* entrypoint and never under
``src/app``: the repo-wide no-``boto3`` boot proof depends on that boundary.
This module is that implementation.

Contract:

- The secret id comes from ``FEEDNOW_PEPPER_SECRET_ID`` (a name, never
  material) or an explicit constructor argument.
- Construction is **pure** (no I/O, no SDK call), exactly as the protocol
  requires. The first :meth:`current` performs the single ``GetSecretValue``
  and caches the result for the container's lifetime; the composition root
  calls it once at cold start so a missing, unreadable, or undersized pepper
  fails before any request is served.
- The payload is JSON and the pepper lives in the ``pepper`` field — the
  field the Phase 07 CDK generates it under.
- The **≥ 32-byte** floor is enforced by delegating to
  :class:`~app.auth.pepper.StaticPepper`, so there is exactly one rule in
  the codebase.
- The value never appears in ``repr``/``str``, in ``__dict__`` renderings,
  or in any error message. Malformed-payload failures are raised with the
  context suppressed because ``json``/codec errors can quote the document.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Mapping
from typing import Any, Final

import boto3

from app.auth.pepper import MIN_PEPPER_BYTES, StaticPepper

#: Environment variable naming the pepper secret (a name, never material).
PEPPER_SECRET_ID_ENV: Final = "FEEDNOW_PEPPER_SECRET_ID"

#: JSON field the generated secret stores the pepper under. Must match the
#: CDK ``generate_string_key`` (Phase 07 task 4).
PEPPER_FIELD: Final = "pepper"

# Fixed, value-free failure descriptions. The secret material never enters
# an exception message, and the offending payload never rides along as a
# chained context (``from None``).
_MISSING_SECRET_ID: Final = f"{PEPPER_SECRET_ID_ENV} must name the API-key pepper secret"
_BAD_SHAPE: Final = (
    f"pepper secret must be a JSON object carrying a string '{PEPPER_FIELD}' field"
    f" of at least {MIN_PEPPER_BYTES} bytes"
)


class SecretsManagerPepper:
    """One :class:`~app.auth.pepper.PepperSource` read per container.

    ``client`` is the injectable seam for unit tests (the same pattern the
    Phase 06 adapter uses for ``dynamodb_resource``); when omitted a
    ``secretsmanager`` client is built on first use, which is still never at
    import time.
    """

    def __init__(
        self,
        secret_id: str | None = None,
        *,
        client: Any | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        resolved = secret_id
        if resolved is None:
            env = os.environ if environ is None else environ
            resolved = env.get(PEPPER_SECRET_ID_ENV)
        name = (resolved or "").strip()
        if not name:
            # The env var name is configuration, not secret material.
            raise ValueError(_MISSING_SECRET_ID)
        self._secret_id = name
        self._client = client
        self._static: StaticPepper | None = None
        self._lock = threading.Lock()

    @property
    def secret_id(self) -> str:
        """The configured secret name — safe to log, never the value."""
        return self._secret_id

    def current(self) -> bytes:
        """Return the cached pepper, fetching it exactly once.

        :raises ValueError: the secret is unreadable or its ``pepper`` field
            is missing, non-string, or shorter than
            :data:`~app.auth.pepper.MIN_PEPPER_BYTES`. The message is fixed
            and carries the secret *name* only.
        """
        with self._lock:
            if self._static is None:
                self._static = StaticPepper(self._fetch())
            return self._static.current()

    # -- internals -----------------------------------------------------------

    def _fetch(self) -> bytes:
        """Perform the single ``GetSecretValue`` and extract the pepper."""
        try:
            response = self._secrets_client().get_secret_value(SecretId=self._secret_id)
        except Exception as exc:  # boto3 ClientError and friends
            # Fixed text: nothing from the request or response is appended.
            raise ValueError(f"pepper secret {self._secret_id!r} is not readable") from exc
        return _parse_pepper(response, self._secret_id)

    def _secrets_client(self) -> Any:
        if self._client is None:
            self._client = boto3.client("secretsmanager")
        return self._client

    def __repr__(self) -> str:
        return "SecretsManagerPepper(<redacted>)"

    __str__ = __repr__


def _parse_pepper(response: Mapping[str, Any], secret_id: str) -> bytes:
    """Pull the ``pepper`` field out of one ``GetSecretValue`` response.

    Accepts the JSON ``SecretString`` (what the CDK-generated secret
    produces) and the ``SecretBinary`` form of the same JSON document. Every
    rejection is the one fixed message, raised with the context suppressed so
    no fragment of the payload can be rendered.
    """
    raw = response.get("SecretString")
    if raw is None:
        binary = response.get("SecretBinary")
        if isinstance(binary, bytes | bytearray | memoryview):
            raw = binary
    if not isinstance(raw, str | bytes | bytearray | memoryview):
        raise ValueError(f"pepper secret {secret_id!r} is empty: {_BAD_SHAPE}") from None
    try:
        document = bytes(raw) if not isinstance(raw, str) else raw.encode("utf-8")
        payload = json.loads(document.decode("utf-8"))
        field = payload[PEPPER_FIELD] if isinstance(payload, dict) else None
    except (UnicodeDecodeError, ValueError, KeyError, TypeError):
        # ``from None``: JSON/codec errors quote the offending document.
        raise ValueError(f"pepper secret {secret_id!r} is malformed: {_BAD_SHAPE}") from None
    if not isinstance(field, str) or not field:
        raise ValueError(f"pepper secret {secret_id!r} is malformed: {_BAD_SHAPE}") from None
    return field.encode("utf-8")


__all__ = ["PEPPER_FIELD", "PEPPER_SECRET_ID_ENV", "SecretsManagerPepper"]
