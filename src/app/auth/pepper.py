"""Pepper loading abstraction (Phase 05 task 1; spec §8, breakdown decision 3).

The *pepper* is the server-side secret that turns the stored credential
digest into ``HMAC-SHA256(pepper, secret)``: without it, a stolen database
yields nothing grindable offline. This module defines the seam, not the
source of truth:

- :class:`PepperSource` is a runtime-checkable protocol with a single
  ``current() -> bytes`` method. ``current()`` is deliberately a method
  rather than a stored attribute so a future rotation can hand out a new
  version without any consumer signature changing (rotation itself is a
  Phase 05 non-goal — one current version).
- :class:`StaticPepper` is the in-memory implementation used by tests and
  non-AWS deployments. It validates the **≥ 32-byte** floor at
  construction (pure, boot-safe: no I/O, no configuration import) and
  redacts itself everywhere — ``repr``/``str`` render as
  ``StaticPepper(<redacted>)``, and no pepper byte ever appears in an
  exception message, log record, or audit entry.

**Phase 07 obligation:** wire the AWS Secrets Manager implementation at the
deployment entrypoint behind this same protocol. Nothing here imports AWS
SDKs, so the no-``boto3`` proof stays green for everything Phase 05 ships.
"""

from __future__ import annotations

from typing import Final, Protocol, runtime_checkable

#: Minimum pepper length in bytes, enforced at construction (decision 3).
#: 32 bytes keeps the HMAC key at the SHA-256 block-size security level.
MIN_PEPPER_BYTES: Final = 32


@runtime_checkable
class PepperSource(Protocol):
    """Supplies the current pepper bytes to the credential layer.

    Implementations must be safe to construct at boot (pure) and must never
    expose the pepper through ``repr``/``str`` or error text.
    """

    def current(self) -> bytes:
        """Return the current pepper (at least :data:`MIN_PEPPER_BYTES`)."""
        ...


class StaticPepper:
    """A fixed in-memory :class:`PepperSource` (tests, non-AWS deployments).

    The pepper is copied on construction so a caller-held ``bytearray``
    cannot mutate the value afterwards, and it is stored only in a private
    attribute with both ``repr`` and ``str`` redacted.
    """

    def __init__(self, pepper: bytes) -> None:
        if not isinstance(pepper, (bytes, bytearray, memoryview)):
            raise TypeError("pepper must be bytes")
        value = bytes(pepper)
        if len(value) < MIN_PEPPER_BYTES:
            # Fixed description: the required floor and nothing else — the
            # supplied bytes never enter the message.
            raise ValueError(f"pepper must be at least {MIN_PEPPER_BYTES} bytes")
        self._pepper = value

    def current(self) -> bytes:
        """Return the static pepper bytes."""
        return self._pepper

    def __repr__(self) -> str:
        return "StaticPepper(<redacted>)"

    __str__ = __repr__


__all__ = ["MIN_PEPPER_BYTES", "PepperSource", "StaticPepper"]
