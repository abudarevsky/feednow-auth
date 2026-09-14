"""Unit tests for Phase 05 task 1 pepper abstraction (:mod:`app.auth.pepper`).

Verify lines covered (per the Phase 05 breakdown, task 1 / decision 3):

1. :class:`StaticPepper` rejects peppers shorter than 32 bytes — with an
   exception message that never contains the supplied pepper material.
2. ``repr``/``str`` are redacted: no pepper byte appears in either.
3. ``current()`` returns the constructed pepper; construction is pure and
   mutation-safe (bytearray input is copied).
4. :class:`PepperSource` is a runtime-checkable protocol satisfied by
   ``StaticPepper`` and by any duck-typed ``current()`` implementation —
   the seam Phase 07 wires to Secrets Manager without touching consumers.
"""

from __future__ import annotations

import contextlib

import pytest

from app.auth.pepper import MIN_PEPPER_BYTES, PepperSource, StaticPepper

#: Fixed 32-byte pepper for the happy-path fixtures.
PEPPER = b"0123456789abcdef0123456789abcdef"

#: A 31-byte pepper whose ASCII form is easy to detect in any leak.
MARKED_SHORT_PEPPER = b"leak-check-marked-pepper-31byte"


def _assert_no_pepper_bytes(rendered: str, pepper: bytes) -> None:
    """Neither the raw bytes nor any printable run of them may appear."""
    if not pepper:  # the empty sequence is a substring of everything
        return
    assert pepper not in rendered.encode("utf-8", errors="ignore")
    assert repr(pepper) not in rendered
    with contextlib.suppress(UnicodeDecodeError):  # pragma: no cover - ASCII fixtures
        assert pepper.decode("ascii") not in rendered


# -- 1. Length floor ----------------------------------------------------------


def test_min_pepper_bytes_is_32():
    assert MIN_PEPPER_BYTES == 32


def test_accepts_exactly_32_bytes():
    source = StaticPepper(PEPPER)
    assert source.current() == PEPPER


def test_accepts_longer_peppers():
    longer = PEPPER + b"-and-more-entropy-here"
    assert StaticPepper(longer).current() == longer


@pytest.mark.parametrize("short", [b"", b"x", b"x" * 31, MARKED_SHORT_PEPPER])
def test_rejects_peppers_below_32_bytes(short):
    with pytest.raises(ValueError) as excinfo:
        StaticPepper(short)
    assert str(MIN_PEPPER_BYTES) in str(excinfo.value)
    # The message describes the floor, never the supplied material.
    _assert_no_pepper_bytes(str(excinfo.value), short)


@pytest.mark.parametrize("wrong_type", ["0123456789abcdef0123456789abcdef", 42, None])
def test_rejects_non_bytes_with_typeerror(wrong_type):
    with pytest.raises(TypeError) as excinfo:
        StaticPepper(wrong_type)  # type: ignore[arg-type]
    _assert_no_pepper_bytes(str(excinfo.value), b"0123456789abcdef0123456789abcdef")


# -- 2. Redaction -------------------------------------------------------------


def test_repr_and_str_are_redacted():
    source = StaticPepper(PEPPER)
    for rendered in (repr(source), str(source), f"{source}", f"{source!r}"):
        assert rendered == "StaticPepper(<redacted>)"
        _assert_no_pepper_bytes(rendered, PEPPER)


def test_pepper_not_exposed_via_public_attributes():
    source = StaticPepper(PEPPER)
    public_values = [getattr(source, name) for name in dir(source) if not name.startswith("_")]
    assert PEPPER not in public_values


# -- 3. Purity and mutation-safety --------------------------------------------


def test_current_returns_bytes():
    assert isinstance(StaticPepper(PEPPER).current(), bytes)


def test_bytearray_input_is_copied_at_construction():
    mutable = bytearray(PEPPER)
    source = StaticPepper(mutable)
    mutable[0] ^= 0xFF  # caller mutates after construction
    assert source.current() == PEPPER


def test_construction_is_pure_and_repeatable():
    first = StaticPepper(PEPPER)
    second = StaticPepper(PEPPER)
    assert first.current() == second.current()


# -- 4. The protocol seam ------------------------------------------------------


def test_static_pepper_satisfies_the_protocol():
    assert isinstance(StaticPepper(PEPPER), PepperSource)


def test_protocol_is_runtime_checkable():
    assert getattr(PepperSource, "_is_runtime_protocol", False) is True


def test_duck_typed_source_satisfies_the_protocol():
    class RotatingPepper:
        """Shape-only stand-in for the Phase 07 Secrets Manager source."""

        def current(self) -> bytes:
            return PEPPER

    assert isinstance(RotatingPepper(), PepperSource)


def test_source_without_current_does_not_satisfy_the_protocol():
    class NoPepper:
        pass

    assert not isinstance(NoPepper(), PepperSource)
