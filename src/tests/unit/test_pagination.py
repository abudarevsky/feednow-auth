"""Unit tests for pagination conventions (Phase 01 task 2)."""

from __future__ import annotations

import json

import pytest
from pydantic import BaseModel, ValidationError

from app.models.pagination import (
    DEFAULT_PAGE_LIMIT,
    MAX_PAGE_LIMIT,
    Page,
    PageParams,
    clamp_limit,
)


class _Item(BaseModel):
    name: str


def test_pinned_defaults():
    assert DEFAULT_PAGE_LIMIT == 20
    assert MAX_PAGE_LIMIT == 100
    assert PageParams().limit == DEFAULT_PAGE_LIMIT
    assert PageParams().cursor is None


@pytest.mark.parametrize(
    ("requested", "effective"),
    [
        (500, MAX_PAGE_LIMIT),  # clamped down to max
        (101, MAX_PAGE_LIMIT),
        (100, MAX_PAGE_LIMIT),  # at max stays
        (0, 1),  # clamped up to min
        (-10, 1),
        (1, 1),
        (50, 50),  # in range untouched
    ],
)
def test_limit_default_and_max_clamping(requested, effective):
    assert PageParams(limit=requested).limit == effective
    assert clamp_limit(requested) == effective


@pytest.mark.parametrize(
    ("requested", "effective"),
    [
        ("500", MAX_PAGE_LIMIT),  # query params arrive as strings
        ("0", 1),
        ("50", 50),
        (" 42 ", 42),
    ],
)
def test_limit_clamping_on_string_query_input(requested, effective):
    assert PageParams(limit=requested).limit == effective


def test_bool_limit_rejected():
    with pytest.raises(ValidationError):
        PageParams(limit=True)


def test_malformed_limit_still_rejected():
    with pytest.raises(ValidationError):
        PageParams(limit="not-a-number")


def test_page_params_and_page_reject_unknown_fields():
    with pytest.raises(ValidationError):
        PageParams(limit=10, offset=20)  # offset-style pagination is not the contract
    with pytest.raises(ValidationError):
        Page[_Item](items=[], total=3)


def test_cursor_is_treated_as_opaque_string():
    opaque = "b64:eyJrZXkiOiIxIn0=!!??~~~"  # content must not be interpreted
    page = Page[_Item](items=[{"name": "a"}], next_cursor=opaque)
    assert page.next_cursor == opaque
    params = PageParams(cursor=opaque)
    assert params.cursor == opaque
    # Round-trips byte-for-byte through JSON.
    assert json.loads(page.model_dump_json())["next_cursor"] == opaque


def test_empty_cursor_rejected():
    with pytest.raises(ValidationError):
        PageParams(cursor="")


def test_page_is_generic_and_typed():
    page = Page[_Item](items=[{"name": "a"}, _Item(name="b")])
    assert all(isinstance(item, _Item) for item in page.items)
    assert page.next_cursor is None  # final page by default
    payload = json.loads(page.model_dump_json())
    assert payload == {"items": [{"name": "a"}, {"name": "b"}], "limit": 20, "next_cursor": None}


def test_page_limit_bounds_are_enforced_not_clamped():
    # Page echoes an already-validated limit; out-of-bounds is a bug, not input.
    with pytest.raises(ValidationError):
        Page[_Item](items=[], limit=0)
    with pytest.raises(ValidationError):
        Page[_Item](items=[], limit=MAX_PAGE_LIMIT + 1)
    with pytest.raises(ValidationError):
        Page[_Item](items=[], limit="20x")
