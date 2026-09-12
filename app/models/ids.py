"""Typed, prefix-validated FeedNow identifier value objects.

Conventions (Phase 01 contract, frozen for downstream phases):

- Application-identity IDs (``usr_``, ``org_``, ``key_``) are the only values
  that may appear as ``actor_id``/path parameters in the API (spec §10, §14).
  They are modeled by :class:`ApplicationId` subclasses.
- Record IDs (``extid_``, ``mem_``, ``aud_``) identify stored rows for
  ExternalIdentity, Membership, and AuditEvent. They are internal and must
  never surface as ``actor_id`` or in §14 path parameters. They are modeled
  by :class:`RecordId` subclasses.
- Provider subjects (Cognito ``sub``, Shopify IDs, ...) are plain constrained
  strings (:data:`ProviderSubject`), never ID value objects. Email, Cognito
  ``sub``, and Shopify IDs must never be coerced into application identity.
- Concrete generation strategies (entropy source, ULID-style ``key_id`` per
  spec §8) belong to owner phases 03/05; this module only *validates*
  prefixes and shape so Phase 01 cannot become the de facto entropy contract.

All ID types are immutable ``str`` subclasses: they serialize as plain JSON
strings, hash/equal like strings, and are distinguished by their concrete
type and prefix.
"""

from __future__ import annotations

import re
from typing import Annotated, ClassVar, Self

from pydantic import GetJsonSchemaHandler, StringConstraints
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import CoreSchema, core_schema

#: Character set allowed after the prefix. Deliberately permissive so the
#: generation strategies chosen in Phases 03/05 (e.g. ULID/Crockford base32)
#: all validate without a Phase 01 change.
ID_SUFFIX_PATTERN = r"[0-9A-Za-z_-]+"

#: Hard length cap for any ID value (prefix + separator + suffix).
MAX_ID_LENGTH = 128

_SUFFIX_RE = re.compile(ID_SUFFIX_PATTERN)


class _PrefixedId(str):
    """Immutable, prefix-validated string identifier. Not used directly."""

    #: Concrete subclasses set this to their bare prefix (without ``_``).
    prefix: ClassVar[str] = ""

    def __new__(cls, value: str, *_args: object) -> Self:
        if not cls.prefix:  # pragma: no cover - guards abstract bases
            raise TypeError(f"{cls.__name__} is abstract; use a concrete ID type")
        if not isinstance(value, str):
            raise TypeError(f"{cls.__name__} expects a str, got {type(value).__name__}")
        return super().__new__(cls, cls._validated(value))

    @classmethod
    def _validated(cls, value: str) -> str:
        expected = f"{cls.prefix}_"
        if not value.startswith(expected):
            raise ValueError(f"{cls.__name__} must start with '{expected}'")
        suffix = value[len(expected) :]
        if not suffix:
            raise ValueError(f"{cls.__name__} must have a non-empty suffix after '{expected}'")
        if _SUFFIX_RE.fullmatch(suffix) is None:
            raise ValueError(
                f"{cls.__name__} suffix must match '{ID_SUFFIX_PATTERN}', got {suffix!r}"
            )
        if len(value) > MAX_ID_LENGTH:
            raise ValueError(f"{cls.__name__} must be at most {MAX_ID_LENGTH} characters")
        return value

    # -- Pydantic v2 integration -------------------------------------------

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source_type: object,
        handler: GetJsonSchemaHandler,
    ) -> CoreSchema:
        return core_schema.no_info_plain_validator_function(
            cls._pydantic_validate,
            serialization=core_schema.to_string_ser_schema(),
        )

    @classmethod
    def _pydantic_validate(cls, value: object) -> Self:
        if isinstance(value, str):
            # Re-validating an existing instance is cheap and keeps
            # construction the single source of truth for the shape rules.
            return cls(value)
        raise ValueError(f"{cls.__name__} expects a string, got {type(value).__name__}")

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        core_schema_: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> JsonSchemaValue:
        return {
            "type": "string",
            "title": cls.__name__,
            "pattern": f"^{cls.prefix}_{ID_SUFFIX_PATTERN}$",
            "maxLength": MAX_ID_LENGTH,
            "description": f"FeedNow {cls.__name__} identifier (prefix '{cls.prefix}_').",
        }


class ApplicationId(_PrefixedId):
    """Base for IDs that act as FeedNow application identities (spec §10)."""


class RecordId(_PrefixedId):
    """Base for internal record IDs of stored rows (never API identities)."""


class UserId(ApplicationId):
    """Internal FeedNow user identifier (``usr_``)."""

    prefix: ClassVar[str] = "usr"


class OrganizationId(ApplicationId):
    """Internal FeedNow organization identifier (``org_``)."""

    prefix: ClassVar[str] = "org"


class ApiKeyId(ApplicationId):
    """Internal FeedNow API key identifier (``key_``).

    Distinct from the non-secret ``key_id`` credential segment inside
    ``fn_live_<key-id>_<secret>`` (spec §8), which is owned by Phase 05.
    """

    prefix: ClassVar[str] = "key"


class ExternalIdentityId(RecordId):
    """Record ID of an ExternalIdentity row (``extid_``). Internal only."""

    prefix: ClassVar[str] = "extid"


class MembershipId(RecordId):
    """Record ID of a Membership row (``mem_``). Internal only."""

    prefix: ClassVar[str] = "mem"


class AuditEventId(RecordId):
    """Record ID of an AuditEvent row (``aud_``). Internal only."""

    prefix: ClassVar[str] = "aud"


#: ``AuthorizationContext.actor_id`` (spec §10) is either a user or an API
#: key application identity — never a record ID and never a provider subject.
ActorId = UserId | ApiKeyId

#: Provider-side subject (Cognito ``sub``, Shopify shop ID, OIDC ``sub``, ...).
#: A plain constrained string by design: it must never be coerced into, or
#: modeled as, an ID value object (AGENTS.md: internal IDs are the identity).
ProviderSubject = Annotated[str, StringConstraints(min_length=1, max_length=255)]

__all__ = [
    "ID_SUFFIX_PATTERN",
    "MAX_ID_LENGTH",
    "ActorId",
    "ApiKeyId",
    "ApplicationId",
    "AuditEventId",
    "ExternalIdentityId",
    "MembershipId",
    "OrganizationId",
    "ProviderSubject",
    "RecordId",
    "UserId",
]
