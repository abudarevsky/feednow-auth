"""Storage package: contract surface here, adapters by explicit submodule path.

``app/storage/__init__.py`` re-exports **contract symbols only** and must never
import an adapter module (``sqlite``, later ``dynamodb``). Adapters are
imported explicitly: ``from app.storage.sqlite import open_sqlite_storage``.

Keeping the package initializer adapter-free means application code typed
against :class:`~app.storage.contract.Storage` never loads a driver, and the
subprocess-isolated import check in the storage implementation tests proves it.

Current behavior and invariants: ``docs/storage.md``."""

from app.storage.contract import (
    DuplicateEntityError,
    DuplicateEntityKind,
    DuplicateExternalIdentityError,
    EntityNotFoundError,
    InvalidCursorError,
    LastActiveAdministratorError,
    ProvisionedOrganization,
    ProvisionedUser,
    ReferenceNotFoundError,
    RoleTransition,
    RoleTransitionOutcome,
    Storage,
    StorageError,
)

__all__ = [
    "DuplicateEntityError",
    "DuplicateEntityKind",
    "DuplicateExternalIdentityError",
    "EntityNotFoundError",
    "InvalidCursorError",
    "LastActiveAdministratorError",
    "ProvisionedOrganization",
    "ProvisionedUser",
    "ReferenceNotFoundError",
    "RoleTransition",
    "RoleTransitionOutcome",
    "Storage",
    "StorageError",
]
