"""Application administrator bootstrap and revocation (admin).

Service layer over the :class:`~app.storage.contract.Storage` protocol only —
no HTTP, no CLI, no adapter imports (AGENTS.md boundary). It discharges contract
13 required behaviors 1, 2, 3, and 7 for the grant/revoke half that the implementation
CLI will call:

- :func:`resolve_unique_user` turns an operator-supplied exact email into
  exactly one internal :class:`~app.models.user.User` via the contract's
  bounded :meth:`~app.storage.contract.Storage.list_users_by_email` lookup.
  application-role made email non-unique, so zero/one/many is the caller's explicit
  problem: zero → :class:`AdministratorNotFoundError`, many →
  :class:`AmbiguousAdministratorEmailError` (message carries the count and the
  ``usr_`` ids only — never provider material), and neither path writes.
- :func:`grant_administrator` (``USER → ADMIN``) and
  :func:`revoke_administrator` (``ADMIN → USER``) resolve the unique user,
  form the audit event, and hand **one** caller-formed
  :class:`~app.models.audit_event.AuditEvent` to the single atomic
  :meth:`~app.storage.contract.Storage.transition_application_role` operation
  (contract 13 required behavior 3: the last-ACTIVE-admin guard and the CAS are
  the adapter's concurrency-safe job — this service never composes a
  check-then-write and never provisions users).
- The adapter outcome maps 1:1: ``TRANSITIONED`` means the role write and the
  audit row committed together; ``NO_CHANGE`` is the idempotent no-op the
  adapter already skipped — the service asserts the outcome and **never**
  re-appends, so repeated grants/revokes create no duplicate audits (required
  behavior 7). :class:`~app.storage.contract.LastActiveAdministratorError`
  propagates untranslated: the refusal is a storage-domain outcome, and CLI
  exit-code mapping is implementation's caller-side concern.

Audit formation (required behavior 7, pinned by the design notes):

- ``action`` is exactly ``user.application_role.granted`` /
  ``user.application_role.revoked``; ``target_type="user"``; ``target_id`` is
  the affected ``usr_``.
- ``metadata`` is exactly ``{"from_role", "to_role"}`` — no email, no Cognito
  ``sub``, no token, no auth code.
- ``actor_type="user"``/``actor_id=`` the **affected user**: the pinned
  out-of-band decision, because the CLI has no operator identity to record
  and the :data:`~app.models.authorization_context.ActorType` vocabulary is
  frozen.
- ``organization_id`` is the user's **earliest active** organization via
  ``list_user_organizations(user_id, PageParams(limit=1))`` — the same
  deterministic anchor ``/v1/me`` uses (storage pins ``(created_at, id)``
  ascending over active memberships). No active organization →
  :class:`AdministratorAuditAnchorMissingError` raised **before** any
  transition call, so the refusal mutates nothing.

Clock and entropy: exactly **one** injected ``now`` read and **one** ``ids()``
mint per command (both default to the production sources; the ``ids`` seam is
the single-audit-id factory from :mod:`app.services.idgen`, not the
provisioning :class:`~app.services.identity.ProvisioningIds` bag — this
service mints exactly one ``aud_`` id and no entity ids). The same timestamp
stamps ``updated_at`` and the audit's ``created_at``, mirroring the identity
service's single-clock discipline. Storage mints nothing.

Current behavior and invariants: ``docs/administration.md``."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from app.models.audit_event import AuditEvent
from app.models.enums import ApplicationRole
from app.models.ids import AuditEventId, OrganizationId, UserId
from app.models.pagination import PageParams
from app.models.timestamps import UtcDatetime, utc_now
from app.models.user import User
from app.services.idgen import new_audit_event_id
from app.storage.contract import (
    RoleTransition,
    Storage,
)

#: Canonical audit action vocabulary for the two administration transitions
#: (spec 13; the ``AuditAction`` bounded free string stays open by design —
#: :mod:`app.models.audit_event`).
GRANT_ACTION = "user.application_role.granted"
REVOKE_ACTION = "user.application_role.revoked"


class AdministratorNotFoundError(Exception):
    """No user carries the requested email address (contract 13 behavior 1).

    The message is fixed and carries no email or provider material; the CLI
    echoes the operator-supplied address itself if it wants to.
    """

    def __init__(self, message: str = "no user exists for this email address") -> None:
        super().__init__(message)


class AmbiguousAdministratorEmailError(Exception):
    """More than one user carries the requested email (application-role made email
    non-unique, contract 13 behavior 1).

    ``user_ids`` keeps the candidate ``usr_`` identities machine-readable for
    the CLI (implementation lists them on stderr); the message carries **only** the
    count and the ``usr_`` ids — never provider material, and not even the
    email, which the operator already holds.
    """

    def __init__(self, count: int, user_ids: Sequence[UserId]) -> None:
        #: Number of distinct users that matched the exact email.
        self.count = count
        #: The candidate ``usr_`` identities, in the contract's
        #: ``(created_at, id)`` order.
        self.user_ids: tuple[UserId, ...] = tuple(user_ids)
        listed = ", ".join(str(user_id) for user_id in self.user_ids)
        super().__init__(f"{count} users share this email address: {listed}")


class AdministratorAuditAnchorMissingError(Exception):
    """The user has no active organization to anchor the transition audit.

    Raised **before** any transition call, so the refusal leaves storage
    untouched (the audit FK parent must exist at commit time, and every
    registered user is provisioned with a personal organization — reaching
    this error means the user's memberships are all suspended or gone).
    Fixed safe message; no user, email, or organization material.
    """

    def __init__(
        self,
        message: str = "user has no active organization to anchor the audit",
    ) -> None:
        super().__init__(message)


def resolve_unique_user(storage: Storage, email: str) -> User:
    """Resolve ``email`` to exactly one user or refuse — read-only either way.

    One :meth:`~app.storage.contract.Storage.list_users_by_email` exact-match
    read; zero matches → :class:`AdministratorNotFoundError`, more than one →
    :class:`AmbiguousAdministratorEmailError`. Neither failure path writes, and
    this function performs no other storage call.
    """
    users = storage.list_users_by_email(email)
    if not users:
        raise AdministratorNotFoundError()
    if len(users) > 1:
        raise AmbiguousAdministratorEmailError(len(users), [user.id for user in users])
    return users[0]


def grant_administrator(
    storage: Storage,
    email: str,
    *,
    now: Callable[[], UtcDatetime] = utc_now,
    ids: Callable[[], AuditEventId] = new_audit_event_id,
) -> RoleTransition:
    """Promote the unique user for ``email`` to ``ADMIN`` (idempotent).

    Delegates every decision to :func:`_transition_role` with
    ``expected_role=USER``/``new_role=ADMIN``; granting an existing admin
    returns the adapter's ``NO_CHANGE`` no-op. Returns the adapter's
    :class:`~app.storage.contract.RoleTransition` so the CLI can distinguish
    "granted" from "already granted".
    """
    return _transition_role(
        storage,
        email,
        expected_role=ApplicationRole.USER,
        new_role=ApplicationRole.ADMIN,
        action=GRANT_ACTION,
        now=now,
        ids=ids,
    )


def revoke_administrator(
    storage: Storage,
    email: str,
    *,
    now: Callable[[], UtcDatetime] = utc_now,
    ids: Callable[[], AuditEventId] = new_audit_event_id,
) -> RoleTransition:
    """Demote the unique user for ``email`` to ``USER`` (idempotent).

    Same pipeline as :func:`grant_administrator` with the direction flipped.
    Demoting the **last active** administrator propagates
    :class:`~app.storage.contract.LastActiveAdministratorError` untranslated —
    the adapter checked and refused atomically, and this service never
    re-checks. Revoking an existing plain user returns ``NO_CHANGE``.
    """
    return _transition_role(
        storage,
        email,
        expected_role=ApplicationRole.ADMIN,
        new_role=ApplicationRole.USER,
        action=REVOKE_ACTION,
        now=now,
        ids=ids,
    )


def _audit_anchor(storage: Storage, user: User) -> OrganizationId:
    """The user's earliest **active** organization — the audit parent.

    ``list_user_organizations`` already filters to active memberships and
    orders ``(created_at, id)`` ascending, so page 1 item 1 is the same
    deterministic anchor ``/v1/me`` resolves. Zero items →
    :class:`AdministratorAuditAnchorMissingError` (raised by the caller
    before any transition, so the refusal mutates nothing).
    """
    page = storage.list_user_organizations(user.id, PageParams(limit=1))
    if not page.items:
        raise AdministratorAuditAnchorMissingError()
    return page.items[0].id


def _transition_role(
    storage: Storage,
    email: str,
    *,
    expected_role: ApplicationRole,
    new_role: ApplicationRole,
    action: str,
    now: Callable[[], UtcDatetime],
    ids: Callable[[], AuditEventId],
) -> RoleTransition:
    """Shared grant/revoke pipeline: resolve → anchor → form → transition.

    Exactly one clock read and one ``aud_`` mint, and only on the path that
    reaches the transition (resolution and anchor refusals consume neither).
    The single :meth:`~app.storage.contract.Storage.transition_application_role`
    call commits role write + audit append atomically, or skips both
    (``NO_CHANGE``), or refuses both (guard errors propagate untranslated).
    """
    user = resolve_unique_user(storage, email)
    organization_id = _audit_anchor(storage, user)
    timestamp = now()
    audit_event = AuditEvent(
        id=ids(),
        organization_id=organization_id,
        actor_type="user",
        actor_id=user.id,
        action=action,
        target_type="user",
        target_id=str(user.id),
        metadata={"from_role": expected_role.value, "to_role": new_role.value},
        created_at=timestamp,
    )
    return storage.transition_application_role(
        user_id=user.id,
        expected_role=expected_role,
        new_role=new_role,
        updated_at=timestamp,
        audit_event=audit_event,
    )


__all__ = [
    "GRANT_ACTION",
    "REVOKE_ACTION",
    "AdministratorAuditAnchorMissingError",
    "AdministratorNotFoundError",
    "AmbiguousAdministratorEmailError",
    "grant_administrator",
    "resolve_unique_user",
    "revoke_administrator",
]
