"""Server-side global-administrator dependency (Phase 13 task 4; spec 13
required behavior 6).

The one seam a future application-administration surface will mount: it
composes the published Phase 05 :func:`~app.auth.dependencies.
build_current_principal` (so both actor kinds — human and API-key — are
authenticated by the existing dispatch and reach this module already
resolved) and enforces the **global** grant rule on top:

- granted: the principal is human (``principal.user is not None``) **and**
  ``principal.user.application_role is ApplicationRole.ADMIN`` — the same
  :class:`~app.auth.principal.Principal` is returned verbatim;
- denied: every other outcome — ordinary humans, and **every** API-key
  variant, including a key whose creating user is an ADMIN — answers the
  **same uniform 403** with the one fixed module-level message below.

The key refusal is structural, not a lookup: the API-key branch of the
dispatch yields ``principal.user is None`` and API-key contexts stay
roleless (spec 12 invariant 7), so no key can ever borrow its owner's
application role and no ``key_`` → ``usr_`` reverse lookup exists to be
raced or missed. The message echoes no role, key, or identity material
(AGENTS.md): one body for every denial shape, so the endpoint is not an
oracle for "is this a key", "does this user exist", or "what is their
role".

Denials are **not audited here**: this seam carries no ``operation_id``
(contrast the org-local ``organization_access`` policy) and spec 13 pins
the reviewed audit to the out-of-band administration transition itself,
not to probes of an HTTP surface that does not exist yet. This phase
mounts the dependency on **no** production route — the frozen endpoint
manifest is unchanged and organization-membership administration keeps
its separate org-local role policy (spec 13 required behavior 6, last
sentence). Authentication still precedes authorization: a first-login
human auto-provisions (as on ``/v1/me`` and the org seams) and is then
denied as an ordinary ``USER``.
"""

# No ``from __future__ import annotations`` here on purpose (the
# ``organization_access.py`` precedent): the dependency signature references
# the closure-local ``current_principal`` in ``Annotated[..., Depends(...)]``
# position, and PEP 563 stringified annotations could not resolve it at
# import time.
from collections.abc import Callable
from typing import Annotated, Final

from fastapi import Depends, HTTPException

from app.auth.cognito import AccessTokenVerifier, ProfileSource
from app.auth.dependencies import build_current_principal
from app.auth.pepper import PepperSource
from app.auth.principal import Principal
from app.models.enums import ApplicationRole
from app.storage.contract import Storage

#: The one fixed 403 message for every denial shape (uniform, existence-
#: oracle-free, credential-free — mirrors the Phase 04/05 denial discipline).
APPLICATION_ADMIN_FORBIDDEN_MESSAGE: Final = (
    "you do not have permission to administer the application"
)


def build_application_admin_dependency(
    storage: Storage,
    verifier: AccessTokenVerifier,
    pepper_source: PepperSource,
    profile_source: ProfileSource | None = None,
) -> Callable[..., Principal]:
    """Return the ``Principal`` dependency restricted to application admins.

    A pure wiring factory (no I/O at construction, import-safe — the same
    shape as :func:`~app.auth.dependencies.build_current_user`): it closes
    over the injected seams and composes the prefix-dispatching principal
    chain, so ``pepper_source`` is **required** — the key branch must be
    reachable in order to be refused (a key that never authenticated would
    answer the 401 class, not this 403 class).

    ``profile_source`` (Phase 11) is forwarded to the human branch of the
    composed chain; it only ever matters for a first-login identity miss,
    which then faces the same denial as any other non-admin. The granted
    return is the dispatch's :class:`~app.auth.principal.Principal`
    verbatim — handlers reach the admin's ``usr_`` through its unchanged
    §10 context.
    """
    current_principal = build_current_principal(storage, verifier, pepper_source, profile_source)

    def application_admin_principal(
        principal: Annotated[Principal, Depends(current_principal)],
    ) -> Principal:
        """Grant application admins; answer every other outcome 403."""
        if principal.user is not None and principal.user.application_role is ApplicationRole.ADMIN:
            return principal
        raise HTTPException(status_code=403, detail=APPLICATION_ADMIN_FORBIDDEN_MESSAGE)

    return application_admin_principal


__all__ = [
    "APPLICATION_ADMIN_FORBIDDEN_MESSAGE",
    "build_application_admin_dependency",
]
