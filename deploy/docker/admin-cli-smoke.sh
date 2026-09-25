#!/usr/bin/env bash
# admin-cli-smoke.sh — container proof for the Phase 13 administrator CLI.
#
# Builds the cognito-profile image and proves, entirely inside containers,
# that the operator CLI (python -m feednow_auth.admin) works against the
# /data SQLite volume:
#
#   1. seeds one user (+ its active-organization audit anchor) through the
#      storage API via a one-shot `docker compose run --rm` python snippet;
#   2. `grant` exits 0 and the ADMIN role is persisted (read back through
#      the storage API in a separate container);
#   3. a repeat `grant` exits 0 printing "already granted" (idempotent
#      no-op, no duplicate audit);
#   4. `revoke` of the last active administrator exits 5 and mutates
#      nothing.
#
# The database is a per-run file on the shared `feednow-data` volume, so
# the smoke never touches the app's own SQLite file and the last-admin
# assertion is deterministic. Output is limited to fixed messages and
# internal ids; nothing secret is printed. The Compose file and Dockerfile
# are consumed unchanged (the CLI ships via `uv sync --no-dev` in the prod
# image and is never invoked at startup).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

#: Fixed smoke constants; the per-run db path keeps runs hermetic.
EMAIL="admin-cli-smoke@example.invalid"
USER_ID="usr_smoke_admin"
SMOKE_DB="/data/admin-cli-smoke-$(date +%s)-$$.db"

COMPOSE=(docker compose --profile cognito)
#: CLI-facing storage factory env (docs/RUNNING_WITH_COGNITO.md §10).
STORAGE_ENV=(-e FEEDNOW_STORAGE_BACKEND=sqlite -e "FEEDNOW_SQLITE_PATH=${SMOKE_DB}")
#: Seed/read-back snippets resolve the fixed identities from the env.
SEED_IDS=(-e "SMOKE_EMAIL=${EMAIL}" -e "SMOKE_USER_ID=${USER_ID}")

fail() {
    echo "[smoke] FAILED: $*" >&2
    exit 1
}

cleanup() {
    # Best-effort removal of the per-run database; never masks the exit code.
    "${COMPOSE[@]}" run --rm app rm -f "${SMOKE_DB}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || fail "docker is not available"
docker info >/dev/null 2>&1 || fail "docker daemon is not reachable"

echo "[smoke] building cognito-profile image"
"${COMPOSE[@]}" build app

echo "[smoke] seeding user ${USER_ID}"
"${COMPOSE[@]}" run --rm "${STORAGE_ENV[@]}" "${SEED_IDS[@]}" app python -c '
import os
from datetime import UTC, datetime

from app.models.enums import (
    ApplicationRole,
    MembershipRole,
    MembershipStatus,
    OrganizationStatus,
    OrganizationType,
    UserStatus,
)
from app.models.ids import MembershipId, OrganizationId, UserId
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.user import User
from app.storage.factory import create_storage, storage_settings_from_env

user_id = UserId(os.environ["SMOKE_USER_ID"])
t0 = datetime(2026, 9, 25, 0, 0, 0, tzinfo=UTC)
storage = create_storage(storage_settings_from_env(os.environ))
try:
    storage.create_user(
        User(
            id=user_id,
            display_name="smoke admin",
            email=os.environ["SMOKE_EMAIL"],
            status=UserStatus.ACTIVE,
            application_role=ApplicationRole.USER,
            created_at=t0,
            updated_at=t0,
        )
    )
    storage.create_organization(
        Organization(
            id=OrganizationId("org_smoke_anchor"),
            name="Smoke Anchor",
            slug="org-smoke-anchor",
            type=OrganizationType.CUSTOMER,
            status=OrganizationStatus.ACTIVE,
            created_at=t0,
            updated_at=t0,
        )
    )
    storage.create_membership(
        Membership(
            id=MembershipId("mem_smoke_anchor"),
            organization_id=OrganizationId("org_smoke_anchor"),
            user_id=user_id,
            role=MembershipRole.OWNER,
            status=MembershipStatus.ACTIVE,
            created_at=t0,
        )
    )
finally:
    storage.close()
print("seeded", user_id)
' || fail "seed container did not exit 0"

#: Run one CLI command; stdout+stderr land in LAST_OUT, exit code is returned.
run_admin() {
    local out code
    set +e
    out="$("${COMPOSE[@]}" run --rm "${STORAGE_ENV[@]}" app \
        python -m feednow_auth.admin "$@" 2>&1)"
    code=$?
    set -e
    LAST_OUT="${out}"
    return "${code}"
}

echo "[smoke] grant: expecting exit 0"
grant_code=0
run_admin grant --email "${EMAIL}" || grant_code=$?
if [[ "${grant_code}" -ne 0 ]]; then
    echo "[smoke] grant output: ${LAST_OUT}" >&2
    fail "grant exited ${grant_code}, expected 0"
fi
case "${LAST_OUT}" in
    *"granted ${EMAIL}"*) : ;;
    *) echo "[smoke] grant output: ${LAST_OUT}" >&2
       fail "grant did not report the transition" ;;
esac

echo "[smoke] role persisted: reading back through the storage API"
"${COMPOSE[@]}" run --rm "${STORAGE_ENV[@]}" "${SEED_IDS[@]}" app python -c '
import os

from app.models.enums import ApplicationRole
from app.models.ids import UserId
from app.storage.factory import create_storage, storage_settings_from_env

storage = create_storage(storage_settings_from_env(os.environ))
try:
    user = storage.get_user(UserId(os.environ["SMOKE_USER_ID"]))
finally:
    storage.close()
if user.application_role is not ApplicationRole.ADMIN:
    raise SystemExit(97)
print("role=admin for", user.id)
' || fail "persisted role is not admin after grant"

echo "[smoke] repeat grant: expecting exit 0 with 'already granted'"
repeat_code=0
run_admin grant --email "${EMAIL}" || repeat_code=$?
if [[ "${repeat_code}" -ne 0 ]]; then
    echo "[smoke] repeat grant output: ${LAST_OUT}" >&2
    fail "repeat grant exited ${repeat_code}, expected 0"
fi
case "${LAST_OUT}" in
    *"already granted ${EMAIL}"*) : ;;
    *) echo "[smoke] repeat grant output: ${LAST_OUT}" >&2
       fail "repeat grant did not report 'already granted'" ;;
esac

echo "[smoke] revoke last admin: expecting exit 5"
revoke_code=0
run_admin revoke --email "${EMAIL}" || revoke_code=$?
if [[ "${revoke_code}" -ne 5 ]]; then
    echo "[smoke] revoke output: ${LAST_OUT}" >&2
    fail "last-admin revoke exited ${revoke_code}, expected 5"
fi
case "${LAST_OUT}" in
    *"last active administrator"*) : ;;
    *) echo "[smoke] revoke output: ${LAST_OUT}" >&2
       fail "last-admin revoke did not report the refusal" ;;
esac

echo "[smoke] PASS: container CLI grant/idempotency/last-admin-refusal verified"
