from datetime import UTC, datetime

from app.models.enums import (
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
from app.storage.contract import EntityNotFoundError
from app.storage.sqlite import SQLiteStorage

NOW = datetime(2026, 9, 26, 10, 0, tzinfo=UTC)


def make_user(user_id: str) -> User:
    return User(
        id=UserId(user_id),
        display_name="New User",
        email=f"{user_id}@example.com",
        status=UserStatus.ACTIVE,
        created_at=NOW,
        updated_at=NOW,
    )


def make_org(org_id: str, name: str) -> Organization:
    return Organization(
        id=OrganizationId(org_id),
        name=name,
        slug=org_id,
        type=OrganizationType.CUSTOMER,
        status=OrganizationStatus.ACTIVE,
        created_at=NOW,
        updated_at=NOW,
    )


def add_membership(storage: SQLiteStorage, org_id: str, user_id: str, suffix: str) -> None:
    storage.create_membership(
        Membership(
            id=MembershipId(f"mem_test_{suffix}"),
            organization_id=OrganizationId(org_id),
            user_id=UserId(user_id),
            role=MembershipRole.OWNER,
            status=MembershipStatus.ACTIVE,
            created_at=NOW,
        )
    )


def test_profile_update_changes_only_display_name(tmp_path):
    storage = SQLiteStorage(tmp_path / "profile.sqlite")
    user = storage.create_user(make_user("usr_test_profile"))
    updated = user.model_copy(
        update={"display_name": "Ada Lovelace", "updated_at": NOW.replace(minute=1)}
    )
    assert storage.update_user(updated).display_name == "Ada Lovelace"
    assert storage.get_user(user.id).email == user.email


def test_suspend_preserves_login_membership_and_disables_organization(tmp_path):
    storage = SQLiteStorage(tmp_path / "suspend.sqlite")
    user = storage.create_user(make_user("usr_test_suspend"))
    org = storage.create_organization(make_org("org_test_suspend", "Suspend me"))
    add_membership(storage, str(org.id), str(user.id), "suspend")
    storage.admin_suspend_organization(org.id, NOW.replace(minute=1))
    suspended = storage.get_organization(org.id)
    assert suspended.status is OrganizationStatus.DISABLED
    assert suspended.suspended_at == NOW.replace(minute=1)
    assert storage.get_user(user.id).status is UserStatus.ACTIVE
    storage.admin_suspend_organization(org.id, NOW.replace(minute=2))
    assert storage.get_organization(org.id).suspended_at == NOW.replace(minute=1)
    assert (
        storage.get_membership(organization_id=org.id, user_id=user.id).status
        is MembershipStatus.ACTIVE
    )


def test_reactivate_clears_timestamp_and_restores_organization_access(tmp_path):
    storage = SQLiteStorage(tmp_path / "reactivate.sqlite")
    org = storage.create_organization(make_org("org_test_reactivate", "Restore me"))
    storage.admin_suspend_organization(org.id, NOW.replace(minute=1))

    storage.admin_reactivate_organization(org.id, NOW.replace(minute=2))

    reactivated = storage.get_organization(org.id)
    assert reactivated.status is OrganizationStatus.ACTIVE
    assert reactivated.suspended_at is None
    assert reactivated.updated_at == NOW.replace(minute=2)


def test_delete_removes_organization_and_all_its_users(tmp_path):
    storage = SQLiteStorage(tmp_path / "delete.sqlite")
    user = storage.create_user(make_user("usr_test_delete"))
    org = storage.create_organization(make_org("org_test_delete", "Delete me"))
    add_membership(storage, str(org.id), str(user.id), "delete")
    storage.admin_delete_organization(org.id)
    try:
        storage.get_user(user.id)
    except EntityNotFoundError:
        pass
    else:
        raise AssertionError("organization user should be removed")
    try:
        storage.get_organization(org.id)
    except EntityNotFoundError:
        pass
    else:
        raise AssertionError("organization should be removed")
