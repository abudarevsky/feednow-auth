"""SQLite-backed extension required by local organization administration."""

from typing import Protocol

from app.models.ids import OrganizationId
from app.models.organization import Organization
from app.models.pagination import Page, PageParams
from app.models.timestamps import UtcDatetime
from app.storage.contract import Storage


class LocalAdminStorage(Storage, Protocol):
    """Base storage contract plus local-only global organization queries."""

    def admin_summary(self) -> dict[str, int]:
        """Return organization and active-membership totals for local admins."""
        ...

    def admin_search_organizations(self, query: str, page: PageParams) -> Page[Organization]:
        """Return a case-insensitive organization page for local admin search."""
        ...

    def admin_suspend_organization(self, organization_id: OrganizationId, at: UtcDatetime) -> None:
        """Timestamp suspension and revoke organization keys."""
        ...

    def admin_reactivate_organization(
        self, organization_id: OrganizationId, at: UtcDatetime
    ) -> None:
        """Enable the organization and clear its suspension timestamp."""
        ...

    def admin_delete_organization(self, organization_id: OrganizationId) -> None:
        """Delete organization-owned data and any users left without resources."""
        ...


__all__ = ["LocalAdminStorage"]
