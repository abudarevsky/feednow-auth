"""Retryable dispatch of FeedNow's durable organization onboarding outbox."""

from __future__ import annotations

import json
from collections.abc import Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from app.models.ids import OrganizationId
from app.models.timestamps import utc_now
from app.storage.contract import Storage

ONBOARDING_PATH = "/internal/onboarding/organizations"
HTTP_TIMEOUT_SECONDS = 5


def dispatch_organization_onboarding(
    storage: Storage,
    organization_id: OrganizationId,
    *,
    base_url: str,
    service_credential: str,
    opener: Callable[..., object] = urlopen,
) -> bool:
    """Attempt an unsent outbox request once, persisting a safe outcome.

    Callers invoke this after identity resolution. The outbox is committed in
    the first-provisioning transaction; repeated logins retry pending or failed
    records, while successful delivery is terminal. Credentials are accepted
    only as call-time configuration and never enter the persisted model.
    """
    request = storage.get_organization_onboarding_request(organization_id)
    if request is None or request.status == "succeeded":
        return request is not None
    attempted = request.model_copy(
        update={"attempts": request.attempts + 1, "updated_at": utc_now(), "last_error": None}
    )
    storage.update_organization_onboarding_request(attempted)
    endpoint = base_url.rstrip("/") + ONBOARDING_PATH
    payload = json.dumps(
        {
            "org_id": str(request.organization_id),
            "request_id": request.request_id,
            "bootstrap_version": request.bootstrap_version,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    http_request = Request(
        endpoint,
        data=payload,
        headers={
            "Authorization": f"Bearer {service_credential}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with opener(http_request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            status = getattr(response, "status", 200)
            if not 200 <= status < 300:
                raise RuntimeError("non_success_status")
    except HTTPError as exc:
        outcome = f"http_{exc.code}"
    except (URLError, TimeoutError, OSError, RuntimeError):
        outcome = "dispatch_unavailable"
    else:
        storage.update_organization_onboarding_request(
            attempted.model_copy(update={"status": "succeeded", "updated_at": utc_now()})
        )
        return True
    storage.update_organization_onboarding_request(
        attempted.model_copy(
            update={"status": "failed", "updated_at": utc_now(), "last_error": outcome}
        )
    )
    return False


__all__ = ["HTTP_TIMEOUT_SECONDS", "ONBOARDING_PATH", "dispatch_organization_onboarding"]
