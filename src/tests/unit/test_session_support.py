"""Proofs for browser-session support routes shared by local and AWS runtimes."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.session_support import build_session_support_router
from app.auth.pepper import StaticPepper
from app.auth.session import SessionManager
from app.storage.sqlite import SQLiteStorage


def _client(tmp_path) -> tuple[TestClient, SQLiteStorage]:  # type: ignore[no-untyped-def]
    storage = SQLiteStorage(tmp_path / "session-support.sqlite")
    router = build_session_support_router(
        storage,
        verifier=object(),  # The tested unauthenticated/logout routes do not verify tokens.
        pepper=StaticPepper(b"a" * 48),
        profile_source=None,
        session_manager=SessionManager(storage),
        cognito_domain="https://cognito.example.test",
        client_id="public-client",
        frontend_url="https://account.example.test",
        cookie_secure=True,
    )
    app = FastAPI()
    app.include_router(router)
    return TestClient(app), storage


def test_logout_clears_both_cookies_and_returns_hosted_logout_url(tmp_path) -> None:  # type: ignore[no-untyped-def]
    client, storage = _client(tmp_path)
    try:
        response = client.post("/logout")
    finally:
        storage.close()

    assert response.status_code == 200
    assert response.json() == {
        "logout_url": "https://cognito.example.test/logout?client_id=public-client&logout_uri=https%3A%2F%2Faccount.example.test%2Flogin"
    }
    cookies = response.headers.get_list("set-cookie")
    session_cookie = next(cookie for cookie in cookies if cookie.startswith("feednow_session="))
    csrf_cookie = next(cookie for cookie in cookies if cookie.startswith("feednow_csrf="))
    assert "max-age=0" in session_cookie.lower() and "; secure" in session_cookie.lower()
    assert "max-age=0" in csrf_cookie.lower() and "; secure" in csrf_cookie.lower()


def test_session_service_and_csrf_routes_require_authentication(tmp_path) -> None:  # type: ignore[no-untyped-def]
    client, storage = _client(tmp_path)
    try:
        services = client.get("/v1/services")
        csrf = client.get("/v1/csrf")
    finally:
        storage.close()

    assert services.status_code == 401
    assert csrf.status_code == 401
