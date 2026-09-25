"""Local-only ``/oauth/callback`` capture page for the WIP 09 login script.

The WIP 09 flow registers ``http://localhost:8000/oauth/callback`` as the
Cognito hosted-UI redirect (``FEEDNOW_COGNITO_REDIRECT_URI``). The local
Docker composition root (:mod:`local_runtime`) serves this page so the
developer can copy the **complete callback URL** — authorization ``code``
and ``state`` included — out of the browser address bar and paste it back
into the terminal running ``cognito-login.sh``.

The route is a display-only capture aid with hard constraints:

- It renders only the four OAuth redirect parameters
  (:data:`ECHOED_PARAMS`) as page **text**, HTML-escaped so no echoed value
  can inject markup (XSS).
- The handler emits **no log record** and persists **nothing**: this module
  imports no logging, storage, service, or audit machinery, and the page is
  built from the request's query string alone.
- It is mounted **only** by the local composition root; the production
  ``app.main:create_app`` surface never sees it.

Container-log hygiene is completed by ``--no-access-log`` in
``docker-compose.cognito.yml``: uvicorn's default access line prints the
full request target (path **and** query string), which would otherwise
carry the one-time code into container logs.
"""

from __future__ import annotations

from collections.abc import Mapping
from html import escape
from typing import Final

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

# Pinned to the redirect URI registered on the Cognito app client (WIP 09).
OAUTH_CALLBACK_URL: Final[str] = "http://localhost:8000/oauth/callback"

# Served path on the local app; must match the URL above.
OAUTH_CALLBACK_PATH: Final[str] = "/oauth/callback"

# Separate callback for the host-side CLI harness, which owns its own PKCE
# verifier and state rather than consuming state created by the browser API.
CLI_OAUTH_CALLBACK_PATH: Final[str] = "/oauth/cli-callback"

# The only query parameters this page ever renders; everything else in the
# callback URL is ignored so unrelated parameters cannot smuggle content in.
ECHOED_PARAMS: Final[tuple[str, ...]] = ("code", "state", "error", "error_description")


def _render_page(values: Mapping[str, str]) -> str:
    """Build the minimal capture page with every echoed value HTML-escaped.

    Names come from the :data:`ECHOED_PARAMS` whitelist; values are escaped
    with quotes enabled so a parameter can never break out of its attribute
    or text context.
    """
    if values:
        items = "".join(
            f"<li><code>{escape(name)}</code> = <code>{escape(values[name])}</code></li>"
            for name in ECHOED_PARAMS
            if name in values
        )
        params_block = f"<ul>{items}</ul>"
    else:
        params_block = "<p>No callback parameters were received.</p>"

    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        "<title>FeedNow login callback</title></head><body>"
        "<h1>FeedNow login callback</h1>"
        "<p>Copy the <strong>complete URL</strong> from the browser address bar, "
        "switch to the terminal running <code>cognito-login.sh</code>, paste it "
        "at the prompt, and press Enter.</p><p>Received parameters:</p>"
        f"{params_block}"
        "</body></html>"
    )


def build_oauth_callback_router() -> APIRouter:
    """Return the local-only ``GET /oauth/callback`` capture router.

    Import- and build-safe: performs no I/O, registers no logging handler,
    and holds no state between requests.
    """
    router = APIRouter(tags=["oauth-callback-local"])

    @router.get(
        OAUTH_CALLBACK_PATH,
        response_class=HTMLResponse,
        include_in_schema=False,
        summary="Legacy local OAuth callback capture page (development only)",
    )
    async def oauth_callback(request: Request) -> HTMLResponse:
        """Echo the redirect parameters as escaped page text and nothing else."""
        query = request.query_params
        values = {name: query[name] for name in ECHOED_PARAMS if name in query}
        return HTMLResponse(content=_render_page(values), status_code=200)

    return router


def build_oauth_cli_callback_router() -> APIRouter:
    """Return the local-only callback route reserved for the CLI PKCE flow."""
    router = APIRouter(tags=["oauth-callback-local"])

    @router.get(
        CLI_OAUTH_CALLBACK_PATH,
        response_class=HTMLResponse,
        include_in_schema=False,
        summary="CLI OAuth callback capture page (development only)",
    )
    async def oauth_cli_callback(request: Request) -> HTMLResponse:
        query = request.query_params
        values = {name: query[name] for name in ECHOED_PARAMS if name in query}
        return HTMLResponse(content=_render_page(values), status_code=200)

    return router


__all__ = [
    "ECHOED_PARAMS",
    "CLI_OAUTH_CALLBACK_PATH",
    "OAUTH_CALLBACK_PATH",
    "OAUTH_CALLBACK_URL",
    "build_oauth_callback_router",
    "build_oauth_cli_callback_router",
]
