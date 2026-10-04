# Browser sessions

The service provides a server-side OAuth authorization-code + PKCE login
boundary for browser clients. Cognito remains responsible for credentials,
MFA, account recovery, and provider authentication. The browser receives an
opaque `feednow_session` cookie; Cognito tokens and the PKCE verifier remain
server-side.

## Login lifecycle

`GET /oauth/login` validates the requested return destination against the
configured same-origin paths and allowed origins, creates single-use OAuth
state and a PKCE verifier, then redirects to Cognito. `GET /oauth/callback`
consumes the state, exchanges the authorization code, validates the access
token, fetches a verified user profile when needed, resolves or provisions
the internal user, and establishes an opaque application session.

OAuth routes are outside the versioned `/v1` endpoint manifest. The deployed
runtime mounts them when its complete session configuration is present; the
AWS CDK stack supplies all required values. The account CloudFront callback
path `/api/oauth/callback` is rewritten to the backend `/oauth/callback` route.
Local Docker and AWS also share the browser-facing session, CSRF, services,
and logout routes.

## Cookie and CSRF behavior

The `feednow_session` cookie is `HttpOnly`, `SameSite=Lax`, and scoped to `/`;
`Secure` follows runtime configuration. Session IDs contain no identity claims
and are stored with an expiry. Login state is single-use and expires after ten
minutes.

The browser composition provides `GET /v1/csrf`. It sets a readable
`feednow_csrf` cookie bound to the opaque session ID. Unsafe `/v1` requests
authenticated by the session cookie must also send the matching
`X-CSRF-Token`; comparisons are constant-time. Bearer-token requests do not
use this cookie check. The `/v1/service-auth/` routes are exempt from the
session CSRF check because they authenticate with their own server-only
service credential; requests without a valid service credential are rejected
by the route itself.

## Limits and operations

The service has no general session-revocation endpoint. Removing the complete
session configuration prevents the OAuth and browser session routes from
mounting; stored records then expire normally. See [Cognito setup](cognito.md)
and [operations](operations.md) for provider settings and runtime checks.
