# 11 — Cognito authentication profile and session boundary

**Status:** draft — no implementation is authorized.  
**Depends on:** current Cognito JWT verification and the local PKCE login script.  
**Unblocks:** 12-shadow-registration and 13-administrator-bootstrap.

## Baseline and gap

`app.auth.cognito.CognitoAccessTokenVerifier` validates Cognito RS256 access
tokens, issuer, client ID, expiry, and `token_use=access`.
`deploy/docker/cognito-login.sh` already uses authorization-code + PKCE and
can request Cognito's Google identity provider. The local `/oauth/callback`
route is intentionally only a display page; it does not establish a session.

The access-token verifier currently creates `sub@cognito.invalid` when email
is absent. That is sufficient for a local bearer proof but not durable identity
provisioning: it supplies neither a verified email nor verification state. The
production application has no authorization-code callback/session flow.

## Scope

1. Cognito remains the sole owner of passwords, registration, verification,
   MFA, recovery, Google federation, and token issuance. FeedNow Auth adds no
   password storage or custom password endpoint.
2. Define an immutable authenticated profile with `sub`, `email`,
   `email_verified`, and optional display name. A provisioning profile requires
   a bounded non-empty email, `email_verified=true`, and the same `sub` as the
   validated access token.
3. Add a narrow Cognito user-info/profile client. It receives a validated
   access token, uses only approved Cognito configuration, checks returned `sub`,
   bounds fields, and never logs tokens/profile data. JWT validation remains
   mandatory; user-info is not a signature-verification substitute.
4. Replace placeholder-email use for provisioning with the verified profile.
   Missing, malformed, unverified, or subject-mismatched data fails safely with
   no storage mutation.
5. Define a real authorization-code callback: server-side, expiring, single-use
   state and PKCE verifier; approved return URLs; token validation; profile
   retrieval; secure application-session creation; then original redirect. The
   local callback remains a capture page until this is accepted.
6. Preserve `cognito-login.sh` as a test harness. It may exchange its code and
   call `/v1/me` with an access token, but must not print or retain token data.
7. Document/verify Hosted UI authorization code + PKCE, `openid email profile`,
   native email self-service/verification, and Google federation. Deployed
   client settings, not source alone, are the operational proof.

## Acceptance tests

- Mocked native-Cognito and Google profile journeys.
- Missing/unverified/malformed email, mismatched `sub`, invalid/replayed/expired
  state, disallowed return URL, and provider outage.
- Existing signature, issuer, client, expiry, and `token_use` failures reject
  before profile or storage access.
- Token, authorization-code, state, and profile secrecy in logs/errors.

## Handoff and non-goals

Update current-state documentation only after verification. Do not implement
account linking, frontend account pages, password recovery, or real-AWS unit
tests. A WIP breakdown must name session persistence, callback URLs, cookie
policy, exact error mappings, focused tests, and rollback behavior.
