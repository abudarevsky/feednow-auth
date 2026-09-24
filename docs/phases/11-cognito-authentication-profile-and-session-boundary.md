# Current state: Cognito authentication profile and session boundary

Phase 11 is implemented and hermetically verified. The auth boundary now
owns three new components alongside the Phase 03 verifier: the verified
profile seam (`CognitoProfile` + `require_provisioning_profile` +
`CognitoUserInfoClient`), the application session
(`src/app/auth/session.py`), and the authorization-code + PKCE session
boundary (`GET /oauth/login` + `GET /oauth/callback` in
`src/app/api/oauth.py`). First-login provisioning no longer synthesizes a
placeholder email: it requires a verified user-info profile whose `sub`
equals the validated token's. The deployed runtime mounts the session
routes only when the complete seven-key session configuration is present
(all-or-nothing gate; removing the keys is the rollback seam).
**Cookie-based authentication of `/v1/*` routes is not enabled by this
phase** — session verification is component-level only and `/v1/*` keeps
the bearer-token contract. Cognito remains the sole owner of passwords,
registration, verification, MFA, recovery, Google federation, and token
issuance; no password storage or custom password endpoint was added.

## Scope

- `src/app/auth/cognito.py` (extended): `CognitoProfile` (frozen value
  object: `sub`, optional `email`, `email_verified`, optional
  `display_name`), `require_provisioning_profile` (the single provisioning
  gate: `sub` bounded and equal to the verified token's, email present and
  ≤320, `email_verified` exactly `True`, display name bounded or `None`),
  the `ProfileSource` protocol, and `CognitoUserInfoClient` (constructor-
  pinned absolute-HTTPS user-info endpoint, bearer-only GET, redirects
  refused, fixed safe reasons). `CognitoClaims.email` is now `str | None`
  — the `sub@cognito.invalid` placeholder is gone.
- `src/app/auth/session.py`: `SessionManager` (opaque
  `secrets.token_urlsafe(32)` session ids over the storage contract;
  `verify` never raises for caller-controlled input) and the cookie
  policy helpers (`SESSION_COOKIE_NAME = "feednow_session"`,
  `build_session_cookie`, `read_session_cookie`).
- `src/app/auth/token_exchange.py`: `CognitoTokenEndpoint` — public-PKCE
  authorization-code exchange (no client secret ever sent, stored, or
  accepted); returns only `access_token` and discards `id_token` /
  `refresh_token` without storing or echoing them.
- `src/app/models/session.py`: `OAuthLoginState` and `AppSession` frozen
  records (bounded `StateId`/`CodeVerifier`/`ReturnUrl`/`SessionId`).
- `src/app/storage/contract.py`: four additive operations
  (`save_oauth_login_state`, `consume_oauth_login_state`,
  `create_app_session`, `get_app_session`) — the `Storage` protocol is now
  23 methods; both adapters implement them (SQLite: `DELETE ... RETURNING`
  for single-winner consumption; DynamoDB: conditional `DeleteItem` with
  `ReturnValues=ALL_OLD` plus a read-side clock check).
- `src/app/services/identity.py`: `resolve_or_provision` takes an optional
  `profile_provider` invoked **only** on the identity-tuple miss path (the
  hit path performs zero profile work and never overwrites the stored
  email); `verified_provisioning_profile` runs the gate before any storage
  write, and a missing provider on the miss path is a fixed 401
  (`"verified profile required for provisioning"`).
- `src/app/auth/dependencies.py` + the four §14 routers: optional
  `profile_source` seam on `build_current_user` / `build_current_principal`
  (human branch only; the API-key branch is untouched).
- `src/app/api/oauth.py`: the `/oauth/login` + `/oauth/callback` session
  boundary (contract below), registered with `include_in_schema=False`
  and deliberately outside the frozen `/v1` `ENDPOINTS` manifest.
- `deploy/aws/runtime/handler.py`: the all-or-nothing session gate
  (seven `SESSION_ENV_KEYS`, task 13) and the rollback seam.
- `deploy/aws/cdk/feednow_auth_stack.py`: `oauth_login_states` +
  `app_sessions` tables with the `expires_at_epoch` TTL attribute and the
  matching least-privilege IAM matrix (`PutItem`/`DeleteItem` and
  `GetItem`/`PutItem` on the two new table ARNs only — no Scan, no index
  grants).
- `deploy/docker/local_runtime.py`: constructs `CognitoUserInfoClient`
  when `FEEDNOW_COGNITO_USERINFO_URL` is set and passes it to all four
  routers; the local `/oauth/callback` capture page stays mounted
  unchanged as the development harness, and `cognito-login.sh` remains the
  preserved test harness (its token secrecy is pinned by
  `src/tests/unit/test_cognito_login_script.py`).

## Session boundary contract

`GET /oauth/login` validates `next` (default: the configured landing URL)
against an exact-origin allowlist plus same-origin relative paths —
credentials-in-URL, non-http(s) schemes, backslash/protocol-relative
smuggling, and foreign origins get a fixed 400 `validation_error` and the
submitted value is never echoed. On accept it mints a single-use `state`
(32 bytes) and PKCE verifier (64 bytes, RFC 7636), stores an
`OAuthLoginState` expiring in 600 s, and 302s to the configured authorize
URL with `response_type=code`, `scope=openid email profile`, and
`code_challenge_method=S256`. The verifier never leaves the server.

`GET /oauth/callback` — the mapping table **is** the contract (frozen
Phase 01 error envelope):

| Step failure | HTTP | code |
| --- | --- | --- |
| (a) provider `error` param / missing `code`/`state` | 401 | `unauthenticated` |
| (b) unknown / expired / already-replayed state | 401 | `unauthenticated` |
| (c) token-endpoint exchange failure | 503 | `internal_error` |
| (d) access-token verification failure | 401 | `unauthenticated` |
| (d) token provider unavailable (JWKS outage) | 503 | `internal_error` |
| (e) profile shape / verification / subject failure | 401 | `unauthenticated` |
| (e) profile provider unavailable | 503 | `internal_error` |
| (f) disabled user / no active organization | 403 | `forbidden` |
| (f) provisioning conflict | 409 | `conflict` |
| (g) stored return URL no longer allow-listed | 400 | `validation_error` |

Success (g) issues the session, sets the `feednow_session` cookie
(`HttpOnly; SameSite=Lax; Path=/`, `Max-Age` = configured TTL, `Secure`
only when `FEEDNOW_COOKIE_SECURE=true`), and 302s to the re-validated
return URL. JWT validation remains mandatory before any profile or user
storage work; every failure message is a fixed constant or a
producer-pinned safe reason — the authorization code, state, verifier,
tokens, and email appear in no log record, error envelope, or redirect
target (the modules import no logging; `test_audit_hygiene.py` sweeps the
full journey).

## Deployed session configuration (all-or-nothing gate)

Seven optional Lambda keys (`SESSION_ENV_KEYS` in
`deploy/aws/runtime/handler.py`): `FEEDNOW_COGNITO_AUTHORIZE_URL`,
`FEEDNOW_COGNITO_TOKEN_ENDPOINT`, `FEEDNOW_COGNITO_USERINFO_URL`,
`FEEDNOW_OAUTH_REDIRECT_URL`, `FEEDNOW_ALLOWED_RETURN_ORIGINS`,
`FEEDNOW_SESSION_TTL_SECONDS`, `FEEDNOW_COOKIE_SECURE`. All seven present
mounts the session router and wires the user-info source into the four
§14 routers; none present is the rollback seam (the deployed **route**
surface is exactly the pre-phase-11 app); a partial set fails cold start
naming only the missing keys. Note that the rollback restores routes, not
the pre-phase-11 first-login *behavior*: with the gate off no profile
source is wired, so deployed bearer first-login provisioning fails 401
(`"verified profile required for provisioning"`) where it once succeeded
with a synthesized placeholder email — the same reason the **local**
Cognito composition needs `FEEDNOW_COGNITO_USERINFO_URL` for first-login
provisioning. The CDK stack deliberately does **not** set these keys —
the operator supplies them (runbook §7 in
[`../RUNNING_WITH_COGNITO.md`](../RUNNING_WITH_COGNITO.md) is the
verification procedure).

## Verification

Evidence (2026-09-24):

- `PYTHONPATH=. uv run pytest -q` → **1823 passed, 144 skipped** (Phase 07
  baseline 1537 + 286 Phase 11 assertions; the 144 skips remain the
  DynamoDB Local gated cases — Docker was unavailable for this recording
  run, so the DynamoDB entries stay the marker-gated procedure from
  `docs/operations.md`). Two pre-existing third-party deprecation warnings
  from the starlette/fastapi testclient stack.
- New-test counts: `test_cognito_profile.py` 64 (profile value object,
  gate, and user-info client over the loopback harness),
  `test_oauth_login_init.py` 33, `test_oauth_callback_flow.py` 25 (native
  and Google-federated journeys plus every failure branch and secrecy
  sweep), `test_session_manager.py` 29, `test_token_exchange.py` 37,
  `test_runtime_handler.py` 65 (gate, rollback seam, cold-start contract).
- `PYTHONPATH=. uv run pytest src/tests/storage_contract -q` → **76
  passed, 71 skipped** (SQLite entry 74; the DynamoDB entry contributes
  its 2 ungated cases and skips the 71 marker-gated ones without a Local
  endpoint). The suite gained the unknown-id, expired-record, and
  double-consume-single-winner cases for the four new operations.
- `cdk synth` from `deploy/aws/cdk` with the placeholder inputs → exit 0,
  no Docker; the cloud assembly contains exactly **9**
  `AWS::DynamoDB::Table` resources including `feednow-auth-dev-oauth_login_states`
  and `feednow-auth-dev-app_sessions`, each with
  `TimeToLiveSpecification {AttributeName: expires_at_epoch, Enabled: true}`,
  and the Lambda policy actions stay inside the pinned matrix
  (`GetItem`/`PutItem`/`DeleteItem`/`BatchGetItem`/`Query`/
  `ConditionCheckItem`/`UpdateItem` — no Scan, no admin actions).
- `uv run ruff format --check .` (156 files) and `git diff --check` clean.
  `uv run ruff check .` reports one **pre-existing** I001 in
  `deploy/docker/local_runtime.py`; the un-sorted import block predates
  this phase (the I001 fires identically on the pre-Phase-11 revision) and
  is left for a separate chore change.
- **Not performed (pending operator execution):** the deployed-client
  settings readout and the two manual browser journeys (native email and
  `Google` federation) of runbook §7 against the live dev stack — they
  need operator AWS credentials and a browser, so the runbook is recorded
  as the procedure, not as completed evidence. Until those checks are
  executed and their results recorded here, the phase's **operational
  acceptance remains open** (deployed settings, not source, are the proof).

## Non-goals honored

No account linking, no frontend account pages, no password recovery
endpoints, no real-AWS unit tests, no cookie authentication of `/v1/*`
routes, and no password storage or custom password endpoint — Cognito
keeps sole ownership of credentials and token issuance.

## Known limitations

- Deployed operational proof pending (see Verification).
- Sessions are absolute-expiry only (no refresh/extension) and there is no
  session revocation surface yet; `read_session_cookie`/
  `SessionManager.verify` exist at component level for the phase that will
  authenticate cookie-bearing routes.
- The session gate is operator-set Lambda configuration, not CDK-managed;
  a stack re-deploy does not carry the seven keys unless the deployment
  tooling supplies them.
- `consume_oauth_login_state` deletes expired states opportunistically;
  the DynamoDB TTL sweep is the eventual cleaner (Local never sweeps).

## Published interfaces (what Phase 12+ codes against)

| Interface | Module | Consumers |
| --- | --- | --- |
| `CognitoProfile`, `require_provisioning_profile`, `ProfileSource`, `CognitoUserInfoClient` | `src/app/auth/cognito.py` | any new provisioning or profile-consuming path |
| `SessionManager`, `SESSION_COOKIE_NAME`, `build_session_cookie`, `read_session_cookie` | `src/app/auth/session.py` | the future cookie-authenticated route surface |
| `CognitoTokenEndpoint.exchange` | `src/app/auth/token_exchange.py` | any additional authorization-code journey |
| `OAuthLoginState`, `AppSession` records + the four contract operations | `src/app/models/session.py`, `src/app/storage/contract.py` | adapters and session lifecycle work |
| `build_oauth_router` (error mapping table as contract) | `src/app/api/oauth.py` | login-flow extensions (must keep the `/v1` manifest frozen) |
| `SESSION_ENV_KEYS` + `_session_config` gate | `deploy/aws/runtime/handler.py` | deployment configuration and rollback |
