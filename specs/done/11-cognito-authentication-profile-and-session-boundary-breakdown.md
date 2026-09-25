1. Add the CognitoProfile value type and provisioning-profile gate
   - Scope: src/app/auth/profile.py (new), src/tests/unit/test_auth_profile.py (new)
   - Change: Define frozen dataclass `CognitoProfile(sub: str, email: str | None, email_verified: bool, display_name: str | None)` and `require_provisioning_profile(profile: CognitoProfile, *, token_sub: str) -> CognitoProfile` enforcing: `sub` non-empty and ≤255 equal to `token_sub`; `email` present, non-empty, ≤320; `email_verified` exactly `True`; `display_name` ≤255 or None. Every failure raises `app.auth.errors.TokenValidationError` with a fixed safe reason that never interpolates email or subject values. Use plain integer bounds and import no `app.models` types (mirror the verifier's decision-4 rule in cognito.py).
   - Verify: pytest src/tests/unit/test_auth_profile.py
   - Depends on: none

2. Add the narrow Cognito user-info profile client
   - Scope: src/app/auth/userinfo.py (new), src/tests/support/cognito.py (extend with a loopback HTTP handler that serves canned JSON at fixed paths), src/tests/unit/test_userinfo_client.py (new)
   - Change: Define `ProfileSource` Protocol with `fetch(access_token: str, expected_sub: str) -> CognitoProfile` and `CognitoUserInfoClient(userinfo_url: str, timeout_seconds: float = 5.0)` that validates `userinfo_url` is HTTPS at construction (the endpoint is fixed approved configuration; no per-call URL selection). `fetch` sends `GET` with `Authorization: Bearer <access_token>`, parses `sub`, `email`, `email_verified`, `name` (mapping `name` to `display_name`, absent/empty → None), bounds every string, and raises `TokenValidationError("profile subject does not match the token")` when the returned `sub` differs from `expected_sub`. Network errors, non-2xx, and unparseable bodies raise `TokenProviderUnavailableError` with fixed reasons. The module imports no logging and never includes token, email, or payload material in exception text.
   - Verify: pytest src/tests/unit/test_userinfo_client.py
   - Depends on: 1

3. Let the identity service consume a verified profile on the provisioning path
   - Scope: src/app/services/identity.py, src/tests/unit/test_identity_service.py, src/tests/unit/test_identity_service_sqlite.py
   - Change: Add keyword `profile_provider: Callable[[], CognitoProfile] | None = None` to `resolve_or_provision`; it is invoked **only** on the identity-tuple miss path (hit path performs zero profile work and never overwrites the stored user's email). When invoked, run `require_provisioning_profile(profile, token_sub=claims.sub)` before building the batch; `build_provisioning_batch(claims, now, ids, *, profile: CognitoProfile | None = None)` takes `User.email` from `profile.email` and display name from `profile.display_name or claims.username or claims.sub` when a profile is present, falling back to today's claims-only behavior when None (placeholder removal is a later task). Profile gate failures propagate as `TokenValidationError` before any `provision_user` call, preserving the no-storage-mutation rule.
   - Verify: pytest src/tests/unit/test_identity_service.py src/tests/unit/test_identity_service_sqlite.py
   - Depends on: 1

4. Wire the profile source through the HTTP auth chain and composition roots
   - Scope: src/app/auth/dependencies.py, src/app/api/me.py, src/app/api/organizations.py, src/app/api/members.py, src/app/api/keys.py, deploy/docker/local_runtime.py, src/tests/unit/test_principal_dispatch.py, src/tests/integration/test_me_endpoint.py
   - Change: Extend `build_current_user(storage, verifier, profile_source: ProfileSource | None = None)` and `build_current_principal(...)` so the human branch builds `profile_provider = lambda: profile_source.fetch(raw_bearer_token, claims.sub)` when a source is configured and passes it to `resolve_or_provision`; with no source the chain behaves exactly as today. Router factories accept an optional `profile_source` and forward it. `local_runtime.build_app` constructs `CognitoUserInfoClient` when `FEEDNOW_COGNITO_USERINFO_URL` is set and passes it to all four routers. Add tests proving the provider is never called for an already-provisioned user (zero user-info requests on the hit path) and that a first-login `/v1/me` provisions with the profile email, not the claims email.
   - Verify: pytest src/tests/unit/test_principal_dispatch.py src/tests/integration/test_me_endpoint.py src/tests/unit/test_identity_service.py
   - Depends on: 2, 3

5. Remove the placeholder email from the verifier and require a profile for provisioning
   - Scope: src/app/auth/cognito.py, src/app/services/identity.py, src/tests/unit/test_cognito_verifier.py, src/tests/unit/test_identity_service.py, src/tests/unit/test_identity_service_sqlite.py, src/tests/integration/test_me_endpoint.py, src/tests/integration/test_concurrent_provisioning.py, src/tests/integration/test_organizations_endpoints.py, src/tests/integration/test_api_keys_endpoints.py
   - Change: In stage 7 of `CognitoAccessTokenVerifier._build_claims`, an absent/null `email` claim yields `CognitoClaims.email = None` (delete the `sub@cognito.invalid` synthesis); present-but-malformed still raises. `CognitoClaims.email` becomes `str | None`. In `identity.py`, delete the claims-only fallback: on the miss path a missing `profile_provider` raises `TokenValidationError("verified profile required for provisioning")` before any storage write, and `build_provisioning_batch` requires a validated profile for `User.email`. Update the module docstrings and every test that asserted the placeholder or provisioned on the miss path via email-carrying claims to pass an explicit fake `profile_provider` — including the sqlite-service tests (test_identity_service_sqlite.py) and the race/collision provisioning tests (test_concurrent_provisioning.py), whose `resolve_or_provision(storage, _claims())` calls on empty stores must become `resolve_or_provision(storage, _claims(), profile_provider=lambda: <fake profile with matching sub>)` so the single-winner and `ProvisioningConflictError` assertions still hold.
   - Verify: pytest src/tests/unit/test_cognito_verifier.py src/tests/unit/test_identity_service.py src/tests/unit/test_identity_service_sqlite.py src/tests/integration/test_me_endpoint.py src/tests/integration/test_concurrent_provisioning.py
   - Depends on: 3, 4

6. Add login-state and session records to the storage contract with the SQLite adapter
   - Scope: src/app/models/session.py (new), src/app/storage/contract.py, src/app/storage/sqlite.py, src/tests/storage_contract/suite.py, src/tests/unit/test_sqlite_core.py, src/app/storage/dynamodb.py (stubs only), src/tests/storage_contract/test_dynamodb_contract.py
   - Change: Define frozen records `OAuthLoginState(state_id: str, code_verifier: str, return_url: str, expires_at: datetime)` and `AppSession(session_id: str, user_id: UserId, expires_at: datetime)` in `app/models/session.py`. Add four contract methods: `save_oauth_login_state(state)`, `consume_oauth_login_state(state_id) -> OAuthLoginState | None` (atomic get-and-delete: exactly one concurrent caller receives the record), `create_app_session(session)`, `get_app_session(session_id) -> AppSession | None` (returns None at/past `expires_at`). SQLite adapter: two new tables created with `CREATE TABLE IF NOT EXISTS` at open (additive; no data migration), consumption via a single `DELETE ... RETURNING`. Add suite cases for unknown id, expired record, and double-consume-single-winner; mark the DynamoDB runs of the four new operations `xfail(raises=NotImplementedError)` and add matching `NotImplementedError` stubs to the DynamoDB adapter (removed by task 7).
   - Verify: pytest src/tests/storage_contract/test_sqlite_contract.py src/tests/unit/test_sqlite_core.py
   - Depends on: none

7. Implement the DynamoDB adapter for login-state and session operations
   - Scope: src/app/storage/dynamodb.py, src/tests/storage_contract/test_dynamodb_contract.py, src/tests/unit/test_dynamodb_codec.py
   - Change: Implement the four contract operations against two new key-schema entries in the module's `SCHEMA` (single-table style consistent with Phase 06: partition key `pk` = `{state_id}` / `{session_id}` with distinct table names `oauth_login_states` and `app_sessions`), storing a numeric `expires_at_epoch` attribute for TTL. Atomic consumption uses `delete_item` with `ConditionExpression` `attribute_exists(pk)` and `ReturnValues=ALL_OLD` so a replayed consume returns None. Reads filter expired records server-side via a condition on `expires_at_epoch`. Remove the task-6 xfail markers and NotImplementedError stubs.
   - Verify: pytest src/tests/storage_contract/test_dynamodb_contract.py (against DynamoDB Local per the existing harness)
   - Depends on: 6

8. Provision the state and session tables in CDK with least-privilege IAM
   - Scope: deploy/aws/cdk/feednow_auth_stack.py, src/tests/unit/test_cdk_dynamodb.py, src/tests/unit/test_cdk_iam.py
   - Change: Add the two new tables to the stack's `_SCHEMA` mirror (environment-prefixed names like the existing seven), enable `expires_at_epoch` as the TTL attribute on both, and extend the Lambda role policy matrix with exactly the actions the task-7 adapter calls (`PutItem`, `GetItem`, `DeleteItem` with condition) on the two new table ARNs only — no Scan, no index grants, no admin actions. Names derive from the existing `FEEDNOW_ENV`-parameterized prefix so dev/staging/prod are covered.
   - Verify: pytest src/tests/unit/test_cdk_dynamodb.py src/tests/unit/test_cdk_iam.py, then `cdk synth` in deploy/aws/cdk succeeds and the two new tables appear in the cloud assembly
   - Depends on: 7

9. Add the application session issuer/verifier and cookie policy
   - Scope: src/app/auth/session.py (new), src/tests/unit/test_session_manager.py (new)
   - Change: `SessionManager(storage, ttl_seconds: int = 1800)` with `issue(user_id) -> str` (session id from `secrets.token_urlsafe(32)`, persists `AppSession` with `expires_at = utc_now() + ttl`) and `verify(session_id) -> UserId | None` (storage lookup; unknown or expired → None; never raises for caller-controlled input). Module constants: `SESSION_COOKIE_NAME = "feednow_session"`, `build_session_cookie(value, *, max_age, secure: bool) -> str` producing `HttpOnly; SameSite=Lax; Path=/` (Secure flag caller-controlled by deployment config), and `read_session_cookie(request) -> str | None`. No logging anywhere in the module; the session id is opaque and carries no claims.
   - Verify: pytest src/tests/unit/test_session_manager.py
   - Depends on: 6

10. Add the authorization-code token-exchange client
    - Scope: src/app/auth/token_exchange.py (new), src/tests/unit/test_token_exchange.py (new)
    - Change: `CognitoTokenEndpoint(token_endpoint_url: str, client_id: str, timeout_seconds: float = 5.0)` validating HTTPS at construction; `exchange(code: str, redirect_uri: str, code_verifier: str) -> str` POSTs `application/x-www-form-urlencoded` (`grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier`) for the public PKCE client (no client secret — matches the Phase 07 app client), parses and returns only `access_token`, discards `id_token`/`refresh_token` without storing or echoing them. Any network failure, non-2xx, or missing/short `access_token` raises `TokenProviderUnavailableError` with a fixed reason containing no code, verifier, or token material. Reuses the task-2 loopback support server.
    - Verify: pytest src/tests/unit/test_token_exchange.py
    - Depends on: 2

11. Add the OAuth login-initiation route
    - Scope: src/app/api/oauth.py (new), src/tests/integration/test_oauth_login_init.py (new)
    - Change: `build_oauth_router(...)` factory registering `GET /oauth/login` with `include_in_schema=False` and deliberately outside the frozen `/v1` ENDPOINTS manifest (WIP 11 scope 5 is the authorizing revision; health-route precedent). Behavior: validate `next` (default: configured landing URL) against an exact-origin allowlist `allowed_return_origins` plus same-origin relative paths — reject credentials-in-URL, non-http(s) schemes, and foreign origins with 400 `validation_error` (fixed message, `next` never echoed). On accept, mint `state = secrets.token_urlsafe(32)` and PKCE verifier `secrets.token_urlsafe(64)` (43–128 chars, RFC 7636 charset), store `OAuthLoginState(state, verifier, next, expires_at=now+600s)` via `save_oauth_login_state`, and 302 to the configured authorize URL with `response_type=code`, `client_id`, the configured `redirect_uri`, `scope=openid email profile`, `code_challenge_method=S256`, and `code_challenge`. Constructor takes all URLs as approved configuration; no import-time env reads.
    - Verify: pytest src/tests/integration/test_oauth_login_init.py
    - Depends on: 6

12. Add the OAuth callback route with the full journey, error mapping, and session cookie
    - Scope: src/app/api/oauth.py, src/tests/integration/test_oauth_callback_flow.py (new), src/tests/integration/test_audit_hygiene.py (extend)
    - Change: `GET /oauth/callback` on the task-11 router: (a) Cognito `error` parameter or missing `code`/`state` → 401 `unauthenticated` fixed message, provider text never echoed; (b) `consume_oauth_login_state(state)` returning None (unknown, expired, or already-replayed) → 401 `unauthenticated` "login state is invalid or expired"; (c) `CognitoTokenEndpoint.exchange` with the stored verifier → failure 503 `internal_error`; (d) verify the returned access token through the existing `AccessTokenVerifier` → `TokenValidationError` 401, `TokenProviderUnavailableError` 503, all before any storage touch; (e) `ProfileSource.fetch(token, claims.sub)` + `require_provisioning_profile` → 401 on shape/verification/subject failures; (f) `resolve_or_provision` → `DisabledUserError`/`NoActiveOrganizationError` 403, `ProvisioningConflictError` 409; (g) success: `SessionManager.issue(user.id)`, `Set-Cookie` via `build_session_cookie`, 302 to the stored `return_url` re-validated against the allowlist. Exact mapping table above is the contract. Integration tests cover mocked native and Google-federated profile journeys plus every failure branch, and assert with `caplog` and response-body checks that code, state, verifier, tokens, and email appear in no log record, error envelope, or redirect target. The local capture page in deploy/docker/oauth_callback.py stays mounted by local_runtime unchanged.
    - Verify: pytest src/tests/integration/test_oauth_callback_flow.py src/tests/integration/test_audit_hygiene.py
    - Depends on: 5, 9, 10, 11

13. Mount the session flow in the AWS composition root behind configuration (rollback seam)
    - Scope: deploy/aws/runtime/handler.py, src/tests/unit/test_runtime_handler.py
    - Change: Add `RuntimeConfig` keys `FEEDNOW_COGNITO_AUTHORIZE_URL`, `FEEDNOW_COGNITO_TOKEN_ENDPOINT`, `FEEDNOW_COGNITO_USERINFO_URL`, `FEEDNOW_OAUTH_REDIRECT_URL`, `FEEDNOW_ALLOWED_RETURN_ORIGINS`, `FEEDNOW_SESSION_TTL_SECONDS`, `FEEDNOW_COOKIE_SECURE`; `build_app` mounts `build_oauth_router(...)` and passes `CognitoUserInfoClient` to the four resource routers only when all session keys are present, and raises a fixed config error naming the missing key otherwise. Removing the configuration returns the deployed surface to the exact pre-phase-11 app (rollback behavior). Preserve the cold-start contract: no import-time I/O, boto3 still absent from `sys.modules` after import, one GetSecretValue unchanged.
    - Verify: pytest src/tests/unit/test_runtime_handler.py src/tests/integration/test_app_skeleton.py
    - Depends on: 12

14. Pin cognito-login.sh token-secrecy with regression tests
    - Scope: src/tests/unit/test_cognito_login_script.py
    - Change: Add static assertions over deploy/docker/cognito-login.sh: no `echo`/`printf`/`cat`/write target references `${ACCESS_TOKEN}`, `${CODE_VERIFIER}`, `${STATE}`, or `${AUTH_CODE}` outside curl argument arrays; the only token-derived output is the `/v1/me` response body; no `tee`/redirect persists the token response to a file. The script itself is unchanged (it remains the Phase-11-preserved test harness).
    - Verify: pytest src/tests/unit/test_cognito_login_script.py
    - Depends on: none

15. Document and verify the deployed Hosted UI settings as the operational proof
    - Scope: docs/RUNNING_WITH_COGNITO.md
    - Change: Add a "Deployed client settings verification" runbook: exact console/CLI checks for authorization-code+PKCE flow, `openid email profile` scopes, callback/logout URLs including the deployed `/oauth/callback` (sourced from `COGNITO_CALLBACK_URLS`), native email self-sign-up and verification, and Google IdP enablement on the app client; document the new `FEEDNOW_*` session configuration from task 13, including the note that after task 5 the local runtime requires `FEEDNOW_COGNITO_USERINFO_URL` to be set for `cognito-login.sh` first-login provisioning (bearer-only first login without user-info config now fails 401), and the manual native and `--provider Google` journeys against the dev deployment, recording that deployed settings — not source — are the proof. No CDK code change in this task.
    - Verify: runbook executes against the dev deployment and its results are quotable for the phase handoff doc (task 16)
    - Depends on: 12, 13

16. Update current-state docs and record the phase 11 handoff evidence
    - Scope: docs/architecture.md, docs/contracts.md, docs/operations.md, docs/README.md, docs/phases/11-cognito-authentication-profile-and-session-boundary.md (new)
    - Change: Record only after tasks 1–15 pass: the auth boundary now owns profile/user-info/session components; contracts.md gains the `/oauth/login` + `/oauth/callback` behavior, the exact error mapping table from task 12, the `feednow_session` cookie policy, the four additive storage-contract operations, and the explicit note that cookie-based authentication of `/v1/*` routes is **not** enabled by this phase (session verification is component-level only); operations.md gains the new env configuration and the config-removal rollback procedure; phases/11 records the acceptance-test evidence (test commands and results, `cdk synth` output reference, deployed-settings verification from task 15) and the non-goals honored (no account linking, no frontend account pages, no password recovery, no real-AWS unit tests).
    - Verify: pytest full suite green; docs/requirements.md checklist satisfied for the changed documents
    - Depends on: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
