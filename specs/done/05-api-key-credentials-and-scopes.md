# Phase 05 — API-key credentials and scoped authorization

**Dependency:** Phases 02 and 04  
**Handoff to:** Phases 06, 07, and 08

## Goal

Deliver tenant-bound programmatic credentials with secure one-time disclosure, scope enforcement, revocation, and a common authorization context.

## Work boundary

- Generate `fn_live_<key-id>_<secret>` and `fn_test_<key-id>_<secret>` credentials with at least 256 bits of secure randomness.
- Load pepper through a configuration/secrets abstraction; persist only HMAC-SHA256(pepper, secret), key metadata, scopes, lifecycle fields, and safe audits.
- Implement protected create/list/revoke endpoints.
- Implement parsing, point lookup by key ID, constant-time hash comparison, lifecycle checks, and API-key AuthorizationContext resolution.

## Acceptance criteria

- Full plaintext is returned only by successful creation, exactly once; list/subsequent reads expose masked/non-secret fields only.
- Invalid format, unknown, expired, revoked, disabled, and mismatched secrets are rejected without leaking which secret segment failed.
- Revocation is immediately effective and creates `api_key.revoked`.
- Human contexts expose roles; API keys expose organization, key actor ID, and scopes with no human role escalation.
- Tests prove secret non-persistence/non-logging, environment prefixes, scope enforcement, and cross-organization isolation.

## Non-goals

Key rotation, OAuth client credentials, usage metering, rate limits, and commercial entitlement behavior.

## Handoff

Provide a reusable dependency for product middleware/infrastructure authorizers without requiring synchronous feednow-auth calls on every request.

## Implementation tasks

1. Implement API key service with credential generation, validation, and lifecycle management (src/app/services/api_key_service.py)
2. Extend data models to support API key credentials (src/app/models/api_key.py)
3. Update storage contract to support API key operations (src/app/storage/contract.py)
4. Create API endpoints for create/list/revoke operations (src/app/api/keys.py)
5. Implement configuration and secrets handling with pepper loading (src/app/auth/)
6. Implement authorization context resolution for API keys (src/app/auth/)
7. Integrate authentication middleware for API key validation (src/app/auth/)
8. Add audit events for API key operations (src/app/services/audit_service.py)
9. Create comprehensive test suite covering all aspects of API key functionality (src/tests/)
10. Update documentation and verify all acceptance criteria are met (docs/)

