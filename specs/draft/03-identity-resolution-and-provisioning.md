# Phase 03 — Identity resolution and safe provisioning

**Dependency:** Phase 02  
**Handoff to:** Phases 04, 06, and 07

## Goal

Validate Cognito access tokens and resolve them into an internal FeedNow user and default organization without making Cognito fields product identity.

## Work boundary

- Implement Cognito JWKS discovery/caching and access-token validation: signature, issuer, audience/client binding, expiry, and expected token use.
- Convert verified Cognito `sub` plus provider tenant into an `ExternalIdentity` lookup.
- On first authenticated request, invoke atomic provisioning for User, identity, personal organization, owner membership, and audits.
- Implement `GET /v1/me` with provider-neutral AuthorizationContext.

## Acceptance criteria

- Invalid, expired, wrong-issuer/audience, and malformed tokens are rejected without storage mutation.
- A first valid request yields exactly one user, identity, workspace, owner membership, and required creation audit trail.
- Repeated and concurrent first requests resolve the same identity and do not create duplicate tenants.
- `/v1/me` returns no raw Cognito token/provider secret and uses FeedNow user/organization IDs.
- Tests use signed fixtures or a JWKS test server, not a live Cognito pool.

## Non-goals

Registration, hosted UI, OAuth callback, federation configuration, and membership-management endpoints.

## Handoff

Publish the authentication dependency interface and resolved AuthorizationContext for routers and API-key authentication.

