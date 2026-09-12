# Phase 08 — Service hardening and consumer integration contract

**Dependency:** Phases 04, 05, 06, and 07  
**Handoff to:** product-service implementation work

## Goal

Make the service operable and consumable by Vispector, ExcelToPIM, and future products without making it a synchronous proxy for every product request.

## Work boundary

- Add safe structured audits/logs, health/readiness, metrics, error mapping, and operational runbooks.
- Publish an OpenAPI/consumer guide for JWT/API-key AuthorizationContext, role/scope enforcement, key lifecycle, and failures.
- Provide reusable middleware/library or authorizer integration guidance for local/infrastructure validation.
- Add end-to-end tests across authentication, provisioning, membership policy, issuance, scoped authorization, and revocation.

## Acceptance criteria

- Products can enforce organization, role, and required scopes from the documented common context without importing a storage adapter.
- Architecture does not require product APIs to synchronously call feednow-auth for every protected request.
- Operators can diagnose auth, provisioning, denial, and storage failures via safe correlated telemetry and runbooks.
- End-to-end tests demonstrate the source specification's ten success criteria, including cross-adapter behavior and immediate revocation.
- Consumer documentation identifies future federation/PostgreSQL extension points without implementing either.

## Non-goals

Product adoption, Shopify identity implementation, billing, rate limits, rotation, and PostgreSQL delivery.

## Handoff

Deliver the versioned consumer contract, operational guide, validation evidence, and scoped follow-on projects for each consumer.

