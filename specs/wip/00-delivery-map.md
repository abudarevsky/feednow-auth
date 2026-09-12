# feednow-auth delivery map

## Source and sequencing

Current-state baseline: [agent-oriented application documentation](../../docs/README.md).
The documentation describes what exists; this delivery map describes the
future-state transformation sequence.

This plan decomposes `../draft/feednow-auth-service-specification.md` into independently reviewable work. Each phase is a unit of work for an implementation agent, not a mandate to implement every later phase in the same change.

| Phase | Unit of work | Depends on | Produces |
| --- | --- | --- | --- |
| 01 | Repository foundation and domain contracts | none | runnable service skeleton and stable domain boundary |
| 02 | Storage contract and SQLite behavior | 01 | local persistence plus executable conformance suite |
| 03 | Identity resolution and safe provisioning | 02 | Cognito identity mapping and default tenancy |
| 04 | Organization membership and authorization | 03 | tenancy-protected organization and membership API |
| 05 | API-key credentials and scoped authorization | 02, 04 | one-time issuance, verification, and revocation |
| 06 | DynamoDB adapter and cross-adapter verification | 02, 03, 05 | production adapter with behavior parity |
| 07 | AWS infrastructure and deployable runtime | 03, 05, 06 | Cognito, Lambda/API Gateway, DynamoDB, secrets, IAM |
| 08 | Service hardening and consumer contract | 04, 05, 06, 07 | operational controls and reusable integration guidance |

## Cross-phase invariants

- Provider identities map to internal FeedNow users through `ExternalIdentity`; product services must not require Cognito-specific data.
- Organizations are the tenancy boundary for business resources and API credentials.
- Storage adapters implement domain operations, including atomic compound operations; adapter-specific types stay private.
- Human and API-client authentication resolve to one common authorization context.
- Sensitive values are never persisted or logged.

## Review rule

An agent should use one phase file as its scope. If delivery uncovers a missing contract, propose an explicit update to the current or later phase rather than smuggling cross-cutting behavior into implementation.
