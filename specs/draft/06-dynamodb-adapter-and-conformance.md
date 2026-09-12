# Phase 06 — DynamoDB adapter and cross-adapter conformance

**Dependency:** Phases 02, 03, and 05  
**Handoff to:** Phases 07 and 08

## Goal

Implement the production DynamoDB adapter behind the storage contract and prove behavior parity with SQLite.

## Work boundary

- Design keys/indexes from contract access patterns, including external identity/key-ID lookup, organization membership listing, and audit access.
- Implement conflict mapping, pagination translation, and atomic operations with DynamoDB transactions/conditions.
- Run the existing conformance suite against DynamoDB Local and document adapter verification.

## Acceptance criteria

- No service/API module imports DynamoDB client types or catches DynamoDB exceptions.
- DynamoDB Local passes the same conformance cases as SQLite without adapter-conditional tests.
- Identity/membership uniqueness, provisioning, key lookup/revocation, isolation, and pagination match SQLite observations.
- Conditional/transaction failures become stable domain conflicts or retryable errors.
- Table/index schema and required IAM actions are documented for the AWS CDK stack.

## Non-goals

Cloud provisioning, PostgreSQL, and public API changes merely to fit DynamoDB.

## Handoff

Provide DynamoDB Local validation, table/index requirements, and a least-privilege access matrix for Phase 07.
