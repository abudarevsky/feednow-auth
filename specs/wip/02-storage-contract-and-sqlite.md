# Phase 02 — Storage contract and SQLite behavior

**Dependency:** Phase 01  
**Handoff to:** Phases 03, 05, and 06

Current-state baseline: [application documentation](../../docs/README.md).
This phase defines the storage transformation from the documented current
state to the required SQLite-backed owner state.

## Goal

Create domain-oriented storage operations, a SQLite adapter for local/integration testing, and an executable adapter conformance suite.

## Work boundary

- Define a storage protocol for users, external identities, organizations, memberships, API keys, audit events, pagination, and atomic `provision_user`.
- Implement SQLite schema/transactions, constraints, repositories, and deterministic pagination at the contract boundary.
- Create adapter-neutral conformance tests plus a lightweight memory fake only where it helps unit tests.

## Acceptance criteria

- Application-facing storage methods reveal no SQL/SQLite-specific values.
- SQLite rejects duplicate external identities and duplicate organization/user membership as domain conflicts.
- `provision_user` atomically creates user, identity, organization, owner membership, and audit events, with safe duplicate/concurrent retries.
- Conformance tests cover retrieval, isolation, duplicate rejection, API-key lookup/revocation, provisioning, and pagination.
- The full conformance suite passes against a clean temporary SQLite database.

## Non-goals

No DynamoDB calls, HTTP routes, JWT parsing, or API-key secret hashing.

## Handoff

Document the storage factory and conformance invocation. Later phases use only the contract; Phase 06 runs this unchanged suite against DynamoDB.
