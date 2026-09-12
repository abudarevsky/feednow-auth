# Phase 01 — Repository foundation and domain contracts

**Dependency:** none  
**Handoff to:** Phase 02

## Goal

Establish a Python 3.13+ FastAPI service layout (dev toolchain pinned to 3.14.5 per acceptance criteria; see breakdown) and provider-neutral domain/API contracts without binding business logic to persistence or AWS SDKs.

## Work boundary

- Create the package layout in `AGENTS.md`, `pyproject.toml`, local developer commands, and a minimal health-capable FastAPI application.
- Define Pydantic/domain models for User, ExternalIdentity, Organization, Membership, ApiKey (never with plaintext secret persistence), AuditEvent, and AuthorizationContext.
- Define stable ID, timestamp, status, role, organization type, environment, scope, pagination, and error conventions.
- Define versioned request/response schemas for specified endpoints; handlers may remain unimplemented until their owner phase.

## Acceptance criteria

- Python 3.14.5 dependency and test tooling are reproducibly declared.
- The app imports and exposes a health endpoint without AWS credentials or a database connection.
- Domain models represent every specified entity and internal IDs are distinct from external provider subjects.
- API schemas do not expose secret hashes, tokens, or plaintext credentials except an explicit one-time key-creation response type.
- Focused unit tests validate serialization and invalid enum/shape rejection.

## Non-goals

No database adapter, Cognito validation, endpoint behavior, or AWS CDK resources.

## Handoff

Provide package/import commands, model/schema documentation, and the exact contract modules Phase 02 must implement against.

**Breakdown:** [01-foundation-and-domain-contracts-breakdown.md](01-foundation-and-domain-contracts-breakdown.md) — APPROVED WITH EDITS (reviewer, 2026-09-12); ready for @build-step. Precondition: `git init` + scaffold commit.
