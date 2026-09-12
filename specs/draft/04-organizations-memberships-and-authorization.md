# Phase 04 — Organizations, memberships, and authorization

**Dependency:** Phase 03  
**Handoff to:** Phases 05 and 08

## Goal

Expose organization/membership management while making tenancy and role checks consistent, testable, and auditable.

## Work boundary

- Implement organization list/create/read and member list/add/remove endpoints with explicit role policy.
- Implement shared organization-access and role-authorization dependencies.
- Enforce organization isolation and append required mutation/denial audits.
- Define target-user resolution as an internal FeedNow user ID; do not introduce email invitations without a new specification.

## Acceptance criteria

- A user lists only memberships and cannot read another organization by guessed ID.
- Only documented roles mutate organizations/memberships; out-of-policy attempts are denied consistently.
- Membership creation/removal is duplicate-safe and preserves documented owner invariants.
- Authorized mutations create safe audit events; denials create `authorization.denied` without sensitive data.
- Integration tests cover owner/admin/member/viewer decisions and cross-tenant denial for every endpoint.

## Non-goals

API-key issuance, invitations, billing plans, and product business-resource authorization.

## Handoff

Document reusable role-check and organization-authorization contracts used by API-key management and downstream services.

