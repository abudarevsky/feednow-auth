# feednow-auth documentation

This is the agent-oriented entrypoint for `feednow-auth`. Read documents in
this order before changing the service:

1. [Architecture](architecture.md) — ownership and dependency boundaries.
2. [Contracts](contracts.md) — stable domain, API, error, and pagination rules.
3. [Operations](operations.md) — local commands, production runtime, and checks.
4. [Phase 01](phases/01-foundation.md) — completed foundation handoff.
5. [Phase 02](phases/02-storage.md) — current storage baseline and gap.

These documents are the source of truth for the application that exists in
this repository. They describe implemented paths, behavior, contracts,
runtime, and verified evidence. Transformation plans belong in `specs/` and
may link here for their current-state baseline; this documentation set does
not link to future-state specifications.

## Documentation rule

Every behavior or contract change must update the nearest document here and
the governing `specs/` file when the public contract changes. A phase is not
complete until its docs, verification evidence, and handoff boundary are
updated together. See [Documentation requirements](requirements.md).
