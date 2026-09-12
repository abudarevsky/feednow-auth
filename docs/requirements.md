# Documentation maintenance requirements

## Required structure

- `docs/README.md` is the agent reading-order entrypoint.
- `docs/architecture.md` describes ownership and dependency direction.
- `docs/contracts.md` describes public and cross-phase invariants.
- `docs/operations.md` contains runnable setup and verification commands.
- `docs/phases/` contains one handoff document per active or completed phase.
- `docs/` is the source of truth for the implemented application state.
- `specs/` defines future-state strategy, owner boundaries, steps, and
  acceptance criteria; specs may link to docs for the baseline.

## Change rules

- Update docs in the same change as code or contract changes.
- Link new concepts to their source module and record the implemented
  behavior here; do not link docs to WIP or draft specifications.
- Include scope, invariants, examples, verification, and known limitations
  for every current-state document. Keep transformation steps in `specs/`.
- Do not duplicate a contract with a second conflicting value; link to the
  canonical specification instead.
- Do not describe an unverified deployment, browser flow, or remote resource
  as complete.
- Preserve historical phase evidence under `specs/done/`; correct it with a
  new note or current handoff rather than rewriting its recorded results.

## Documentation definition of done

- The affected docs exist and are linked from `docs/README.md`.
- Repository paths and commands work with the `src/` layout.
- Implemented behavior and known limitations are explicit.
- `git diff --check` passes and the relevant verification commands are
  recorded.
