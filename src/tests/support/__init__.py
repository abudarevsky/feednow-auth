"""Test-support helpers shared by the identity+ suites.

Deliberately outside ``app`` so runtime packages never import test machinery.
The identity acceptance rule these serve: token tests use signed fixtures or
a local JWKS test server — never a live Cognito pool.

Current behavior and invariants: ``docs/architecture.md``."""
