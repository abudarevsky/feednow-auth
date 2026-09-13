"""Test-support helpers shared by the Phase 03+ suites.

Deliberately outside ``app`` so runtime packages never import test machinery.
The Phase 03 acceptance rule these serve: token tests use signed fixtures or
a local JWKS test server — never a live Cognito pool.
"""
