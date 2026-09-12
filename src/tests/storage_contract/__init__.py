"""Adapter-neutral storage conformance harness (Phase 02).

``suite.py`` holds the shared behavior cases; ``test_sqlite_contract.py`` is
the SQLite entry point that provides the ``storage`` fixture. Phase 06 adds
an equivalent DynamoDB entry point and runs the suite module unchanged.
"""
