"""Adapter-neutral storage conformance harness (storage).

``suite.py`` holds the shared behavior cases; ``test_sqlite_contract.py`` is
the SQLite entry point that provides the ``storage`` fixture. DynamoDB adds
an equivalent DynamoDB entry point and runs the suite module unchanged.

Current behavior and invariants: ``docs/storage.md``."""
