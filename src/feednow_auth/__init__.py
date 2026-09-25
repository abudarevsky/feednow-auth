"""Packaging shim for the FeedNow auth operator tooling (Phase 13 task 5).

The runtime application lives in the ``app`` package; this package exists
because the required operator invocation is ``python -m feednow_auth.admin``
(spec 13 required behavior 4). This initializer is deliberately
**empty of behavior**: importing :mod:`feednow_auth` performs no I/O, reads
no environment, and imports nothing. The CLI itself lives in
:mod:`feednow_auth.admin`.
"""
