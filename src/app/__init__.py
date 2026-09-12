"""FeedNow auth service runtime package.

Layering (see AGENTS.md): ``api`` for HTTP handling, ``auth`` for credential
and JWT logic, ``models`` for provider-neutral domain types, ``services``
for business rules, and ``storage`` for the persistence contract/adapters.
"""
