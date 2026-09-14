# Current state: DynamoDB adapter and cross-adapter conformance

Phase 06 is implemented. The production DynamoDB adapter sits behind the
frozen 19-method `Storage` contract — the second adapter after SQLite,
consumed **unchanged** by the Phase 02 conformance suite, which now runs
against DynamoDB Local as a second, marker-gated entry. Every multi-item
write is one `TransactWriteItems` with positional conflict classification,
`revoke_api_key` is a conditional-update CAS mirroring SQLite field-for-field,
lists are GSI queries with adapter-native opaque keyset cursors, and driver
exceptions never escape the adapter. Phase 06 changes **no** contract, model,
service, or API surface and adds **one** runtime dependency (`boto3`);
`app.main` stays DynamoDB-free (proven by the repo-wide AST scan and the
subprocess import proof). No cloud provisioning (Phase 07), no audit read
surface (Phase 08), no PostgreSQL.

## Scope

- `src/app/storage/dynamodb.py`: `SCHEMA` (the single-source seven-table
  layout), the `open_dynamodb_storage` factory + `DynamoDbStorage` adapter
  (all 19 contract methods), the pure codecs (timestamp/tenant/sort-key/
  constraint-key/cursor), and the pure positional classifier
  (`classify_cancellation_reasons` / `classify_client_error` /
  `execute_transaction` / `execute_conditional_write`). Imported only by
  explicit submodule path; `app/storage/__init__.py` stays contract-only.
- `src/tests/support/dynamodb_local.py`: the opt-in Local harness — endpoint
  probe + skip reason, `create_tables`/`delete_tables` driven by `SCHEMA`,
  `make_dynamodb_storage` through the documented factory; dummy credentials,
  fresh random table prefix per test.
- `src/tests/storage_contract/test_dynamodb_contract.py`: the conformance
  entry — the documented replication of the SQLite entry; re-exports
  `suite.py` **unchanged** (byte-identical hash pin) with the same 60
  adapter-neutral cases plus 3 entry-local proofs.
- Marker `dynamodb_local` registered in `pyproject.toml`; gating is
  `FEEDNOW_DYNAMODB_LOCAL_ENDPOINT` set **and** reachable, so the default
  `uv run pytest` stays green without Docker.
- `pyproject.toml`/`uv.lock`: `boto3>=1.35,<2` as the only new runtime
  dependency (its transitive closure — botocore, jmespath, python-dateutil,
  s3transfer, six, urllib3 — is the whole `uv.lock` delta).

## Table and index schema (transcribed from `SCHEMA`)

`SCHEMA` in `src/app/storage/dynamodb.py` is the single source: the Local
harness builds its `CreateTable` payloads from `TableSpec.create_parameters`,
and Phase 07's CDK stack must declare the same schema. Names carry a
configurable `table_prefix` (factory keyword) so `dev`/`staging`/`prod`
parameterize and the harness isolates per test.

| Table (prefix + name) | Partition key | Sort key | GSIs (ALL projection) | Carries |
| --- | --- | --- | --- | --- |
| `users` | `pk` = `usr_` id | — | — | user payload |
| `organizations` | `pk` = `org_` id | — | — | organization payload |
| `external_identities` | `pk` = `extid_` id | — | — | provider tuple + `user_id` |
| `audit_events` | `pk` = `aud_` id | — | — | audit payload (write-only this phase) |
| `api_keys` | `pk` = `key_` id | — | `by-organization`: `g_org` / `g_created` | key payload incl. `secret_hash` |
| `memberships` | `organization_id` | `user_id` | `by-organization`: `g_org` / `g_created`; `by-user`: `g_user` / `g_org_created` | membership payload + denormalized org `created_at` |
| `unique_constraints` | `pk` = `<kind>#<normalized value>` | — (key-only) | — | `kind`, `entity_id`, plus `user_id` on email/identity items |

Sort-key encodings (fixed-width sortable timestamp
`YYYY-MM-DDTHH:MM:SS.ffffffZ`, `#`-separated id tiebreaker last, so
lexicographic order equals `(created_at, id)` order): `g_created` =
`<created_at>#<mem_/key_ id>`; `g_org_created` =
`<organization created_at>#<org_ id>` (denormalized at write time — safe
because no organization update path exists in the frozen contract).

Record-id conflicts are **native** `attribute_not_exists(pk)` failures on
`users`/`organizations`/`external_identities`/`audit_events`/`api_keys`
(→ `kind="entity_id"`) and on the `memberships` base pair (→ `kind=
"membership"`). Everything DynamoDB cannot enforce natively is a
`unique_constraints` item, conditional-put with `attribute_not_exists(pk)`:

| Constraint `kind` | Value normalized into the PK | Surfaces as `DuplicateEntityKind` |
| --- | --- | --- |
| `user_email` | `user.email` | `user_email` |
| `organization_slug` | `organization.slug` | `organization_slug` |
| `external_identity` | `provider#subject#tenant` (`None`→`""`) | `external_identity` |
| `api_key_id` | the §8 credential segment | `api_key_id` |
| `membership_id` | the `mem_` record id (guard item) | `entity_id` |

The key-only constraint table is what makes every lookup whose entity id is
*unknown* (`get_user_by_external_identity`, `get_api_key_by_key_id`,
`provision_user`'s race-winner resolution) a single `GetItem`.

## Least-privilege IAM matrix (Phase 07 CDK input, AC 5)

Resource ARNs: `arn:aws:dynamodb:<region>:<account>:table/<prefix><name>`
and `.../table/<prefix><name>/index/<index-name>`. A `Query` on a GSI needs
`dynamodb:Query` on **both** the table and the index ARN.
`TransactWriteItems` has no dedicated action: each transact item needs the
underlying item action on its table (`Put` → `dynamodb:PutItem`,
`ConditionCheck` → `dynamodb:ConditionCheckItem`).

| Access pattern (contract op) | DynamoDB calls | IAM actions → resources |
| --- | --- | --- |
| `get_user` / `get_organization` / `get_membership` / `get_api_key` | `GetItem` (consistent) | `GetItem` → `users` / `organizations` / `memberships` / `api_keys` |
| `get_user_by_external_identity` | `GetItem` ×2 (constraint → user) | `GetItem` → `unique_constraints`, `users` |
| `get_api_key_by_key_id` | `GetItem` ×2 (constraint → key) | `GetItem` → `unique_constraints`, `api_keys` |
| `create_user` | `TransactWriteItems` (Put users + Put constraint) | `PutItem` → `users`, `unique_constraints` |
| `create_external_identity` | `TransactWriteItems` (Put + Put constraint + ConditionCheck user) | `PutItem` → `external_identities`, `unique_constraints`; `ConditionCheckItem` → `users` |
| `create_organization` | `TransactWriteItems` (Put orgs + Put constraint) | `PutItem` → `organizations`, `unique_constraints` |
| `create_membership` | `GetItem` orgs (denorm) + `TransactWriteItems` (Put + Put guard + ConditionCheck orgs/users) | `GetItem` → `organizations`; `PutItem` → `memberships`, `unique_constraints`; `ConditionCheckItem` → `organizations`, `users` |
| `create_api_key` | `TransactWriteItems` (Put + Put constraint + ConditionCheck orgs/users) | `PutItem` → `api_keys`, `unique_constraints`; `ConditionCheckItem` → `organizations`, `users` |
| `revoke_api_key` (CAS) | conditional `UpdateItem` + `GetItem` | `UpdateItem`, `GetItem` → `api_keys` |
| `delete_membership` | conditional `DeleteItem` | `DeleteItem` → `memberships` |
| `append_audit_event` | `TransactWriteItems` (Put audit + ConditionCheck org) | `PutItem` → `audit_events`; `ConditionCheckItem` → `organizations` |
| `list_user_organizations` | `Query` by-user + `BatchGetItem` orgs (trimmed page only) | `Query` → `memberships` + `memberships/index/by-user`; `BatchGetItem` → `organizations` |
| `list_memberships` | `Query` by-organization | `Query` → `memberships` + `memberships/index/by-organization` |
| `list_api_keys` | `Query` by-organization | `Query` → `api_keys` + `api_keys/index/by-organization` |
| `provision_user` | `TransactWriteItems` (8 entity/constraint puts + audits + external-parent `ConditionCheck`s) + `GetItem`s (race-winner constraint, external org) | `PutItem` → `users`, `external_identities`, `organizations`, `memberships`, `audit_events`, `unique_constraints`; `ConditionCheckItem` → `users`, `organizations`; `GetItem` → `unique_constraints`, `organizations` |
| `provision_organization` | `TransactWriteItems` (org + slug + membership + guard + audits + users check) + `GetItem` orgs (external-org denorm only) | `PutItem` → `organizations`, `memberships`, `audit_events`, `unique_constraints`; `ConditionCheckItem` → `users`, `organizations`; `GetItem` → `organizations` |

Consolidated per-resource grant (what the CDK policy should attach to the
Lambda execution role):

| Resource | Actions |
| --- | --- |
| `table/<prefix>users` | `GetItem`, `PutItem`, `ConditionCheckItem` |
| `table/<prefix>organizations` | `GetItem`, `PutItem`, `BatchGetItem`, `ConditionCheckItem` |
| `table/<prefix>external_identities` | `PutItem` |
| `table/<prefix>audit_events` | `PutItem` |
| `table/<prefix>api_keys` (+ `index/by-organization`) | `GetItem`, `PutItem`, `UpdateItem`, `Query` (index: `Query` only) |
| `table/<prefix>memberships` (+ `index/by-organization`, `index/by-user`) | `GetItem`, `PutItem`, `DeleteItem`, `Query` (indexes: `Query` only) |
| `table/<prefix>unique_constraints` | `GetItem`, `PutItem` |

Hardening options for Phase 07: every `PutItem`/`ConditionCheckItem` the
adapter performs is transactional, so those grants may be pinned with
`"Condition": {"StringEquals": {"dynamodb:EnclosingOperation":
"TransactWriteItems"}}`; `CreateTable`/`DeleteTable`/`DescribeTable` belong
to the CDK/CloudFormation deploy path **only** — the runtime adapter never
issues them (the test harness does, against Local). No `Scan`, no
`dynamodb:PutResourcePolicy`, no wildcard actions or resources.

## Conflict, pagination, and CAS translation summary

- **Positional classification (decision 3):** each operation submits its
  transact items in a fixed order (base puts → constraint puts → parent
  `ConditionCheck`s, mirroring SQLite's statement order) with a parallel
  descriptor list; on `TransactionCanceledException` the **first
  `ConditionalCheckFailed` in submission order** decides the domain error
  (constraint item → its mapped kind; base put → `entity_id`, except the
  membership pair → `membership`; parent check → `ReferenceNotFoundError`).
  Submission order is why a multi-failure race classifies identically on
  both adapters.
- **Transient vs stable:** `TransactionConflict` (and the single-item
  `TransactionConflictException`/`TransactionInProgressException`) are the
  DynamoDB analogue of SQLite's `busy_timeout` — the whole write re-runs a
  bounded number of times (`MAX_TRANSACTION_ATTEMPTS = 5`) so a racing loser
  converges on the winner's committed rows; exhaustion or throughput faults
  become the base `StorageError` (retryable channel; no new error classes).
  `provision_user`'s email/identity-tuple failure is spec §6's race →
  `DuplicateExternalIdentityError` with `existing_user_id` resolved by one
  post-rollback constraint `GetItem`; `provision_organization`'s taken slug
  is a plain `DuplicateEntityError` (no converge), deliberately.
- **No leak:** translated errors carry fixed, log-safe text — no table
  names, driver messages, regions, or request ids propagate.
- **Pagination (decision 5):** cursors are opaque base64url JSON
  `{"scope", "resume"}` carrying the **last returned** item's full key set
  (index + base keys), never the raw `LastEvaluatedKey` (which can sit past
  filtered rows); each `Query` fetches `SCAN_BATCH = 100` items and the loop
  accumulates to `limit + 1` (the probe-row pattern shared with SQLite's
  `_build_page`), so filtered continuation is exact; foreign-scope or
  malformed tokens → `InvalidCursorError`, never a raw decode error.
  `list_user_organizations` reassembles its page through one `BatchGetItem`
  read-back of the **trimmed** page's org ids (≤ `MAX_PAGE_LIMIT` = 100 keys,
  always inside the BatchGetItem caps; the probe row's org is never fetched).
- **CAS (decision 4):** `revoke_api_key` is a standalone conditional
  `UpdateItem` (`attribute_exists(pk) AND #status = 'active'`, setting only
  `status` + `revoked_at`); on a condition miss a consistent `GetItem`
  returns stored truth — absent → `EntityNotFoundError`, already-revoked →
  the original `revoked_at` (idempotent success), exactly SQLite's
  observable behavior.
- **Read-your-writes:** all point reads pass `ConsistentRead=True`; GSI
  queries cannot (DynamoDB rejects the flag on an index) — see limitations.

## Verification

Run commands live in [Operations](../operations.md#dynamodb-local-phase-06-harness).
Evidence (2026-09-14, DynamoDB Local 2.6.0 `-inMemory -sharedDb`):

- `uv run pytest` (default env, no Docker) → **1327 passed, 134 skipped**
  (baseline 1253 + Phase 06: 67 unit — task 1 harness support 18, task 2
  codec 30 + errors/classifier 19; 136 marker-gated — task 1 smoke 1, task 3
  identity 14, task 4 membership 20, task 5 api-keys 16, tasks 6–7
  provisioning 22, task 8 conformance entry 63 (2 of its entry-local proofs
  run by default); task 9 boundary proofs 5; every skip names
  `FEEDNOW_DYNAMODB_LOCAL_ENDPOINT` as its reason).
- `FEEDNOW_DYNAMODB_LOCAL_ENDPOINT=http://localhost:8000 uv run pytest` →
  **1461 passed** (the same suite with all 134 gated cases exercised).
- `FEEDNOW_DYNAMODB_LOCAL_ENDPOINT=http://localhost:8000 uv run pytest src/tests/storage_contract`
  → **127 passed** = SQLite entry 64 (60 suite cases + 4 entry-local driver
  proofs) + DynamoDB entry 63 (the same 60 cases + 3 entry-local proofs);
  `suite.py` byte-identical across entries (sha256 pin), no adapter-conditional
  test anywhere (AC 2).
- Concurrency barrier cases (`test_concurrent_identical_provisions_yield_exactly_one_success`,
  concurrent revocations) stable across 3 re-runs on the transactional path.
- `uv run ruff check .` / `uv run ruff format --check .` clean;
  `git diff --check` clean excluding the user-owned `AGENTS.md` (which stays
  dirty in the working tree by the phase precondition).
- AC 1 boundary proofs: the repo-wide AST scan
  (`src/tests/integration/test_dynamodb_isolation.py`) shows
  `storage/dynamodb.py` is the only `src/app` module importing
  `boto3`/`botocore`/`app.storage.dynamodb` (absolute or relative form),
  `app/storage/__init__.py` imports the contract only, and the
  subprocess-isolated `import app.main` loads no driver or adapter module.

## Known limitations

- **Local ≠ production:** DynamoDB Local ignores IAM entirely (the matrix
  above is CDK input, not test-verified), answers with negligible latency,
  and is always strongly consistent. In production the GSI `Query` reads are
  eventually consistent (the flag is rejected on index queries) — a
  just-written membership/key may miss its own listing for a replication
  interval; point reads are protected by `ConsistentRead=True`.
- **`last_used_at` is still never written** (unchanged Phase 05 limitation;
  verification is read-only by design; Phase 08 candidate).
- **Audit GSI reserved, not created:** `audit_events` stays append-only with
  no index — the Phase 08 read surface adds it; nothing today queries it.
- **`delete_membership` leaves the `mem_` guard item** (the breakdown pins a
  single conditional delete and the suite's re-grant-after-delete case uses
  a fresh `mem_` id, so the lifetime is unobserved; Phase 08 hardening note).
- **Duplicate record ids inside one provision batch** (caller misuse)
  surface as the base `StorageError` (a transaction may not touch one item
  twice) where SQLite reports a `DuplicateEntityError` — both are leak-free
  and leave zero residue; unreachable through the services.
- Retry/backoff tuning and capacity mode are Phase 08 operational
  hardening; `table_prefix` defaults to `""` and must be set per environment
  by the Phase 07 entrypoint.

## Published interfaces (what Phases 07/08 code against)

| Interface | Module | Consumers |
| --- | --- | --- |
| `SCHEMA` (`TableSpec`/`IndexSpec` + `create_parameters`) | `src/app/storage/dynamodb.py` | **Phase 07 CDK** (declare the same tables/indexes verbatim), Local harness |
| `open_dynamodb_storage(*, endpoint_url=None, region="us-east-1", table_prefix="", dynamodb_resource=None) -> DynamoDbStorage` + `close()` | `src/app/storage/dynamodb.py` | Phase 07 deployment entrypoint (same `Storage`-typed instance the routers/services already take) |
| The IAM matrix above | this document | **Phase 07 CDK** least-privilege policy |
| The 19-method `Storage` contract + domain errors | `src/app/storage/contract.py` | unchanged — SQLite and DynamoDB are interchangeable behind it |
| `dynamodb_local` marker + `FEEDNOW_DYNAMODB_LOCAL_ENDPOINT` gating + harness (`create_tables`/`delete_tables`/`make_dynamodb_storage`) | `pyproject.toml`, `src/tests/support/dynamodb_local.py` | every future adapter entry (Phase 08 hardening runs) |
| Conformance entries (`test_sqlite_contract.py`, `test_dynamodb_contract.py`) over `suite.py` | `src/tests/storage_contract/` | any new adapter must add an entry, never a suite edit |
