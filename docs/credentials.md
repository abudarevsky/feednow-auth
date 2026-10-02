# API Key Management

This document describes the API key management system implemented in feednow-auth, covering credential format, generation, verification, revocation, and security practices.

## Credential Format

API keys follow the `fn_<live|test>_<key-id>_<secret>` format:

- **Environment prefix** (`fn_live_` or `fn_test_`): 8-character fixed prefix indicating the key environment
- **Key ID**: 26-character Crockford-base32 ULID containing a 48-bit millisecond timestamp and 80 bits of randomness
- **Secret**: 43-character base64url-encoded string with 256 bits of CSPRNG entropy

Both environment forms are 78 characters: the fixed prefix is 8 characters,
followed by a 26-character key segment, one separator, and a 43-character
secret. The accepted input bound is 512 characters.

## Key Generation

API keys are generated as follows:

- **Key ID**: Generated using a Crockford-base32 ULID format
  - First 10 characters: 48-bit Unix millisecond timestamp (ensuring uniqueness)
  - Next 16 characters: 80 bits of cryptographically secure randomness
  - No underscores in the alphabet, ensuring unambiguous parsing

- **Secret**: Generated using `secrets.token_urlsafe(32)` producing exactly 32 bytes (256 bits) of cryptographically secure randomness
  - Base64url encoded with characters from the set: A-Z, a-z, 0-9, -, _
  - The secret contains no padding characters

## Storage and Security

### Secret Handling

The system operates under strict security principles:

- **Plaintext secrets never persist**: Secrets are stored only as HMAC-SHA256 hashes with a pepper
- **Hash storage format**: `HMAC-SHA256(pepper, secret)` encoded in lowercase hex (64 characters)
- **Pepper integration**: A server-side secret is used to prevent offline dictionary attacks on stolen databases

### Credential Structure in Storage

| Field | Description |
|-------|-------------|
| `key_id` | The 26-character Crockford-base32 ULID used for database lookup |
| `service_id` | Product binding; newly issued keys use `vispector` |
| `secret_hash` | The `HMAC-SHA256(pepper, secret)` hash (lowercase hex) |
| `key_prefix` | Masked display prefix: `fn_<env>_<key-id>_<first 6 secret chars>...` |

The literal (full credential) is **never stored**. Only the hashed version exists in the database.

## Verification Process

The system implements a constant-time verification pipeline that ensures timing-attack resistance:

1. **Parse**: Extract environment, key ID, and secret from the credential literal
2. **Point lookup**: Use the `key_id` to find the stored API key record
3. **Dummy comparison**: If key not found, perform constant-time dummy HMAC comparison
4. **Secret match**: Compare the provided secret against the stored hash using `hmac.compare_digest`
5. **Environment validation**: Ensure environment prefix matches stored value
6. **Status check**: Verify that the API key is active
7. **Expiry verification**: Check that the API key has not expired

All failures return uniform error messages and HTTP status codes to prevent information leakage.

## Scopes and service binding

Scopes are exact `product:resource:action` strings. Matching is exact; there
are no wildcard or hierarchical grants. A key has no organization role and
cannot inherit a human member or administrator role. Newly issued keys use the
`vispector` service binding; service-aware enforcement is used by the local
Vispector proof route documented in [local-account.md](local-account.md).

## Revocation (CAS)

API key revocation follows a first-write-wins Compare-And-Swap (CAS) mechanism:

- The system performs a database-level atomic check-and-set operation
- Concurrent revocations result in idempotent success preserving the original `revoked_at` timestamp
- Each processed revoke call appends a truthful audit record
- Duplicate/concurrent revocations each produce separate, distinct audit entries

## Secret Exposure and Return Behavior

The system follows strict practices to prevent credential exposure:

- **Secret returned only once**: The plaintext secret is returned **exactly once** in the API response (`201 Created`) during key creation
- **No log exposure**: Secrets are never logged or written to audit records
- **Zero-trust design**: Every part of the system treats secrets as sensitive material
- **Display prefix only**: Key identifiers appear only in masked form (`key_prefix`), revealing only the first 6 characters of the secret

## API Endpoints

### Creation
- **Method**: `POST /v1/organizations/{organization_id}/api-keys`
- **Success**: Returns `201 Created` with full credential literal (secret only in this response)
- **Failure**: Appropriate HTTP status codes and error messages for validation, conflict, or authorization failures

### Listing
- **Method**: `GET /v1/organizations/{organization_id}/api-keys`
- **Return**: Key identity, name, service, environment, masked prefix, status,
  scopes, and lifecycle timestamps; no secret or raw credential segment
- **Security**: Active and revoked keys are returned by design

### Revocation
- **Method**: `DELETE /v1/organizations/{organization_id}/api-keys/{key_id}`
- **Success**: Returns `204 No Content` 
- **Concurrency**: Idempotent, with first-write-wins CAS behavior

## Known Limitations

- No `last_used_at` tracking for API keys
- Expiry enforcement exists but is not settable via API
- No rotation capabilities (single pepper version)
- No scope wildcards or hierarchical matching
- No self-service key rotation or service reassignment
- Audit records appended after commit, with potential window for loss

## Security Properties

The system adheres to several security principles:

- **Secret handling**: Secrets are never stored or logged and are returned only in the creation response
- **Timing equalization**: Unknown-key lookup performs a dummy comparison; secret checks use constant-time comparison
- **Atomic operations**: All revocations follow first-write-wins semantics for consistency
- **Audited authorization**: Organization authorization denials use
  deterministic reason and operation metadata when the organization exists;
  credential material is never included.
