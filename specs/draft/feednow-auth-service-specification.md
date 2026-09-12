# feednow-auth Service Specification

## 1. Purpose

`feednow-auth` is the central authentication, identity, tenancy, authorization, and API credential service for FeedNow products.

Repository baseline: [current application documentation](../../docs/README.md).
This specification defines the target behavior and transformation strategy;
the documentation describes only behavior that exists and has been verified.

Initial consumers:

* Vispector
* ExcelToPIM
* future public APIs
* future Shopify integration

The service must remain product-independent.

Its responsibilities are:

* Cognito-based user authentication integration;
* FeedNow user identity management;
* organization and tenant management;
* memberships and roles;
* API key lifecycle management;
* authorization context resolution;
* storage abstraction;
* audit logging;
* future support for additional identity providers.

Authentication providers prove identity. `feednow-auth` owns application identity and authorization.

---

## 2. Technology

Use:

* Python 3.13+
* FastAPI
* Pydantic v2
* boto3
* PyJWT or Authlib
* SQLite for local development and service integration tests
* DynamoDB for AWS production
* DynamoDB Local for adapter verification
* AWS CDK v2 for infrastructure
* AWS Cognito User Pool
* AWS Secrets Manager
* API Gateway
* Lambda initially

Python is appropriate because this service is predominantly I/O-bound and integrates naturally with Cognito, AWS SDKs, FastAPI, and existing FeedNow Python services.

---

## 3. High-Level Architecture

```text
                 Amazon Cognito
                      │
               Cognito access token
                      │
                      ▼
               feednow-auth
        ┌────────────────────────────┐
        │ Users                      │
        │ External identities        │
        │ Organizations              │
        │ Memberships                │
        │ API keys                   │
        │ Audit events               │
        └─────────────┬──────────────┘
                      │
               Storage contract
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
       SQLite      DynamoDB    PostgreSQL
       local       AWS prod    future
```

`feednow-auth` must not become a mandatory synchronous proxy for every product API request.

It owns identity data and credentials, while product services may validate credentials through reusable middleware or infrastructure authorizers.

---

## 4. Domain Model

### User

```text
User
----
id
display_name
email
status
created_at
updated_at
```

`User.id` is an internal FeedNow identifier.

Do not use:

* email;
* Cognito username;
* Cognito `sub`;
* Shopify ID

as the internal primary identity.

### ExternalIdentity

```text
ExternalIdentity
----------------
id
user_id
provider
provider_subject
provider_tenant
created_at
```

Initial provider:

```text
provider = cognito
provider_subject = Cognito sub
```

Future providers may include:

```text
shopify
google
microsoft
oidc
```

Uniqueness:

```text
(provider, provider_subject, provider_tenant)
```

### Organization

```text
Organization
------------
id
name
slug
type
status
created_at
updated_at
```

Every business resource in FeedNow applications belongs to an organization.

Initial types:

```text
personal
customer
internal
```

### Membership

```text
Membership
----------
id
organization_id
user_id
role
status
created_at
```

Initial roles:

```text
owner
admin
member
viewer
```

### API Key

```text
ApiKey
------
id
organization_id
created_by_user_id
name
key_id
key_prefix
secret_hash
environment
scopes
status
created_at
last_used_at
expires_at
revoked_at
```

Plaintext API secrets must never be persisted.

### Audit Event

```text
AuditEvent
----------
id
organization_id
actor_type
actor_id
action
target_type
target_id
metadata
created_at
```

---

## 5. Cognito Authentication

Cognito is the authentication provider for standalone FeedNow applications.

Initial capabilities:

* email/password registration;
* email verification;
* login;
* logout;
* password reset;
* OAuth Authorization Code Flow with PKCE.

Future federation:

* Google;
* Microsoft;
* enterprise OIDC;
* SAML.

FeedNow applications should use Cognito access tokens when calling APIs.

---

## 6. User Provisioning

On the first authenticated request:

```text
Cognito sub
    ↓
ExternalIdentity lookup
    ↓
FeedNow User
```

If no identity exists:

1. create `User`;
2. create `ExternalIdentity`;
3. create default organization;
4. create `owner` membership.

Provisioning must be atomic from the service perspective and safe against duplicate concurrent requests.

---

## 7. Default Organization

A newly registered user receives a default workspace.

Example:

```text
Andrey's Workspace
```

The user becomes its `owner`.

The organization may later be renamed or converted into a business organization.

---

## 8. API Keys

API keys are first-class FeedNow credentials for programmatic access.

Recommended format:

```text
fn_live_<key-id>_<secret>
fn_test_<key-id>_<secret>
```

Example:

```text
fn_live_01JXYZ7K_a8f...
```

The secret must contain at least 256 bits of cryptographically secure randomness.

The credential must contain a non-secret `key-id` so validation can perform an efficient point lookup.

### API Key Verification

```text
credential
    ↓
extract key-id
    ↓
storage.get_api_key_by_key_id()
    ↓
retrieve stored secret hash
    ↓
hash supplied secret
    ↓
constant-time comparison
```

### Hashing

Use:

```text
HMAC-SHA256(server_pepper, secret)
```

The pepper must be stored outside the database, initially in AWS Secrets Manager.

---

## 9. Scopes

API keys support product-specific scopes.

Initial Vispector examples:

```text
vispector:inspection:run
vispector:inspection:read
vispector:project:read
vispector:spec:read
```

Future ExcelToPIM examples:

```text
exceltopim:catalog:read
exceltopim:catalog:write
```

Commercial plans and rate limits must not be encoded in scopes.

---

## 10. Authorization Context

Every authentication mechanism resolves to the same internal representation.

Human:

```json
{
  "actor_type": "user",
  "actor_id": "usr_...",
  "organization_id": "org_...",
  "roles": ["admin"],
  "scopes": []
}
```

API client:

```json
{
  "actor_type": "api_key",
  "actor_id": "key_...",
  "organization_id": "org_...",
  "roles": [],
  "scopes": ["vispector:inspection:run"]
}
```

Future Shopify authentication must resolve into the same concept.

---

## 11. Storage Abstraction

`feednow-auth` must not depend directly on a particular database.

Recommended structure:

```text
src/app/
  storage/
    contract.py
    sqlite.py
    dynamodb.py
    memory.py
```

Environment mapping:

```text
Unit tests          → in-memory fake / mocks
Local development   → SQLite
Integration tests   → SQLite
Adapter verification→ DynamoDB Local
AWS production      → DynamoDB
K8s portable        → PostgreSQL adapter later
```

### Storage Contract

Example:

```python
class Storage(Protocol):
    def create_user(...)
    def get_user(...)
    def create_external_identity(...)
    def get_user_by_external_identity(...)

    def create_organization(...)
    def get_organization(...)
    def list_user_organizations(...)

    def create_membership(...)
    def get_membership(...)
    def list_memberships(...)
    def delete_membership(...)

    def create_api_key(...)
    def get_api_key(...)
    def get_api_key_by_key_id(...)
    def list_api_keys(...)
    def revoke_api_key(...)

    def append_audit_event(...)
```

Storage-specific concepts must not leak into application code.

Examples that must remain inside adapters:

```text
DynamoDB LastEvaluatedKey
ConditionalCheckFailedException
SQLite Row
SQLAlchemy Session
```

---

## 12. Storage Semantics

The abstraction should represent domain operations, not lowest-common-denominator database operations.

Prefer:

```text
provision_user()
revoke_api_key()
create_membership()
resolve_external_identity()
```

over exposing raw transactions or database commands.

For compound operations, the storage contract may expose atomic domain operations.

Example:

```python
storage.provision_user(
    user=user,
    identity=identity,
    organization=organization,
    membership=membership,
)
```

SQLite may implement this with a transaction.

DynamoDB may implement it with `TransactWriteItems`.

---

## 13. Storage Conformance Tests

The same behavior suite must run against SQLite and DynamoDB.

Required cases include:

* create and retrieve user;
* duplicate external identity is rejected;
* duplicate membership is rejected;
* API key creation;
* API key lookup;
* revoked API key is rejected;
* organization isolation;
* atomic first-user provisioning;
* pagination semantics.

SQLite is the primary service-level test adapter.

DynamoDB Local is used for DynamoDB-specific behavior.

---

## 14. API

### Current User

```text
GET /v1/me
```

### Organizations

```text
GET  /v1/organizations
POST /v1/organizations
GET  /v1/organizations/{organization_id}
```

### Memberships

```text
GET    /v1/organizations/{organization_id}/members
POST   /v1/organizations/{organization_id}/members
DELETE /v1/organizations/{organization_id}/members/{user_id}
```

### API Keys

```text
GET    /v1/organizations/{organization_id}/api-keys
POST   /v1/organizations/{organization_id}/api-keys
DELETE /v1/organizations/{organization_id}/api-keys/{key_id}
```

Initial key management supports:

* create;
* list;
* revoke.

Rotation may follow later.

---

## 15. API Key Creation

Request:

```json
{
  "name": "Production inspection",
  "environment": "live",
  "scopes": [
    "vispector:inspection:run",
    "vispector:inspection:read"
  ]
}
```

Response on creation:

```json
{
  "id": "key_...",
  "name": "Production inspection",
  "key": "fn_live_01J..._xxxxxxxx",
  "created_at": "..."
}
```

The complete secret is returned once only.

Subsequent requests return only masked information.

---

## 16. Audit Requirements

At minimum record:

```text
user.created
organization.created
membership.created
membership.removed
api_key.created
api_key.revoked
authorization.denied
```

Never record:

* plaintext API keys;
* Cognito tokens;
* passwords;
* refresh tokens.

---

## 17. Infrastructure

Provision through AWS CDK under `deploy/aws/cdk`, following the Vispector deployment layout:

```text
Cognito User Pool
Cognito App Client
Cognito domain
API Gateway
Lambda
DynamoDB
Secrets Manager
IAM roles
CloudWatch logs
```

Use separate environments:

```text
dev
staging
prod
```

---

## 18. Repository

```text
feednow-auth/
├── src/
│   ├── app/
│   │   ├── api/
│   │   ├── auth/
│   │   ├── models/
│   │   ├── services/
│   │   ├── storage/
│   │   │   ├── contract.py
│   │   │   ├── sqlite.py
│   │   │   ├── dynamodb.py
│   │   │   └── memory.py
│   │   └── main.py
│   └── tests/
│       ├── unit/
│       ├── integration/
│       └── storage_contract/
├── deploy/
│   └── aws/
│       ├── lambda-requirements.txt
│       └── cdk/
│           ├── app.py
│           ├── cdk.json
│           ├── requirements.txt
│           ├── feednow_auth_stack.py
│           └── .env.example
├── pyproject.toml
└── README.md
```

---

## 19. Phase 1

Deliver:

* Cognito infrastructure;
* JWT validation;
* user provisioning;
* default organization creation;
* organizations;
* memberships;
* SQLite storage adapter;
* DynamoDB storage adapter;
* storage conformance suite;
* API key creation;
* API key listing;
* API key revocation;
* API key scope model;
* audit events.

---

## 20. Success Criteria

The service is complete when:

1. A new Cognito user can be mapped to a FeedNow user.
2. First login creates a default organization safely.
3. Memberships determine organization access.
4. An admin can create an API key.
5. API key plaintext is returned only once.
6. A revoked key is immediately invalid.
7. SQLite and DynamoDB pass the same storage conformance suite.
8. No product code depends on DynamoDB-specific behavior.
9. A future Shopify identity can map into the same user/organization model.
10. A future PostgreSQL adapter can be introduced without changing service business logic.
