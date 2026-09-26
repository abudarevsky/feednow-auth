# FeedNow Auth API Endpoints

## Overview
The feednow-auth service exposes a RESTful API with authentication and authorization capabilities for managing users, organizations, membership, and API keys.

## Endpoints by Category

### 1. Identity/User Endpoints (Phase 03)
- **GET /v1/me** - Get current user information
  - Returns: MeResponse with user details
  - Authentication: Required
  - Authorization: None (user-scoped)

### 2. Organization Endpoints (Phase 04)
- **GET /v1/organizations** - List user's organizations
  - Returns: Page of OrganizationResponse
  - Authentication: Required
  - Authorization: Member role required

- **POST /v1/organizations** - Create new organization
  - Request: OrganizationCreateRequest
  - Returns: OrganizationResponse
  - Authentication: Required
  - Authorization: User must be authenticated (creates organization with owner role)

- **GET /v1/organizations/{organization_id}** - Get organization details
  - Returns: OrganizationResponse
  - Authentication: Required
  - Authorization: Member role required

- **PATCH /v1/organizations/{organization_id}** - Rename organization
  - Request: OrganizationRenameRequest
  - Returns: OrganizationResponse
  - Authentication: Required
  - Authorization: Admin role required

### 3. Membership Endpoints (Phase 04)
- **GET /v1/organizations/{organization_id}/members** - List organization members
  - Returns: Page of MemberResponse
  - Authentication: Required
  - Authorization: Member role required

- **POST /v1/organizations/{organization_id}/members** - Add member to organization
  - Request: MemberCreateRequest
  - Returns: MemberResponse
  - Authentication: Required
  - Authorization: Admin role required

- **DELETE /v1/organizations/{organization_id}/members/{user_id}** - Remove member from organization
  - Authentication: Required
  - Authorization: Admin role required

### 4. API Key Endpoints (Phase 05)
- **GET /v1/organizations/{organization_id}/api-keys** - List organization API keys
  - Returns: Page of ApiKeySummary
  - Authentication: Required
  - Authorization: Member role required

- **POST /v1/organizations/{organization_id}/api-keys** - Create new API key
  - Request: ApiKeyCreateRequest
  - Returns: ApiKeyCreatedResponse (includes full secret)
  - Authentication: Required
  - Authorization: Admin role required

- **DELETE /v1/organizations/{organization_id}/api-keys/{key_id}** - Revoke API key
  - Authentication: Required
  - Authorization: Admin role required

### 5. Administrative Endpoints (Phase 13)
- **GET /v1/admin/summary** - Get application summary
  - Returns: AdminSummary
  - Authentication: Required
  - Authorization: Application admin role required

- **GET /v1/admin/organizations** - Search organizations
  - Returns: Page of AdminOrganization
  - Authentication: Required
  - Authorization: Application admin role required

- **GET /v1/admin/organizations/{organization_id}** - Get organization detail
  - Returns: AdminOrganizationDetail
  - Authentication: Required
  - Authorization: Application admin role required

- **GET /v1/admin/organizations/{organization_id}/members** - List organization members (admin view)
  - Returns: Page of AdminMember
  - Authentication: Required
  - Authorization: Application admin role required

### 6. Authentication/OAuth Endpoints (Phase 11)
- **GET /oauth/login** - Initiate OAuth login flow
  - Redirects to Cognito Hosted UI
  - Authentication: Not required
  - Authorization: Not applicable

- **GET /oauth/callback** - Complete OAuth login flow
  - Handles callback from Cognito
  - Authentication: Not required
  - Authorization: Not applicable

### 7. Operational Endpoints (Phase 01)
- **GET /health** - Service health check
  - Returns: HealthResponse
  - Authentication: Not required
  - Authorization: Not applicable

## Authentication & Authorization Flow
Users authenticate via JWT tokens or API keys. Organization membership is determined through a role-based access control system with different permission levels:
- Member (read-only)
- Admin (read and write operations on organization resources)
- Application Admin (full administrative privileges)

API key authentication uses the prefix dispatch method where keys starting with "fn_live_" or "fn_test_" are treated as API keys, while other tokens are treated as JWTs.

## Security Notes
- All credential material is handled securely with no plaintext secrets in logs or databases
- API keys include a masked prefix but the full secret is only returned at creation time
- The service follows strict identity and authorization boundaries using domain models
- Session management (Phase 11) implements OAuth with PKCE for secure authentication