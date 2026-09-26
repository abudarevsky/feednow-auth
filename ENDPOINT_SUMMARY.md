# API Endpoints Documentation

## Identity Endpoints (User Management)
1. **GET /v1/me**
   - Description: Get current user identity
   - Response: MeResponse with user details (id, display_name, email, status, application_role, created_at, updated_at)
   - Authentication: Required (bearer token)

## Organization Endpoints
2. **GET /v1/organizations**
   - Description: List user's active organizations
   - Response: Paginated list of OrganizationResponse objects
   - Authentication: Required (bearer token)
   - Query parameters: limit, cursor

3. **POST /v1/organizations**
   - Description: Create a new organization
   - Request: OrganizationCreateRequest (name, slug, type)
   - Response: OrganizationResponse with organization details
   - Authentication: Required (bearer token)
   - Status code: 201 Created

4. **GET /v1/organizations/{organization_id}**
   - Description: Get a specific organization
   - Response: OrganizationResponse with organization details
   - Authentication: Required (member access)
   - Path parameter: organization_id

5. **PATCH /v1/organizations/{organization_id}**
   - Description: Rename an organization
   - Request: OrganizationRenameRequest (name)
   - Response: OrganizationResponse with updated organization details
   - Authentication: Required (admin access)
   - Path parameter: organization_id

## Member Endpoints
6. **GET /v1/organizations/{organization_id}/members**
   - Description: List members of an organization
   - Response: Paginated list of MemberResponse objects
   - Authentication: Required (member access)
   - Path parameter: organization_id
   - Query parameters: limit, cursor

7. **POST /v1/organizations/{organization_id}/members**
   - Description: Add a member to an organization
   - Request: MemberCreateRequest (user_id, role)
   - Response: MemberResponse with membership details
   - Authentication: Required (admin access)
   - Path parameter: organization_id

8. **DELETE /v1/organizations/{organization_id}/members/{user_id}**
   - Description: Remove a member from an organization
   - Authentication: Required (admin access)
   - Path parameters: organization_id, user_id
   - Status code: 204 No Content

## API Key Endpoints
9. **GET /v1/organizations/{organization_id}/api-keys**
   - Description: List API keys for an organization
   - Response: Paginated list of ApiKeySummary objects
   - Authentication: Required (member access)
   - Path parameter: organization_id
   - Query parameters: limit, cursor

10. **POST /v1/organizations/{organization_id}/api-keys**
    - Description: Create a new API key for an organization
    - Request: ApiKeyCreateRequest (name, environment, scopes)
    - Response: ApiKeyCreatedResponse with the full secret (returned only once at creation)
    - Authentication: Required (admin access)
    - Path parameter: organization_id
    - Status code: 201 Created

11. **DELETE /v1/organizations/{organization_id}/api-keys/{key_id}**
    - Description: Revoke an API key
    - Authentication: Required (admin access)
    - Path parameters: organization_id, key_id
    - Status code: 204 No Content

## Admin Endpoints
12. **GET /v1/admin/summary**
    - Description: Get application administrative summary
    - Response: AdminSummary
    - Authentication: Required (application admin access)

13. **GET /v1/admin/organizations**
    - Description: Search organizations (admin)
    - Response: Paginated list of AdminOrganization objects
    - Query parameters: limit, cursor, q (search query)

14. **GET /v1/admin/organizations/{organization_id}**
    - Description: Get detailed organization information (admin)
    - Response: AdminOrganizationDetail
    - Path parameter: organization_id

15. **GET /v1/admin/organizations/{organization_id}/members**
    - Description: List members of an organization (admin)
    - Response: Paginated list of AdminMember objects
    - Path parameter: organization_id
    - Query parameters: limit, cursor

## Security Notes
- API keys are handled according to strict security requirements
- Plaintext secrets are returned only once at key creation and are never logged or stored in plaintext
- All authentication uses JWT tokens and proper authorization checks
- Admin endpoints require application-level administrator privileges
- Organization access is validated at the member level for read operations and admin level for write operations