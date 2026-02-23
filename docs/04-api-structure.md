# Direct Organization Management System - API Structure

**Document Version**: 1.0  
**Created**: February 2026  
**Last Updated**: February 2026  
**Status**: Draft

## Table of Contents

1. [API Overview](#api-overview)
2. [API Design Principles](#api-design-principles)
3. [Authentication and Authorization](#authentication-and-authorization)
4. [API Endpoints](#api-endpoints)
5. [Request and Response Formats](#request-and-response-formats)
6. [Error Handling](#error-handling)
7. [Rate Limiting and Throttling](#rate-limiting-and-throttling)
8. [API Versioning](#api-versioning)
9. [API Documentation](#api-documentation)

## API Overview

The Direct Organization Management System provides a comprehensive RESTful API for managing organizations, users, roles, permissions, and groups. The API follows REST principles with proper HTTP methods, status codes, and resource-oriented design.

### API Base URL

```
https://api.direct.example.com/v1/
```

### API Architecture

- **RESTful Design**: Resource-oriented endpoints with standard HTTP methods
- **Stateless**: Each request contains all necessary information
- **JSON Format**: All requests and responses use JSON format
- **Versioning**: API versioning through URL path
- **Authentication**: JWT-based authentication with role-based authorization

### Supported HTTP Methods

- **GET**: Retrieve resources
- **POST**: Create new resources
- **PUT**: Update existing resources (full update)
- **PATCH**: Update existing resources (partial update)
- **DELETE**: Delete resources

## API Design Principles

### Resource Naming

- Use plural nouns for resource names
- Use kebab-case for multi-word resources
- Use nested paths for hierarchical relationships

```http
GET /api/v1/organizations
GET /api/v1/organizations/{orgId}/users
GET /api/v1/organizations/{orgId}/groups/{groupId}/members
```

### HTTP Status Codes

- **200 OK**: Successful GET, PUT, PATCH, DELETE
- **201 Created**: Successful POST
- **204 No Content**: Successful DELETE with no response body
- **400 Bad Request**: Invalid request format or parameters
- **401 Unauthorized**: Authentication required or failed
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Resource not found
- **409 Conflict**: Resource conflict (e.g., duplicate name)
- **422 Unprocessable Entity**: Validation errors
- **429 Too Many Requests**: Rate limit exceeded
- **500 Internal Server Error**: Server error

### Pagination

All list endpoints support pagination using cursor-based pagination:

```http
GET /api/v1/organizations?page=2&limit=20&cursor=eyJpZCI6MTIzfQ==
```

**Response Format:**
```json
{
  "data": [...],
  "pagination": {
    "page": 2,
    "limit": 20,
    "total": 150,
    "hasNext": true,
    "hasPrev": true,
    "nextCursor": "eyJpZCI6MTIzfQ==",
    "prevCursor": "eyJpZCI6ODd9"
  }
}
```

### Filtering and Sorting

```http
GET /api/v1/users?status=active&organizationUnitId=uuid&sortBy=lastName&sortOrder=asc
```

### Search

```http
GET /api/v1/users/search?q=john&fields=name,email
```

## Authentication and Authorization

### Authentication

The API uses JWT (JSON Web Tokens) for authentication:

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Token Structure

```json
{
  "userId": "user-uuid",
  "organizationId": "org-uuid",
  "roles": ["ADMIN", "OU_OWNER"],
  "permissions": ["view_users", "manage_roles"],
  "exp": 1645123456,
  "iat": 1645120856
}
```

### Authentication Endpoints

#### Login

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "refresh-token-string",
  "expiresIn": 3600,
  "user": {
    "id": "user-uuid",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "organizationId": "org-uuid",
    "roles": ["ADMIN"],
    "permissions": ["view_users", "manage_roles"]
  }
}
```

#### Refresh Token

```http
POST /api/v1/auth/refresh
Content-Type: application/json

{
  "refreshToken": "refresh-token-string"
}
```

#### Logout

```http
POST /api/v1/auth/logout
Authorization: Bearer token
```

### Authorization

Role-based access control (RBAC) with scope support:

- **Organization-level permissions**: Apply to entire organization
- **Group-scoped permissions**: Apply only within specific groups
- **Organization Unit-scoped permissions**: Apply only within specific organization units

## API Endpoints

### Organization Management

#### Organizations

**List Organizations**
```http
GET /api/v1/organizations
Authorization: Bearer token
```

**Get Organization**
```http
GET /api/v1/organizations/{orgId}
Authorization: Bearer token
```

**Create Organization (Atomic Transaction)**
```http
POST /api/v1/organizations
Content-Type: application/json

{
  "organization": {
    "name": "Acme Corporation",
    "contactInfo": {
      "email": "admin@acme.com",
      "phone": "+1-555-0123",
      "address": {
        "street": "123 Main St",
        "city": "Anytown",
        "country": "USA"
      }
    }
  },
  "superAdmin": {
    "email": "admin@acme.com",
    "firstName": "John",
    "lastName": "Doe",
    "phone": "+1-555-0123"
  }
}
```

**Response Format:**
```json
{
  "data": {
    "organization": {
      "id": "org-uuid",
      "name": "Acme Corporation",
      "status": "active",
      "createdAt": "2024-02-21T12:00:00Z"
    },
    "superAdmin": {
      "id": "user-uuid",
      "email": "admin@acme.com",
      "firstName": "John",
      "lastName": "Doe",
      "organizationId": "org-uuid",
      "organizationUnitId": "root-unit-uuid",
      "status": "active"
    },
    "rootOrganizationUnit": {
      "id": "root-unit-uuid",
      "name": "Acme Corporation",
      "organizationId": "org-uuid",
      "hierarchyLevel": 0,
      "path": "root-unit-uuid",
      "status": "active"
    },
    "authentication": {
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expiresIn": 3600,
      "refreshToken": "refresh-token-string"
    }
  },
  "meta": {
    "timestamp": "2024-02-21T12:00:00Z",
    "requestId": "req-uuid",
    "version": "1.1"
  }
}
```

**Update Organization**
```http
PUT /api/v1/organizations/{orgId}
Authorization: Bearer token
Content-Type: application/json

{
  "name": "Acme Corporation Updated",
  "contactInfo": {
    "email": "new-admin@acme.com"
  }
}
```

**Delete Organization**
```http
DELETE /api/v1/organizations/{orgId}
Authorization: Bearer token
```

#### Organization Units

**List Organization Units**
```http
GET /api/v1/organizations/{orgId}/organization-units
Authorization: Bearer token
```

**Get Organization Unit**
```http
GET /api/v1/organizations/{orgId}/organization-units/{unitId}
Authorization: Bearer token
```

**Create Organization Unit**
```http
POST /api/v1/organizations/{orgId}/organization-units
Authorization: Bearer token
Content-Type: application/json

{
  "name": "Engineering Department",
  "description": "Engineering and Development team",
  "parentId": "parent-unit-uuid",
  "ownerId": "user-uuid"
}
```

**Update Organization Unit**
```http
PUT /api/v1/organizations/{orgId}/organization-units/{unitId}
Authorization: Bearer token
Content-Type: application/json

{
  "name": "Engineering & DevOps",
  "description": "Engineering, Development, and DevOps teams"
}
```

**Move Organization Unit**
```http
POST /api/v1/organizations/{orgId}/organization-units/{unitId}/move
Authorization: Bearer token
Content-Type: application/json

{
  "newParentId": "new-parent-unit-uuid"
}
```

**Delete Organization Unit**
```http
DELETE /api/v1/organizations/{orgId}/organization-units/{unitId}
Authorization: Bearer token
```

### User Management

#### Users

**List Users**
```http
GET /api/v1/organizations/{orgId}/users
Authorization: Bearer token
```

**Get User**
```http
GET /api/v1/organizations/{orgId}/users/{userId}
Authorization: Bearer token
```

**Create User (Invite)**
```http
POST /api/v1/organizations/{orgId}/invitations
Authorization: Bearer token
Content-Type: application/json

{
  "email": "newuser@company.com",
  "firstName": "Jane",
  "lastName": "Smith",
  "organizationUnitId": "unit-uuid",
  "roleIds": ["role-uuid-1", "role-uuid-2"]
}
```

**Update User**
```http
PUT /api/v1/organizations/{orgId}/users/{userId}
Authorization: Bearer token
Content-Type: application/json

{
  "firstName": "Jane",
  "lastName": "Smith",
  "phone": "+1-555-0456",
  "profileData": {
    "department": "Engineering",
    "employeeId": "EMP-12345"
  }
}
```

**Move User Between Organization Units**
```http
POST /api/v1/organizations/{orgId}/users/{userId}/move
Authorization: Bearer token
Content-Type: application/json

{
  "newOrganizationUnitId": "new-unit-uuid"
}
```

**Delete User**
```http
DELETE /api/v1/organizations/{orgId}/users/{userId}
Authorization: Bearer token
```

**Search Users**
```http
GET /api/v1/organizations/{orgId}/users/search?q=jane&fields=firstName,lastName,email
Authorization: Bearer token
```

### Role and Permission Management

#### Roles

**List Roles**
```http
GET /api/v1/organizations/{orgId}/roles
Authorization: Bearer token
```

**Get Role**
```http
GET /api/v1/organizations/{orgId}/roles/{roleId}
Authorization: Bearer token
```

**Create Role**
```http
POST /api/v1/organizations/{orgId}/roles
Authorization: Bearer token
Content-Type: application/json

{
  "name": "Project Manager",
  "description": "Manages projects and team members",
  "type": "custom",
  "scopeType": "organization_unit",
  "scopeId": "unit-uuid"
}
```

**Update Role**
```http
PUT /api/v1/organizations/{orgId}/roles/{roleId}
Authorization: Bearer token
Content-Type: application/json

{
  "name": "Senior Project Manager",
  "description": "Manages multiple projects and teams"
}
```

**Delete Role**
```http
DELETE /api/v1/organizations/{orgId}/roles/{roleId}
Authorization: Bearer token
```

#### Permissions

**List Permissions**
```http
GET /api/v1/organizations/{orgId}/permissions
Authorization: Bearer token
```

**Get Permission**
```http
GET /api/v1/permissions/{permissionId}
Authorization: Bearer token
```

**Create Permission**
```http
POST /api/v1/organizations/{orgId}/permissions
Authorization: Bearer token
Content-Type: application/json

{
  "name": "manage_projects",
  "description": "Create, update, and delete projects",
  "type": "custom",
  "category": "project_management"
}
```

**Add Permission to Role**
```http
POST /api/v1/organizations/{orgId}/roles/{roleId}/permissions
Authorization: Bearer token
Content-Type: application/json

{
  "permissionId": "permission-uuid"
}
```

**Remove Permission from Role**
```http
DELETE /api/v1/organizations/{orgId}/roles/{roleId}/permissions/{permissionId}
Authorization: Bearer token
```

#### Role Assignments

**List User Roles**
```http
GET /api/v1/organizations/{orgId}/users/{userId}/roles
Authorization: Bearer token
```

**Assign Role to User**
```http
POST /api/v1/organizations/{orgId}/users/{userId}/roles
Authorization: Bearer token
Content-Type: application/json

{
  "roleId": "role-uuid",
  "expiresAt": "2024-12-31T23:59:59Z"
}
```

**Revoke User Role**
```http
DELETE /api/v1/organizations/{orgId}/users/{userId}/roles/{userRoleId}
Authorization: Bearer token
```

**List Group Roles**
```http
GET /api/v1/organizations/{orgId}/groups/{groupId}/roles
Authorization: Bearer token
```

**Assign Role to Group**
```http
POST /api/v1/organizations/{orgId}/groups/{groupId}/roles
Authorization: Bearer token
Content-Type: application/json

{
  "roleId": "role-uuid"
}
```

**Revoke Group Role**
```http
DELETE /api/v1/organizations/{orgId}/groups/{groupId}/roles/{groupRoleId}
Authorization: Bearer token
```

### Group Management

#### Groups

**List Groups**
```http
GET /api/v1/organizations/{orgId}/groups
Authorization: Bearer token
```

**Get Group**
```http
GET /api/v1/organizations/{orgId}/groups/{groupId}
Authorization: Bearer token
```

**Create Group**
```http
POST /api/v1/organizations/{orgId}/groups
Authorization: Bearer token
Content-Type: application/json

{
  "name": "Developers",
  "description": "Software development team",
  "parentId": "parent-group-uuid",
  "type": "custom"
}
```

**Update Group**
```http
PUT /api/v1/organizations/{orgId}/groups/{groupId}
Authorization: Bearer token
Content-Type: application/json

{
  "name": "Software Developers",
  "description": "Frontend and backend development teams"
}
```

**Move Group**
```http
POST /api/v1/organizations/{orgId}/groups/{groupId}/move
Authorization: Bearer token
Content-Type: application/json

{
  "newParentId": "new-parent-group-uuid"
}
```

**Delete Group**
```http
DELETE /api/v1/organizations/{orgId}/groups/{groupId}
Authorization: Bearer token
```

#### Group Members

**List Group Members**
```http
GET /api/v1/organizations/{orgId}/groups/{groupId}/members
Authorization: Bearer token
```

**Add Member to Group**
```http
POST /api/v1/organizations/{orgId}/groups/{groupId}/members
Authorization: Bearer token
Content-Type: application/json

{
  "userId": "user-uuid",
  "roleInGroup": "manager"
}
```

**Update Member Role in Group**
```http
PUT /api/v1/organizations/{orgId}/groups/{groupId}/members/{memberId}
Authorization: Bearer token
Content-Type: application/json

{
  "roleInGroup": "owner"
}
```

**Remove Member from Group**
```http
DELETE /api/v1/organizations/{orgId}/groups/{groupId}/members/{memberId}
Authorization: Bearer token
```

### Audit and Monitoring

#### Audit Logs

**List Audit Logs**
```http
GET /api/v1/organizations/{orgId}/audit-logs
Authorization: Bearer token
```

**Get Audit Log**
```http
GET /api/v1/organizations/{orgId}/audit-logs/{logId}
Authorization: Bearer token
```

**Export Audit Logs**
```http
GET /api/v1/organizations/{orgId}/audit-logs/export?format=csv&startDate=2024-01-01&endDate=2024-12-31
Authorization: Bearer token
```

#### System Health

**Health Check**
```http
GET /api/v1/health
```

**System Status**
```http
GET /api/v1/status
Authorization: Bearer token
```

## Request and Response Formats

### Request Format

All requests use JSON format with the following structure:

```json
{
  "data": {
    // Request payload
  },
  "meta": {
    // Optional metadata
  }
}
```

### Response Format

All responses follow a consistent structure:

```json
{
  "data": {
    // Response data
  },
  "meta": {
    "timestamp": "2024-02-21T12:00:00Z",
    "requestId": "req-uuid",
    "version": "1.0"
  }
}
```

### Error Response Format

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Validation failed",
    "details": [
      {
        "field": "email",
        "message": "Email is required"
      }
    ]
  },
  "meta": {
    "timestamp": "2024-02-21T12:00:00Z",
    "requestId": "req-uuid"
  }
}
```

### Resource Examples

#### Organization Resource

```json
{
  "id": "org-uuid",
  "name": "Acme Corporation",
  "contactInfo": {
    "email": "admin@acme.com",
    "phone": "+1-555-0123"
  },
  "address": {
    "street": "123 Main St",
    "city": "Anytown",
    "country": "USA"
  },
  "status": "active",
  "createdAt": "2024-02-21T12:00:00Z",
  "updatedAt": "2024-02-21T12:00:00Z"
}
```

#### User Resource

```json
{
  "id": "user-uuid",
  "organizationId": "org-uuid",
  "organizationUnitId": "unit-uuid",
  "firstName": "John",
  "lastName": "Doe",
  "email": "john.doe@acme.com",
  "phone": "+1-555-0123",
  "profileData": {
    "department": "Engineering",
    "employeeId": "EMP-123"
  },
  "status": "active",
  "lastLoginAt": "2024-02-21T12:00:00Z",
  "createdAt": "2024-02-21T12:00:00Z",
  "updatedAt": "2024-02-21T12:00:00Z"
}
```

#### Role Resource

```json
{
  "id": "role-uuid",
  "organizationId": "org-uuid",
  "name": "Project Manager",
  "description": "Manages projects and team members",
  "type": "custom",
  "scopeType": "organization_unit",
  "scopeId": "unit-uuid",
  "status": "active",
  "createdAt": "2024-02-21T12:00:00Z",
  "updatedAt": "2024-02-21T12:00:00Z"
}
```

#### Group Resource

```json
{
  "id": "group-uuid",
  "organizationId": "org-uuid",
  "parentId": "parent-group-uuid",
  "name": "Developers",
  "description": "Software development team",
  "type": "custom",
  "status": "active",
  "createdAt": "2024-02-21T12:00:00Z",
  "updatedAt": "2024-02-21T12:00:00Z"
}
```

## Error Handling

### Error Categories

#### Client Errors (4xx)

- **400 Bad Request**: Invalid request format or parameters
- **401 Unauthorized**: Authentication required or failed
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Resource not found
- **409 Conflict**: Resource conflict (e.g., duplicate name)
- **422 Unprocessable Entity**: Validation errors
- **429 Too Many Requests**: Rate limit exceeded

#### Server Errors (5xx)

- **500 Internal Server Error**: Server error
- **502 Bad Gateway**: Upstream server error
- **503 Service Unavailable**: Service temporarily unavailable
- **504 Gateway Timeout**: Upstream server timeout

### Error Response Structure

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": [
      {
        "field": "fieldName",
        "message": "Field-specific error message",
        "value": "invalidValue"
      }
    ],
    "traceId": "trace-uuid"
  },
  "meta": {
    "timestamp": "2024-02-21T12:00:00Z",
    "requestId": "req-uuid"
  }
}
```

### Common Error Codes

- **VALIDATION_ERROR**: Request validation failed
- **AUTHENTICATION_ERROR**: Authentication failed
- **AUTHORIZATION_ERROR**: Insufficient permissions
- **NOT_FOUND**: Resource not found
- **CONFLICT**: Resource conflict
- **RATE_LIMIT_EXCEEDED**: Rate limit exceeded
- **INTERNAL_ERROR**: Internal server error
- **SERVICE_UNAVAILABLE**: Service temporarily unavailable

## Rate Limiting and Throttling

### Rate Limit Strategy

- **Authentication**: 60 requests per minute per IP
- **Organization Management**: 100 requests per minute per organization
- **User Management**: 200 requests per minute per organization
- **Role and Permission Management**: 150 requests per minute per organization
- **Group Management**: 150 requests per minute per organization

### Rate Limit Headers

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1645123456
X-RateLimit-Window: 60
```

### Rate Limit Response

When rate limit is exceeded:

```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1645123456
X-RateLimit-Window: 60
Retry-After: 60

{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Please try again later.",
    "details": [
      {
        "field": "rateLimit",
        "message": "Maximum 100 requests per 60 seconds"
      }
    ]
  }
}
```

## API Versioning

### Versioning Strategy

API versioning is implemented through URL path versioning:

```
https://api.direct.example.com/v1/
https://api.direct.example.com/v2/
```

### Version Support Policy

- **Current Version**: v1 (active development)
- **Deprecated Versions**: Will be announced 6 months in advance
- **Version Lifecycle**: Minimum 12 months support for each version

### Version-Specific Features

Each version maintains backward compatibility within the same major version:

- **v1.0**: Initial release
- **v1.1**: Added scoped roles and permissions
- **v1.2**: Enhanced audit logging and performance optimizations

## API Documentation

### OpenAPI Specification

The API is documented using OpenAPI 3.0 specification:

- **Swagger UI**: Available at `/docs`
- **OpenAPI JSON**: Available at `/api-docs/openapi.json`
- **Interactive Documentation**: `/docs/swagger`

### SDK Generation

SDKs are automatically generated for multiple programming languages:

- **JavaScript/TypeScript**: `@direct/api-client`
- **Python**: `direct-api-client`
- **Java**: `com.direct:api-client`
- **C#**: `Direct.Api.Client`
- **Go**: `github.com/direct/api-client-go`

### Example Usage

#### JavaScript/TypeScript

```javascript
import { DirectApiClient } from '@direct/api-client';

const client = new DirectApiClient({
  baseURL: 'https://api.direct.example.com/v1',
  token: 'your-jwt-token'
});

// List organizations
const organizations = await client.organizations.list();

// Create user
const user = await client.users.create('org-uuid', {
  email: 'user@example.com',
  firstName: 'John',
  lastName: 'Doe'
});

// Assign role to user
await client.userRoles.assign('org-uuid', 'user-uuid', {
  roleId: 'role-uuid'
});
```

#### Python

```python
from direct_api_client import DirectApiClient

client = DirectApiClient(
    base_url='https://api.direct.example.com/v1',
    token='your-jwt-token'
)

# List organizations
organizations = client.organizations.list()

# Create user
user = client.users.create('org-uuid', {
    'email': 'user@example.com',
    'firstName': 'John',
    'lastName': 'Doe'
})

# Assign role to user
client.user_roles.assign('org-uuid', 'user-uuid', {
    'roleId': 'role-uuid'
})
```

This comprehensive API structure provides a robust foundation for building applications that integrate with the Direct Organization Management System, supporting all core functionality with proper authentication, authorization, and error handling.