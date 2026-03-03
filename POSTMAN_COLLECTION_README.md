# Direct Organization Management System - Postman Collection

This document provides instructions on how to use the Postman collection for testing the Direct Organization Management System API.

## Importing the Collection

1. **Download the collection file**: `Direct-Organization-Management.postman_collection.json`
2. **Open Postman** and click on the **Import** button
3. **Select the JSON file** and click **Import**
4. The collection will be available in your Postman workspace

## Collection Structure

The collection is organized into the following folders:

### 1. Health Check
- **Server Health Status**: Basic health check endpoint to verify the API is running

### 2. Scoped Role Management
- **Assign Scoped Role**: Assign a role to a user within a specific scope (organization, group, or organization unit)
- **Revoke Scoped Role**: Revoke a role assignment from a user
- **Get User Scoped Roles**: Retrieve all roles assigned to a user within a specific scope

### 3. Permission Management
- **Check Permission**: Verify if a user has a specific permission within a scope
- **Get User Permissions in Scope**: Retrieve all permissions a user has within a specific scope

### 4. Group Hierarchy
- **Get User Roles with Hierarchy**: Get user roles including inherited roles from parent groups
- **Validate Group Operation**: Validate if a user can perform an operation on a group

### 5. Organization Unit Operations
- **Validate Cross-OU Operation**: Validate if a user can perform operations across different organization units

## Environment Variables

The collection includes the following environment variables:

- **baseUrl**: `http://localhost:3000` (default - change if running on different port)
- **userId**: `user-uuid` (sample user ID)
- **scopeType**: `organization_unit` (default scope type)
- **scopeId**: `ou-engineering-uuid` (sample scope ID)

### Setting Up Environment Variables

1. In Postman, click on the **Environment** dropdown
2. Create a new environment or select an existing one
3. Add the variables listed above with appropriate values
4. Save the environment

## Example API Calls

### Assigning a Role to a User

```http
POST /api/scoped-roles/assign
Content-Type: application/json

{
  "userId": "user-uuid",
  "roleId": "role-ou-manager-uuid",
  "assignedBy": "user-admin-uuid",
  "scopeType": "organization_unit",
  "scopeId": "ou-engineering-uuid",
  "expiresAt": "2024-12-31T23:59:59.999Z",
  "reason": "Project lead assignment"
}
```

### Checking User Permissions

```http
POST /api/permissions/check
Content-Type: application/json

{
  "userId": "user-uuid",
  "permissionName": "view_user_details",
  "context": {
    "userId": "user-uuid",
    "scopeType": "group",
    "scopeId": "group-project-alpha-uuid",
    "targetUserId": "target-user-uuid",
    "action": "view"
  }
}
```

### Getting User Roles in a Scope

```http
GET /api/scoped-roles/user/user-uuid?scopeType=organization_unit&scopeId=ou-engineering-uuid
```

## Response Examples

### Success Response
```json
{
  "success": true,
  "data": {
    "id": "user-role-uuid",
    "userId": "user-uuid",
    "roleId": "role-ou-manager-uuid",
    "assignedBy": "user-admin-uuid",
    "assignedAt": "2024-01-01T00:00:00.000Z",
    "status": "active",
    "createdAt": "2024-01-01T00:00:00.000Z",
    "updatedAt": "2024-01-01T00:00:00.000Z",
    "name": "OU Manager",
    "scopeType": "organization_unit",
    "scopeId": "ou-engineering-uuid"
  }
}
```

### Error Response
```json
{
  "success": false,
  "error": "User user-admin-uuid does not have permission to assign roles in scope ou-engineering-uuid"
}
```

## Testing Tips

1. **Start the API Server**: Make sure the API server is running using `./start.sh`
2. **Check Health**: Always test the health endpoint first to ensure the server is running
3. **Use Environment Variables**: Leverage the environment variables to easily switch between different test scenarios
4. **Test Error Cases**: Try invalid requests to see how the API handles errors
5. **Monitor Logs**: Check the server logs for detailed information about API calls

## Common Test Scenarios

### Scenario 1: Role Assignment and Permission Checking
1. Assign a role to a user in a specific scope
2. Check if the user has the expected permissions
3. Verify the role appears in the user's role list

### Scenario 2: Cross-OU Operations
1. Try to perform operations across different organization units
2. Verify that only admin users can perform cross-OU operations
3. Test the validation responses

### Scenario 3: Group Hierarchy
1. Create a group hierarchy (parent-child relationships)
2. Assign roles to parent groups
3. Verify that child group members inherit the roles

## Troubleshooting

### Server Not Running
- Ensure the API server is started with `./start.sh`
- Check that port 3000 is not in use by another application
- Verify the database connection (if using real database)

### Authentication Issues
- The current implementation uses mock data without authentication
- In a production environment, you would need to add authentication headers

### Invalid Responses
- Check the request format against the examples
- Verify that the environment variables are set correctly
- Ensure the scope types and IDs are valid

## Next Steps

1. **Import the collection** into Postman
2. **Set up environment variables** with your test data
3. **Run the health check** to verify the API is working
4. **Test each endpoint** with different scenarios
5. **Create additional test cases** based on your specific requirements

## Support

For questions about the API or Postman collection:
- Check the server logs for detailed error information
- Review the API documentation in the code comments
- Test with simple requests first before moving to complex scenarios