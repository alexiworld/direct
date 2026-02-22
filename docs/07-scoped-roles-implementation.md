# Scoped Roles Implementation - Detailed Design

**Document Version**: 1.0  
**Created**: February 2026  
**Last Updated**: February 2026  
**Status**: Draft

## Table of Contents

1. [Scoped Roles Overview](#scoped-roles-overview)
2. [The `groupId:roleId` Pattern](#the-groupidroleid-pattern)
3. [Role Assignment with Context](#role-assignment-with-context)
4. [Permission Evaluation with Scopes](#permission-evaluation-with-scopes)
5. [Database Schema for Scoped Roles](#database-schema-for-scoped-roles)
6. [API Implementation](#api-implementation)
7. [Use Cases and Examples](#use-cases-and-examples)

## Scoped Roles Overview

Scoped roles provide context-aware permissions that are limited to specific organizational boundaries. The system supports three types of scoped roles:

1. **Organization-Level**: Applies to the entire organization
2. **Group-Scoped**: Limited to specific groups (`groupId:roleId` pattern)
3. **Organization Unit-Scoped**: Limited to specific organization units

## The `groupId:roleId` Pattern

### Concept Explanation

The `groupId:roleId` pattern represents a role that has specific permissions but is scoped to operate only within the context of a particular group. This is different from assigning a role to a group - instead, it's about limiting the scope of a role's permissions.

### Example Scenario

Consider a "View User Details" permission that should only work within specific groups:

```typescript
// Traditional approach (not scoped)
const viewUserDetailsRole = {
  id: 'role-view-user-details',
  name: 'View User Details',
  permissions: ['view_user_details'],
  scopeType: 'organization' // Works everywhere
};

// Scoped approach (group-scoped)
const groupScopedRole = {
  id: 'role-group-view-user-details',
  name: 'Group View User Details',
  permissions: ['view_user_details'],
  scopeType: 'group',
  scopeId: 'group-developers-uuid' // Only works within developers group
};
```

### Key Differences

| Aspect | Traditional Role | Scoped Role |
|--------|------------------|-------------|
| **Permission Scope** | Organization-wide | Group-specific |
| **Assignment Target** | User directly | User with context |
| **Permission Evaluation** | Always applies | Only within scope |
| **Management** | Admin only | Group managers can assign |

## Role Assignment with Context

### Enhanced Role Assignment Service

```typescript
@Injectable()
export class ScopedRoleAssignmentService {
  constructor(
    private readonly roleRepository: RoleRepository,
    private readonly userRoleRepository: UserRoleRepository,
    private readonly groupService: GroupService,
    private readonly auditService: AuditService
  ) {}

  /**
   * Assign a scoped role to a user with specific context
   * 
   * @param command Assignment command with context
   */
  async assignScopedRole(command: AssignScopedRoleCommand): Promise<UserRoleDto> {
    // 1. Validate the role exists and is scoped
    const role = await this.validateScopedRole(command.roleId, command.scopeType);
    
    // 2. Validate the assigner has authority over the scope
    await this.validateAssignerAuthority(command.assignedBy, role, command);
    
    // 3. Validate the user belongs to the scope
    await this.validateUserInScope(command.userId, role, command);
    
    // 4. Create the scoped role assignment
    const userRole = await this.createUserRoleAssignment(command, role);
    
    // 5. Log the assignment
    await this.auditService.logScopedRoleAssignment(userRole);
    
    return this.mapToDto(userRole);
  }
  
  private async validateScopedRole(roleId: UUID, expectedScopeType: ScopeType): Promise<Role> {
    const role = await this.roleRepository.findById(roleId);
    
    if (!role) {
      throw new ValidationError(`Role with ID ${roleId} not found`);
    }
    
    if (role.scopeType !== expectedScopeType) {
      throw new ValidationError(
        `Role ${roleId} has scope type ${role.scopeType}, expected ${expectedScopeType}`
      );
    }
    
    if (expectedScopeType === ScopeType.GROUP && !role.scopeId) {
      throw new ValidationError(`Group-scoped role must have a scopeId`);
    }
    
    return role;
  }
  
  private async validateAssignerAuthority(
    assignerId: UUID, 
    role: Role, 
    command: AssignScopedRoleCommand
  ): Promise<void> {
    // Get the assigner's roles within the scope
    const assignerRoles = await this.getUserRolesInScope(assignerId, role);
    
    // Check if assigner has role assignment permissions
    const hasAssignmentPermission = assignerRoles.some(userRole => 
      this.hasPermission(userRole.roleId, 'assign_roles_to_users')
    );
    
    if (!hasAssignmentPermission) {
      throw new AuthorizationError(
        `User ${assignerId} does not have permission to assign roles in scope ${role.scopeId}`
      );
    }
    
    // For group-scoped roles, check if assigner is group owner/manager
    if (role.scopeType === ScopeType.GROUP) {
      const groupMembership = await this.groupService.getGroupMembership(
        assignerId, 
        role.scopeId
      );
      
      if (!groupMembership || 
          groupMembership.roleInGroup !== 'owner' && 
          groupMembership.roleInGroup !== 'manager') {
        throw new AuthorizationError(
          `User ${assignerId} must be group owner or manager to assign group-scoped roles`
        );
      }
    }
  }
  
  private async validateUserInScope(
    userId: UUID, 
    role: Role, 
    command: AssignScopedRoleCommand
  ): Promise<void> {
    switch (role.scopeType) {
      case ScopeType.GROUP:
        await this.validateUserInGroup(userId, role.scopeId);
        break;
        
      case ScopeType.ORGANIZATION_UNIT:
        await this.validateUserInOrganizationUnit(userId, role.scopeId);
        break;
        
      case ScopeType.ORGANIZATION:
        // No additional validation needed
        break;
        
      default:
        throw new ValidationError(`Unknown scope type: ${role.scopeType}`);
    }
  }
  
  private async validateUserInGroup(userId: UUID, groupId: UUID): Promise<void> {
    const userGroups = await this.groupService.getUserGroups(userId);
    const isInGroup = userGroups.some(g => g.id === groupId);
    
    if (!isInGroup) {
      throw new ValidationError(
        `User ${userId} is not a member of group ${groupId}`
      );
    }
  }
  
  private async validateUserInOrganizationUnit(userId: UUID, unitId: UUID): Promise<void> {
    const user = await this.userRepository.findById(userId);
    
    if (user.organizationUnitId !== unitId) {
      throw new ValidationError(
        `User ${userId} does not belong to organization unit ${unitId}`
      );
    }
  }
  
  private async createUserRoleAssignment(
    command: AssignScopedRoleCommand, 
    role: Role
  ): Promise<UserRole> {
    const userRole = new UserRole({
      userId: command.userId,
      roleId: command.roleId,
      assignedBy: command.assignedBy,
      assignedAt: new Date(),
      expiresAt: command.expiresAt,
      status: 'active',
      // Store the scope context for permission evaluation
      scopeContext: {
        scopeType: role.scopeType,
        scopeId: role.scopeId,
        assignedAt: new Date()
      }
    });
    
    return await this.userRoleRepository.save(userRole);
  }
}

interface AssignScopedRoleCommand {
  userId: UUID;
  roleId: UUID;
  assignedBy: UUID;
  scopeType: ScopeType;
  expiresAt?: Date;
  reason?: string;
}
```

### API Endpoint for Scoped Role Assignment

```typescript
@Controller('organizations/:orgId/users/:userId/roles')
export class ScopedRoleController {
  constructor(
    private readonly scopedRoleService: ScopedRoleAssignmentService
  ) {}

  @Post('scoped')
  @UseGuards(AuthGuard)
  @HasPermission('assign_roles_to_users')
  async assignScopedRole(
    @Param('orgId') orgId: string,
    @Param('userId') userId: string,
    @Body() assignCommand: AssignScopedRoleDto,
    @Request() req
  ): Promise<UserRoleDto> {
    // Validate organization isolation
    const user = await this.userService.getUser(userId);
    if (user.organizationId !== orgId) {
      throw new BadRequestException('User does not belong to the specified organization');
    }
    
    const command: AssignScopedRoleCommand = {
      userId: userId,
      roleId: assignCommand.roleId,
      assignedBy: req.user.id,
      scopeType: assignCommand.scopeType,
      expiresAt: assignCommand.expiresAt,
      reason: assignCommand.reason
    };
    
    return await this.scopedRoleService.assignScopedRole(command);
  }
}

interface AssignScopedRoleDto {
  roleId: UUID;
  scopeType: ScopeType;
  expiresAt?: Date;
  reason?: string;
}
```

## Permission Evaluation with Scopes

### Enhanced Permission Service

```typescript
@Injectable()
export class ScopedPermissionService {
  constructor(
    private readonly userRoleRepository: UserRoleRepository,
    private readonly roleRepository: RoleRepository,
    private readonly groupService: GroupService
  ) {}

  /**
   * Evaluate if a user has a specific permission within a given context
   */
  async hasPermission(
    userId: UUID, 
    permissionName: string, 
    context?: PermissionContext
  ): Promise<boolean> {
    const userRoles = await this.getUserRoles(userId);
    
    for (const userRole of userRoles) {
      const role = await this.roleRepository.findById(userRole.roleId);
      
      // Check if role has the requested permission
      const hasPermission = this.checkRolePermission(role, permissionName);
      
      if (hasPermission) {
        // Validate scope context
        const scopeValid = await this.validatePermissionScope(role, context);
        
        if (scopeValid) {
          return true;
        }
      }
    }
    
    return false;
  }
  
  /**
   * Get all permissions a user has within a specific scope
   */
  async getUserPermissionsInScope(
    userId: UUID, 
    scopeType: ScopeType, 
    scopeId: UUID
  ): Promise<string[]> {
    const userRoles = await this.getUserRoles(userId);
    const permissions: Set<string> = new Set();
    
    for (const userRole of userRoles) {
      const role = await this.roleRepository.findById(userRole.roleId);
      
      // Check if role applies to this scope
      if (this.roleAppliesToScope(role, scopeType, scopeId)) {
        const rolePermissions = await this.getRolePermissions(role.id);
        rolePermissions.forEach(p => permissions.add(p.name));
      }
    }
    
    return Array.from(permissions);
  }
  
  private async validatePermissionScope(
    role: Role, 
    context?: PermissionContext
  ): Promise<boolean> {
    // If role is organization-level, no scope validation needed
    if (role.scopeType === ScopeType.ORGANIZATION) {
      return true;
    }
    
    // If no context provided, scoped permissions cannot be evaluated
    if (!context) {
      return false;
    }
    
    // Validate scope matches
    if (role.scopeType !== context.scopeType || role.scopeId !== context.scopeId) {
      return false;
    }
    
    // Additional context-specific validation
    return await this.validateContextSpecificRules(role, context);
  }
  
  private async validateContextSpecificRules(
    role: Role, 
    context: PermissionContext
  ): Promise<boolean> {
    switch (role.scopeType) {
      case ScopeType.GROUP:
        return this.validateGroupContext(role, context);
        
      case ScopeType.ORGANIZATION_UNIT:
        return this.validateOrganizationUnitContext(role, context);
        
      default:
        return false;
    }
  }
  
  private async validateGroupContext(role: Role, context: PermissionContext): Promise<boolean> {
    // Check if user is still in the group
    const userGroups = await this.groupService.getUserGroups(context.userId);
    const isInGroup = userGroups.some(g => g.id === role.scopeId);
    
    if (!isInGroup) {
      return false;
    }
    
    // Additional group-specific validation could go here
    // For example, checking if the target resource belongs to the group
    
    return true;
  }
  
  private async validateOrganizationUnitContext(
    role: Role, 
    context: PermissionContext
  ): Promise<boolean> {
    // Check if user still belongs to the organization unit
    const user = await this.userRepository.findById(context.userId);
    
    if (user.organizationUnitId !== role.scopeId) {
      return false;
    }
    
    // Additional organization unit-specific validation could go here
    
    return true;
  }
  
  private roleAppliesToScope(role: Role, scopeType: ScopeType, scopeId: UUID): boolean {
    // Organization-level roles apply everywhere
    if (role.scopeType === ScopeType.ORGANIZATION) {
      return true;
    }
    
    // Scoped roles only apply to their specific scope
    return role.scopeType === scopeType && role.scopeId === scopeId;
  }
}

interface PermissionContext {
  userId: UUID;
  scopeType: ScopeType;
  scopeId: UUID;
  targetResourceId?: UUID;
  action: string;
}
```

## Database Schema for Scoped Roles

### Enhanced User Role Table

```sql
-- Enhanced user_roles table to support scoped roles
ALTER TABLE user_roles ADD COLUMN scope_context JSONB;

-- Add constraint to ensure scope context is present for scoped roles
ALTER TABLE user_roles ADD CONSTRAINT chk_scope_context_consistency CHECK (
    (scope_context IS NOT NULL AND (
        SELECT scope_type FROM roles WHERE id = role_id
    ) != 'organization') OR
    (scope_context IS NULL AND (
        SELECT scope_type FROM roles WHERE id = role_id
    ) = 'organization')
);

-- Create index for scoped role queries
CREATE INDEX idx_user_roles_scoped ON user_roles(user_id, role_id) 
WHERE scope_context IS NOT NULL;

-- Create function to get user permissions with scope validation
CREATE OR REPLACE FUNCTION get_user_permissions_with_scope(
    p_user_id UUID,
    p_scope_type VARCHAR(50),
    p_scope_id UUID
) RETURNS TABLE(permission_name VARCHAR) AS $$
BEGIN
    RETURN QUERY
    SELECT DISTINCT p.name
    FROM user_roles ur
    JOIN roles r ON ur.role_id = r.id
    JOIN role_permissions rp ON r.id = rp.role_id
    JOIN permissions p ON rp.permission_id = p.id
    WHERE ur.user_id = p_user_id
    AND ur.status = 'active'
    AND rp.status = 'active'
    AND p.status = 'active'
    AND (
        r.scope_type = 'organization' OR
        (r.scope_type = p_scope_type AND r.scope_id = p_scope_id)
    );
END;
$$ LANGUAGE plpgsql;
```

### Scoped Role Assignment History

```sql
-- Table to track scoped role assignment history
CREATE TABLE scoped_role_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_role_id UUID NOT NULL REFERENCES user_roles(id) ON DELETE CASCADE,
    scope_type VARCHAR(50) NOT NULL,
    scope_id UUID NOT NULL,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    assigned_by UUID NOT NULL REFERENCES users(id),
    reason TEXT,
    
    -- Constraints
    CONSTRAINT uk_user_role_scope UNIQUE (user_role_id, scope_type, scope_id)
);

-- Index for scoped role queries
CREATE INDEX idx_scoped_role_assignments_user_scope 
ON scoped_role_assignments(user_role_id, scope_type, scope_id);
```

## API Implementation

### Scoped Role Assignment API

```typescript
// POST /api/v1/organizations/{orgId}/users/{userId}/roles/scoped
{
  "roleId": "role-view-user-details-uuid",
  "scopeType": "group",
  "scopeId": "group-developers-uuid",
  "expiresAt": "2024-12-31T23:59:59Z",
  "reason": "Project lead needs to view team member details"
}

// Response
{
  "id": "user-role-assignment-uuid",
  "userId": "user-uuid",
  "roleId": "role-view-user-details-uuid",
  "assignedBy": "assigner-uuid",
  "assignedAt": "2024-02-21T12:00:00Z",
  "expiresAt": "2024-12-31T23:59:59Z",
  "status": "active",
  "scopeContext": {
    "scopeType": "group",
    "scopeId": "group-developers-uuid",
    "assignedAt": "2024-02-21T12:00:00Z"
  }
}
```

### Permission Check API

```typescript
// GET /api/v1/organizations/{orgId}/users/{userId}/permissions?scopeType=group&scopeId=group-developers-uuid
{
  "userId": "user-uuid",
  "organizationId": "org-uuid",
  "scopeType": "group",
  "scopeId": "group-developers-uuid",
  "permissions": [
    "view_user_details",
    "edit_user_details",
    "manage_group_members"
  ],
  "effectiveAt": "2024-02-21T12:00:00Z",
  "expiresAt": "2024-12-31T23:59:59Z"
}

// POST /api/v1/organizations/{orgId}/permissions/check
{
  "userId": "user-uuid",
  "permission": "view_user_details",
  "context": {
    "scopeType": "group",
    "scopeId": "group-developers-uuid",
    "targetUserId": "target-user-uuid",
    "action": "view"
  }
}

// Response
{
  "hasPermission": true,
  "scopeValid": true,
  "effectiveRole": "role-view-user-details-uuid",
  "expiresAt": "2024-12-31T23:59:59Z"
}
```

## Use Cases and Examples

### Use Case 1: Group Project Manager

**Scenario**: A group project manager needs to view and edit user details, but only for members of their specific project group.

```typescript
// Create group-scoped role
const projectManagerRole = {
  id: 'role-project-manager',
  name: 'Project Manager',
  description: 'Can manage project team members',
  scopeType: 'group',
  scopeId: 'group-project-alpha-uuid',
  permissions: [
    'view_user_details',
    'edit_user_details',
    'manage_group_members'
  ]
};

// Assign to user
const assignment = {
  userId: 'user-john-doe-uuid',
  roleId: 'role-project-manager',
  scopeType: 'group',
  scopeId: 'group-project-alpha-uuid',
  reason: 'Assigned as project lead for Alpha project'
};

// Permission evaluation
const hasPermission = await permissionService.hasPermission(
  'user-john-doe-uuid',
  'view_user_details',
  {
    scopeType: 'group',
    scopeId: 'group-project-alpha-uuid',
    targetUserId: 'user-team-member-uuid',
    action: 'view'
  }
);
// Returns: true (if target user is in the same group)

const hasPermissionOutsideScope = await permissionService.hasPermission(
  'user-john-doe-uuid',
  'view_user_details',
  {
    scopeType: 'group',
    scopeId: 'group-project-beta-uuid', // Different group
    targetUserId: 'user-beta-member-uuid',
    action: 'view'
  }
);
// Returns: false (different scope)
```

### Use Case 2: Department-Specific HR Manager

**Scenario**: An HR manager has permissions to view employee details, but only within their specific department (organization unit).

```typescript
// Create organization unit-scoped role
const hrManagerRole = {
  id: 'role-hr-manager',
  name: 'HR Manager',
  description: 'Can manage HR operations in department',
  scopeType: 'organization_unit',
  scopeId: 'ou-engineering-uuid',
  permissions: [
    'view_user_details',
    'edit_user_details',
    'view_user_salary',
    'manage_user_contracts'
  ]
};

// Assign to user in engineering department
const hrAssignment = {
  userId: 'user-hr-specialist-uuid',
  roleId: 'role-hr-manager',
  scopeType: 'organization_unit',
  scopeId: 'ou-engineering-uuid',
  reason: 'HR specialist for engineering department'
};

// Permission evaluation
const canViewEngineeringUser = await permissionService.hasPermission(
  'user-hr-specialist-uuid',
  'view_user_details',
  {
    scopeType: 'organization_unit',
    scopeId: 'ou-engineering-uuid',
    targetUserId: 'user-engineer-uuid',
    action: 'view'
  }
);
// Returns: true (same department)

const cannotViewSalesUser = await permissionService.hasPermission(
  'user-hr-specialist-uuid',
  'view_user_details',
  {
    scopeType: 'organization_unit',
    scopeId: 'ou-sales-uuid', // Different department
    targetUserId: 'user-sales-uuid',
    action: 'view'
  }
);
// Returns: false (different department)
```

### Use Case 3: Cross-Group Collaboration

**Scenario**: A user has different roles in different groups, each with different permission scopes.

```typescript
// User has multiple scoped roles
const userRoles = [
  {
    roleId: 'role-project-manager',
    scopeType: 'group',
    scopeId: 'group-project-alpha-uuid',
    permissions: ['view_user_details', 'edit_user_details']
  },
  {
    roleId: 'role-team-leader',
    scopeType: 'group',
    scopeId: 'group-team-frontend-uuid',
    permissions: ['view_user_details', 'manage_group_members']
  },
  {
    roleId: 'role-organization-member',
    scopeType: 'organization',
    permissions: ['view_organization_details']
  }
];

// Permission evaluation depends on context
const canViewAlphaMember = await permissionService.hasPermission(
  'user-multitasker-uuid',
  'view_user_details',
  {
    scopeType: 'group',
    scopeId: 'group-project-alpha-uuid',
    targetUserId: 'user-alpha-member-uuid',
    action: 'view'
  }
);
// Returns: true (has project manager role in alpha group)

const canViewFrontendMember = await permissionService.hasPermission(
  'user-multitasker-uuid',
  'view_user_details',
  {
    scopeType: 'group',
    scopeId: 'group-team-frontend-uuid',
    targetUserId: 'user-frontend-member-uuid',
    action: 'view'
  }
);
// Returns: true (has team leader role in frontend group)

const canViewBetaMember = await permissionService.hasPermission(
  'user-multitasker-uuid',
  'view_user_details',
  {
    scopeType: 'group',
    scopeId: 'group-project-beta-uuid', // No role in this group
    targetUserId: 'user-beta-member-uuid',
    action: 'view'
  }
);
// Returns: false (no role in beta group)
```

