# Scoped Roles Implementation - Comprehensive Design

**Document Version**: 1.0  
**Created**: February 2026  
**Last Updated**: February 2026  
**Status**: Draft

## Table of Contents

1. [Scoped Roles Overview](#scoped-roles-overview)
2. [Role Types and Scopes](#role-types-and-scopes)
3. [Scoped Role Patterns](#scoped-role-patterns)
4. [Role Assignment with Context](#role-assignment-with-context)
5. [Permission Evaluation with Scopes](#permission-evaluation-with-scopes)
6. [Group Scoped Roles](#group-scoped-roles)
7. [Organization Unit Scoped Roles](#organization-unit-scoped-roles)
8. [Database Schema for Scoped Roles](#database-schema-for-scoped-roles)
9. [API Implementation](#api-implementation)
10. [Use Cases and Examples](#use-cases-and-examples)
11. [Security and Validation](#security-and-validation)

## Scoped Roles Overview

Scoped roles provide context-aware permissions that are limited to specific organizational boundaries. The system supports three types of scoped roles:

1. **Organization-Level**: Applies to the entire organization (unscoped)
2. **Group-Scoped**: Limited to specific groups
3. **Organization Unit-Scoped**: Limited to specific organization units

### Key Concepts

- **Scope**: The boundary within which a role's permissions are valid
- **Context**: The specific organizational context for permission evaluation
- **Assignment**: The process of granting a role to a user with scope validation
- **Evaluation**: The process of checking if a user has permissions within a specific scope

## Role Types and Scopes

### Scope Types

```typescript
enum ScopeType {
  ORGANIZATION = 'organization',     // Organization-wide (unscoped)
  GROUP = 'group',                   // Group-specific
  ORGANIZATION_UNIT = 'organization_unit' // OU-specific
}
```

### Role Hierarchy

```typescript
enum SystemRole {
  SUPER_ADMIN = 'SUPER_ADMIN',       // All permissions, all scopes
  ADMIN = 'ADMIN',                   // Organization-wide admin
  OU_OWNER = 'OU_OWNER',             // Organization unit owner
  OU_MANAGER = 'OU_MANAGER',         // Organization unit manager
  OU_MEMBER = 'OU_MEMBER',           // Organization unit member
  GROUP_OWNER = 'GROUP_OWNER',       // Group owner
  GROUP_MANAGER = 'GROUP_MANAGER',   // Group manager
  GROUP_MEMBER = 'GROUP_MEMBER'      // Group member
}
```

### Role Structure

```typescript
interface Role {
  id: UUID;
  organizationId: UUID;
  name: string;
  description: string;
  type: 'system' | 'custom';
  scopeType: ScopeType;
  scopeId: UUID | null; // null for organization-level roles
  permissions: Permission[];
  status: 'active' | 'inactive';
  createdAt: Date;
  updatedAt: Date;
}
```

## Scoped Role Patterns

### Group-Scoped Roles Pattern

The group-scoped role pattern represents a role that has specific permissions but is scoped to operate only within the context of a particular group. This is different from assigning a role to a group - instead, it's about limiting the scope of a role's permissions.

#### Example Scenario

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

### Organization Unit-Scoped Roles Pattern

The organization unit-scoped role pattern represents a role that has specific permissions but is scoped to operate only within the context of a particular organization unit. This ensures that users can only perform actions within their designated organizational boundaries.

#### Example Scenario

Consider an HR manager role that should only work within a specific department:

```typescript
// Organization unit-scoped role
const hrManagerRole = {
  id: 'role-hr-manager',
  name: 'HR Manager',
  permissions: ['view_user_details', 'edit_user_details', 'manage_user_contracts'],
  scopeType: 'organization_unit',
  scopeId: 'ou-engineering-uuid' // Only works within engineering department
};
```

### Key Differences Between Role Types

| Aspect | Traditional Role | Group-Scoped Role | OU-Scoped Role |
|--------|------------------|-------------------|----------------|
| **Permission Scope** | Organization-wide | Group-specific | OU-specific |
| **Assignment Target** | User directly | User with group context | User with OU context |
| **Permission Evaluation** | Always applies | Only within group | Only within OU |
| **Management** | Admin only | Group owners/managers | OU owners/managers |
| **Access Control** | Organization boundaries | Group boundaries | Department boundaries |

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
    
    if (expectedScopeType === ScopeType.ORGANIZATION_UNIT && !role.scopeId) {
      throw new ValidationError(`Organization unit-scoped role must have a scopeId`);
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
    
    // For organization unit-scoped roles, check if assigner is OU owner/manager
    if (role.scopeType === ScopeType.ORGANIZATION_UNIT) {
      const ouAccess = await this.validateUserOUAccess(assignerId, role.scopeId);
      
      if (!ouAccess.hasAccess || 
          ouAccess.accessType !== 'owner' && 
          ouAccess.accessType !== 'manager') {
        throw new AuthorizationError(
          `User ${assignerId} must be OU owner or manager to assign OU-scoped roles`
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

## Group Scoped Roles

### Group Context Validation

```typescript
class GroupContextValidator {
  async validateGroupScopedOperation(
    userId: UUID,
    groupId: UUID,
    operation: string
  ): Promise<ValidationResult> {
    const user = await this.getUser(userId);
    
    // Check if user has admin privileges (can bypass group restrictions)
    if (await this.hasAdminPrivileges(user)) {
      return { isValid: true, reason: 'Admin override' };
    }
    
    // Check ownership/management of group
    const groupAccess = await this.validateUserGroupAccess(user, groupId);
    if (!groupAccess.hasAccess) {
      return { 
        isValid: false, 
        reason: `No access to group: ${groupId}` 
      };
    }
    
    // Check specific permission for the operation
    return await this.validateGroupOperationPermission(user, groupId, operation);
  }
  
  private async validateUserGroupAccess(
    user: User, 
    groupId: UUID
  ): Promise<GroupAccessValidation> {
    // Check if user is owner of the group
    if (user.id === await this.getGroupOwnerId(groupId)) {
      return { hasAccess: true, accessType: 'owner' };
    }
    
    // Check if user is manager of the group
    if (await this.isUserManager(user.id, groupId)) {
      return { hasAccess: true, accessType: 'manager' };
    }
    
    // Check if user is member of the group
    const userGroups = await this.groupService.getUserGroups(user.id);
    const isInGroup = userGroups.some(g => g.id === groupId);
    
    if (isInGroup) {
      return { hasAccess: true, accessType: 'member' };
    }
    
    return { hasAccess: false, accessType: 'none' };
  }
  
  private async validateGroupOperationPermission(
    user: User,
    groupId: UUID,
    operation: string
  ): Promise<ValidationResult> {
    // Check if user has the required permission for this operation
    const hasPermission = await this.permissionService.hasPermission(
      user.id, 
      operation, 
      {
        scopeType: 'group',
        scopeId: groupId,
        userId: user.id
      }
    );
    
    if (!hasPermission) {
      return { 
        isValid: false, 
        reason: `User does not have permission for operation: ${operation}` 
      };
    }
    
    return { isValid: true, reason: 'Valid group-scoped permission' };
  }
}
```

### Group Role Management

```typescript
class GroupRoleManager {
  async createGroupScopedRole(
    groupId: UUID,
    roleDefinition: CreateGroupRoleDto,
    createdBy: UUID
  ): Promise<RoleDto> {
    // Validate group exists and creator has authority
    const group = await this.groupService.getGroup(groupId);
    const creatorAccess = await this.validateUserGroupAccess(createdBy, groupId);
    
    if (!creatorAccess.hasAccess || 
        creatorAccess.accessType !== 'owner' && 
        creatorAccess.accessType !== 'manager') {
      throw new AuthorizationError(
        'Only group owners and managers can create group-scoped roles'
      );
    }
    
    // Create the group-scoped role
    const role = new Role({
      organizationId: group.organizationId,
      name: roleDefinition.name,
      description: roleDefinition.description,
      type: 'custom',
      scopeType: 'group',
      scopeId: groupId,
      permissions: roleDefinition.permissions,
      status: 'active',
      createdAt: new Date(),
      updatedAt: new Date()
    });
    
    await this.roleRepository.save(role);
    
    // Log the creation
    await this.auditService.logGroupRoleCreation(createdBy, role);
    
    return this.mapToDto(role);
  }
  
  async assignGroupScopedRole(
    groupId: UUID,
    userId: UUID,
    roleId: UUID,
    assignedBy: UUID
  ): Promise<UserRoleDto> {
    // Validate group membership
    const userGroups = await this.groupService.getUserGroups(userId);
    const isInGroup = userGroups.some(g => g.id === groupId);
    
    if (!isInGroup) {
      throw new ValidationError(
        `User ${userId} is not a member of group ${groupId}`
      );
    }
    
    // Validate role is group-scoped for this group
    const role = await this.roleRepository.findById(roleId);
    if (role.scopeType !== 'group' || role.scopeId !== groupId) {
      throw new ValidationError(
        `Role ${roleId} is not a group-scoped role for group ${groupId}`
      );
    }
    
    // Create user role assignment
    const userRole = new UserRole({
      userId: userId,
      roleId: roleId,
      assignedBy: assignedBy,
      assignedAt: new Date(),
      status: 'active',
      scopeContext: {
        scopeType: 'group',
        scopeId: groupId
      }
    });
    
    await this.userRoleRepository.save(userRole);
    
    return this.mapToDto(userRole);
  }
}
```

## Organization Unit Scoped Roles

### Enhanced PermissionEvaluator for OU Scopes

```typescript
// Enhanced PermissionEvaluator
class PermissionEvaluator {
  async evaluatePermission(
    userId: UUID, 
    permissionName: string, 
    context?: PermissionContext
  ): Promise<boolean> {
    // Existing logic...
    
    // Enhanced OU scope validation
    if (role.scopeType === ScopeType.ORGANIZATION_UNIT) {
      return await this.validateOrganizationUnitScope(role, context, user);
    }
  }
  
  private async validateOrganizationUnitScope(
    role: Role, 
    context: PermissionContext,
    user: User
  ): Promise<boolean> {
    if (!context.organizationUnitId) {
      return false;
    }
    
    // Check if the role's scope matches the context
    if (role.scopeId !== context.organizationUnitId) {
      return false;
    }
    
    // Enhanced validation: Check user's relationship to the OU
    const ouValidation = await this.validateUserOUAccess(user, context.organizationUnitId);
    
    if (!ouValidation.hasAccess) {
      this.auditLogger.logScopeViolation(user.id, role.id, context);
      return false;
    }
    
    // Check specific permission requirements
    return await this.validateOUPermissionRequirements(role, permissionName, context);
  }
  
  private async validateUserOUAccess(
    user: User, 
    organizationUnitId: UUID
  ): Promise<OUAccessValidation> {
    // Check if user is owner of the OU
    if (user.id === await this.getOUOwnerId(organizationUnitId)) {
      return { hasAccess: true, accessType: 'owner' };
    }
    
    // Check if user is manager of the OU
    if (await this.isUserManager(user.id, organizationUnitId)) {
      return { hasAccess: true, accessType: 'manager' };
    }
    
    // Check if user belongs to the OU (for member operations)
    if (user.organizationUnitId === organizationUnitId) {
      return { hasAccess: true, accessType: 'member' };
    }
    
    return { hasAccess: false, accessType: 'none' };
  }
}
```

### Organization Unit Context Validator

```typescript
// Enhanced service for OU context validation
class OUContextValidator {
  async validateOUCrossOperation(
    userId: UUID,
    sourceOUId: UUID,
    targetOUId: UUID,
    operation: string
  ): Promise<ValidationResult> {
    const user = await this.getUser(userId);
    
    // Check if user has admin privileges (can bypass OU restrictions)
    if (await this.hasAdminPrivileges(user)) {
      return { isValid: true, reason: 'Admin override' };
    }
    
    // Check ownership/management of source OU
    const sourceAccess = await this.validateUserOUAccess(user, sourceOUId);
    if (!sourceAccess.hasAccess) {
      return { 
        isValid: false, 
        reason: `No access to source OU: ${sourceOUId}` 
      };
    }
    
    // For cross-OU operations, check target OU access
    if (sourceOUId !== targetOUId) {
      const targetAccess = await this.validateUserOUAccess(user, targetOUId);
      if (!targetAccess.hasAccess) {
        return { 
          isValid: false, 
          reason: `No access to target OU: ${targetOUId}` 
        };
      }
      
      // Additional validation for cross-OU operations
      return await this.validateCrossOUOperation(user, sourceOUId, targetOUId, operation);
    }
    
    return { isValid: true, reason: 'Same OU operation allowed' };
  }
  
  private async validateCrossOUOperation(
    user: User,
    sourceOUId: UUID,
    targetOUId: UUID,
    operation: string
  ): Promise<ValidationResult> {
    // Only admins can perform cross-OU operations
    return { 
      isValid: false, 
      reason: 'Cross-OU operations require admin privileges' 
    };
  }
}
```

### Enhanced Role Assignment Service for OU Scopes

```typescript
// Enhanced role assignment with OU scope validation
class RoleAssignmentService {
  async assignScopedRole(
    userId: UUID,
    roleId: UUID,
    assignedBy: UUID,
    context?: AssignmentContext
  ): Promise<UserRole> {
    // Existing validation...
    
    // Enhanced OU scope validation
    if (role.scopeType === ScopeType.ORGANIZATION_UNIT) {
      await this.validateOUScopedAssignment(user, role, assigner, context);
    }
    
    // Create role assignment
    return await this.createUserRoleAssignment(userId, roleId, assignedBy);
  }
  
  private async validateOUScopedAssignment(
    user: User,
    role: Role,
    assigner: User,
    context?: AssignmentContext
  ): Promise<void> {
    // Check if assigner has appropriate OU access
    const assignerAccess = await this.validateUserOUAccess(assigner, role.scopeId);
    
    if (!assignerAccess.hasAccess) {
      throw new AuthorizationError(
        `Assigner does not have access to organization unit: ${role.scopeId}`
      );
    }
    
    // Check if assigner has sufficient privileges within the OU
    if (assignerAccess.accessType !== 'owner' && assignerAccess.accessType !== 'manager') {
      throw new AuthorizationError(
        'Only OU owners and managers can assign OU-scoped roles'
      );
    }
    
    // Check if user belongs to the OU (for non-admin assignments)
    if (user.organizationUnitId !== role.scopeId) {
      throw new ValidationError(
        'User must belong to the organization unit to receive OU-scoped roles'
      );
    }
    
    // Validate role assignment within OU hierarchy
    await this.validateOUHierarchyConstraints(user, role, assigner);
  }
  
  private async validateOUHierarchyConstraints(
    user: User,
    role: Role,
    assigner: User
  ): Promise<void> {
    // Prevent assignment of higher-level roles by lower-level users
    const assignerRoleLevel = await this.getUserRoleLevel(assigner.id, role.scopeId);
    const targetRoleLevel = await this.getRoleLevel(role.id);
    
    if (assignerRoleLevel < targetRoleLevel) {
      throw new AuthorizationError(
        'Cannot assign roles higher than assigner\'s level within the OU'
      );
    }
  }
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

### Enhanced Database Constraints for OU Scopes

```sql
-- Enhanced organization units table with scope validation
ALTER TABLE organization_units ADD COLUMN scope_validation_enabled BOOLEAN DEFAULT true;
ALTER TABLE organization_units ADD COLUMN last_scope_validation TIMESTAMP;

-- Enhanced audit logs for scoped operations
CREATE TABLE ou_scoped_operations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    organization_unit_id UUID NOT NULL REFERENCES organization_units(id),
    operation_type VARCHAR(50) NOT NULL,
    target_resource_id UUID,
    scope_validation_passed BOOLEAN NOT NULL,
    scope_violation_details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_ou_scoped_ops_user (user_id),
    INDEX idx_ou_scoped_ops_ou (organization_unit_id),
    INDEX idx_ou_scoped_ops_operation (operation_type)
);

-- Enhanced role assignments with scope tracking
ALTER TABLE user_roles ADD COLUMN scope_validation_required BOOLEAN DEFAULT false;
ALTER TABLE user_roles ADD COLUMN scope_validation_timestamp TIMESTAMP;
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

### API Endpoint Security

```typescript
// Enhanced organization unit controller
class OrganizationUnitController {
  @Post('/:id/users')
  @UseMiddleware(AuthMiddleware, OUAuthorizationMiddleware)
  async addUserToOU(
    @Param('id') ouId: UUID,
    @Body() request: AddUserToOURequest,
    @CurrentUser() user: AuthenticatedUser
  ): Promise<ApiResponse> {
    // Validate OU scope
    const scopeValidation = await this.ouValidator.validateUserOUAccess(user, ouId);
    
    if (!scopeValidation.hasAccess) {
      throw new ForbiddenError('Access denied: No permissions for this organization unit');
    }
    
    // Check specific permission for adding users
    if (!await this.permissionService.hasPermission(user.id, 'add_users_to_ou', { organizationUnitId: ouId })) {
      throw new ForbiddenError('Insufficient permissions to add users to this organization unit');
    }
    
    // Validate target user belongs to the same organization
    const targetUser = await this.userService.getUser(request.userId);
    if (targetUser.organizationId !== user.organizationId) {
      throw new ValidationError('Cannot add user from different organization');
    }
    
    // Perform the operation
    return await this.ouService.addUserToOrganizationUnit(ouId, request.userId);
  }
  
  @Delete('/:id')
  @UseMiddleware(AuthMiddleware, OUAuthorizationMiddleware)
  async deleteOrganizationUnit(
    @Param('id') ouId: UUID,
    @CurrentUser() user: AuthenticatedUser
  ): Promise<ApiResponse> {
    // Only admins can delete organization units
    if (!await this.permissionService.hasPermission(user.id, 'delete_organization_units')) {
      throw new ForbiddenError('Only administrators can delete organization units');
    }
    
    return await this.ouService.deleteOrganizationUnit(ouId);
  }
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

### Use Case 4: Organization Unit Hierarchy Management

**Scenario**: OU owners and managers can only manage users within their own organization units.

```typescript
// OU owner can invite users to their OU
const ouOwnerInvitation = {
  userId: 'user-new-hire-uuid',
  organizationUnitId: 'ou-engineering-uuid',
  invitedBy: 'user-ou-owner-uuid',
  reason: 'New hire for engineering team'
};

// Permission check for invitation
const canInvite = await permissionService.hasPermission(
  'user-ou-owner-uuid',
  'invite_users_to_ou',
  {
    scopeType: 'organization_unit',
    scopeId: 'ou-engineering-uuid',
    targetUserId: 'user-new-hire-uuid',
    action: 'invite'
  }
);
// Returns: true (OU owner can invite to their OU)

// OU manager cannot invite users to different OU
const cannotInviteToDifferentOU = await permissionService.hasPermission(
  'user-ou-manager-uuid',
  'invite_users_to_ou',
  {
    scopeType: 'organization_unit',
    scopeId: 'ou-marketing-uuid', // Different OU
    targetUserId: 'user-new-hire-uuid',
    action: 'invite'
  }
);
// Returns: false (OU manager cannot operate in different OU)

// Admin can override OU restrictions
const adminCanInviteAnywhere = await permissionService.hasPermission(
  'user-admin-uuid',
  'invite_users_to_ou',
  {
    scopeType: 'organization_unit',
    scopeId: 'ou-any-uuid',
    targetUserId: 'user-any-uuid',
    action: 'invite'
  }
);
// Returns: true (admin has organization-wide permissions)
```

## Security and Validation

### Scope Violation Prevention

```typescript
class SecurityValidator {
  async validateScopeBoundary(
    userId: UUID,
    operation: string,
    targetScope: ScopeContext
  ): Promise<SecurityValidationResult> {
    const user = await this.getUser(userId);
    const userRoles = await this.getUserRoles(userId);
    
    // Check for admin override
    if (await this.hasAdminPrivileges(user)) {
      return { isValid: true, reason: 'Admin override' };
    }
    
    // Check if user has appropriate scoped permissions
    for (const userRole of userRoles) {
      const role = await this.getRole(userRole.roleId);
      
      if (this.roleAppliesToScope(role, targetScope)) {
        const hasPermission = await this.hasPermissionForOperation(
          user.id, 
          operation, 
          targetScope
        );
        
        if (hasPermission) {
          return { isValid: true, reason: 'Valid scoped permission' };
        }
      }
    }
    
    // Log security violation
    await this.auditLogger.logSecurityViolation(userId, operation, targetScope);
    
    return { 
      isValid: false, 
      reason: 'Insufficient scoped permissions for operation' 
    };
  }
  
  private async hasAdminPrivileges(user: User): Promise<boolean> {
    const adminRoles = await this.getUserRolesByType(user.id, 'ADMIN');
    return adminRoles.length > 0;
  }
  
  private roleAppliesToScope(role: Role, targetScope: ScopeContext): boolean {
    if (role.scopeType === ScopeType.ORGANIZATION) {
      return true; // Admin roles apply everywhere
    }
    
    return role.scopeType === targetScope.type && role.scopeId === targetScope.id;
  }
}

interface ScopeContext {
  type: ScopeType;
  id: UUID;
  organizationId: UUID;
}

interface SecurityValidationResult {
  isValid: boolean;
  reason: string;
}
```

### Audit Trail for Scoped Operations

```typescript
class ScopedAuditLogger {
  async logScopedOperation(
    userId: UUID,
    operation: string,
    scopeContext: ScopeContext,
    result: OperationResult
  ): Promise<void> {
    const auditEntry = {
      userId,
      operation,
      scopeType: scopeContext.type,
      scopeId: scopeContext.id,
      organizationId: scopeContext.organizationId,
      timestamp: new Date(),
      result: result.status,
      details: {
        operationDetails: result.details,
        scopeValidation: result.scopeValidation,
        permissionCheck: result.permissionCheck
      }
    };
    
    await this.auditRepository.create(auditEntry);
    
    // Log security violations
    if (!result.scopeValidation.isValid) {
      await this.logSecurityViolation(auditEntry, result.scopeValidation.reason);
    }
  }
  
  private async logSecurityViolation(
    auditEntry: any,
    violationReason: string
  ): Promise<void> {
    const violationEntry = {
      ...auditEntry,
      violationType: 'SCOPE_VIOLATION',
      violationReason,
      severity: 'HIGH',
      requiresReview: true
    };
    
    await this.securityViolationRepository.create(violationEntry);
  }
}
```

This comprehensive implementation provides robust scoped role functionality that ensures proper access control boundaries while maintaining system performance and usability. The design supports both group-scoped and organization unit-scoped roles, with comprehensive validation and audit capabilities.