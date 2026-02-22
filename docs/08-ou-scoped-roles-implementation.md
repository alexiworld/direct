# Organization Unit Scoped Roles Implementation

**Document Version**: 1.0  
**Created**: February 2026  
**Status**: Implementation

## Overview

This document outlines the implementation of Organization Unit (OU) scoped roles to extend the existing scoped roles functionality. This ensures that non-admin users with OU_OWNER and OU_MANAGER roles can only perform actions on their own organization units, maintaining proper access control boundaries.

## Implementation Plan

### Phase 1: Core Permission Evaluation Enhancement

#### 1.1 Enhanced PermissionEvaluator for OU Scopes

**File**: `src/services/permission-evaluator.service.ts`

**Changes**:
- Extend `validateOrganizationUnitScope` method with comprehensive validation
- Add ownership and management validation
- Implement cross-unit operation prevention
- Add proper error handling and logging

#### 1.2 Organization Unit Context Validation

**File**: `src/services/ou-context-validator.service.ts` (New)

**Purpose**: Validate organization unit context for scoped operations

**Key Features**:
- Ownership verification
- Management hierarchy validation
- Cross-unit operation detection
- Permission boundary enforcement

### Phase 2: Role Assignment and Management

#### 2.1 Enhanced Role Assignment Service

**File**: `src/services/role-assignment.service.ts`

**Changes**:
- Add OU-specific role assignment validation
- Implement ownership-based assignment rules
- Add scope consistency checks
- Prevent unauthorized role assignments

#### 2.2 Organization Unit Role Management

**File**: `src/services/ou-role-manager.service.ts` (New)

**Purpose**: Manage OU-scoped roles and permissions

**Key Features**:
- OU-specific role creation and management
- Scope-based permission assignment
- Role inheritance within OU hierarchy
- Permission conflict resolution

### Phase 3: API Endpoint Security

#### 3.1 Organization Unit Management Endpoints

**Files**: 
- `src/controllers/organization-unit.controller.ts`
- `src/middleware/ou-authorization.middleware.ts` (New)

**Changes**:
- Add scope validation to all OU management operations
- Implement ownership checks for critical operations
- Add proper error responses for scope violations
- Maintain audit trail for all operations

#### 3.2 User Management within Organization Units

**Files**:
- `src/controllers/user.controller.ts`
- `src/services/user-management.service.ts`

**Changes**:
- Add OU scope validation for user operations
- Implement move/transfer validation
- Add invitation scope restrictions
- Prevent cross-unit operations

### Phase 4: Database and Schema Enhancements

#### 4.1 Enhanced Database Constraints

**File**: `database/migrations/001_ou_scoped_roles.sql` (New)

**Changes**:
- Add scope validation constraints
- Enhance foreign key relationships
- Add audit trail fields for scoped operations
- Implement proper indexing for scope queries

#### 4.2 Audit Trail Enhancement

**File**: `src/services/audit-logger.service.ts`

**Changes**:
- Add scope context to audit logs
- Implement detailed operation tracking
- Add scope violation logging
- Enhance security event monitoring

## Detailed Implementation

### Core Permission Evaluation

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
// New service for OU context validation
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

### Enhanced Role Assignment Service

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

### Database Schema Enhancements

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

## Testing Strategy

### Unit Tests

1. **PermissionEvaluator Tests**
   - Test OU scope validation with various user roles
   - Test cross-OU operation prevention
   - Test ownership vs management access levels

2. **RoleAssignmentService Tests**
   - Test OU-scoped role assignment validation
   - Test hierarchy constraint enforcement
   - Test error handling for invalid assignments

3. **OUContextValidator Tests**
   - Test cross-OU operation detection
   - Test ownership validation
   - Test management hierarchy validation

### Integration Tests

1. **End-to-End OU Operations**
   - Test user invitation within OU scope
   - Test user movement within OU scope
   - Test role assignment within OU scope

2. **Security Boundary Tests**
   - Test prevention of cross-OU operations
   - Test admin override functionality
   - Test scope violation logging

### Performance Tests

1. **Scope Validation Performance**
   - Test permission evaluation with large OU hierarchies
   - Test concurrent scoped operations
   - Test database query performance for scope validation

## Deployment Strategy

### Phase 1: Core Implementation
- Deploy enhanced PermissionEvaluator
- Deploy OUContextValidator service
- Deploy enhanced RoleAssignmentService

### Phase 2: API Security
- Deploy enhanced API endpoints
- Deploy OU authorization middleware
- Update existing client applications

### Phase 3: Monitoring and Optimization
- Deploy enhanced audit logging
- Monitor scope validation performance
- Optimize database queries for scale

## Rollback Plan

1. **Database Rollback**
   - Remove new tables and columns
   - Restore previous schema version

2. **Application Rollback**
   - Revert to previous service implementations
   - Disable new middleware components
   - Restore previous API behavior

3. **Configuration Rollback**
   - Disable scope validation features
   - Restore previous permission settings
   - Revert audit logging configuration

## Success Criteria

1. **Security Requirements**
   - ✅ Non-admin users cannot perform cross-OU operations
   - ✅ OU owners/managers can only manage their own OUs
   - ✅ Proper scope validation for all OU operations
   - ✅ Comprehensive audit trail for scoped operations

2. **Functional Requirements**
   - ✅ OU owners can invite users to their OUs
   - ✅ OU managers can manage users within their OUs
   - ✅ Proper error messages for scope violations
   - ✅ Admin override functionality works correctly

3. **Performance Requirements**
   - ✅ Scope validation adds minimal latency (< 50ms)
   - ✅ Database queries remain efficient with large datasets
   - ✅ Concurrent operations handle scope validation correctly

This implementation extends the existing scoped roles functionality to provide comprehensive organization unit access control while maintaining system performance and usability.