import { injectable, inject } from 'inversify';
import { ScopeType, PermissionContext, UserRole, User, Role } from '../types';
import { AuditLoggerService } from './audit-logger.service';
import { DatabaseService } from './database.service';

export interface OUAccessValidation {
  hasAccess: boolean;
  accessType: 'owner' | 'manager' | 'member' | 'none';
}

export interface ValidationResult {
  isValid: boolean;
  reason: string;
}

@injectable()
export class PermissionEvaluator {
  @inject('DatabaseService') private databaseService: DatabaseService;
  @inject('AuditLoggerService') private auditLogger: AuditLoggerService;

  async evaluatePermission(
    userId: string, 
    permissionName: string, 
    context?: PermissionContext
  ): Promise<boolean> {
    const user = await this.getUser(userId);
    const userRoles = await this.getUserRoles(userId);
    
    for (const userRole of userRoles) {
      const role = await this.getRole(userRole.roleId);
      const hasPermission = this.checkRolePermission(role, permissionName);
      
      if (hasPermission) {
        // Check scope validity
        const scopeValid = await this.validateScope(role, context, user);
        
        if (scopeValid) {
          return true;
        }
      }
    }
    
    return false;
  }
  
  private async validateScope(
    role: Role, 
    context?: PermissionContext,
    user?: User
  ): Promise<boolean> {
    if (role.scopeType === ScopeType.ORGANIZATION) {
      return true; // No scope restrictions
    }
    
    if (!context) {
      return false; // Scoped permissions require context
    }
    
    switch (role.scopeType) {
      case ScopeType.GROUP:
        return this.validateGroupScope(role, context);
        
      case ScopeType.ORGANIZATION_UNIT:
        return this.validateOrganizationUnitScope(role, context, user!);
        
      default:
        return false;
    }
  }
  
  private async validateGroupScope(
    role: Role, 
    context: PermissionContext
  ): Promise<boolean> {
    if (!context.groupId) {
      return false;
    }
    
    // Check if the role's scope matches the context
    if (role.scopeId !== context.groupId) {
      return false;
    }
    
    // Check if user is still a member of the group
    const userGroups = await this.getUserGroups(context.userId);
    const isInGroup = userGroups.some(g => g.id === context.groupId);
    
    return isInGroup;
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
      await this.auditLogger.logScopeViolation(user.id, role.id, context, 'OU_SCOPE_VIOLATION');
      return false;
    }
    
    // Check specific permission requirements based on access type
    return await this.validateOUPermissionRequirements(role, permissionName, context, ouValidation);
  }

  private async validateUserOUAccess(
    user: User, 
    organizationUnitId: string
  ): Promise<OUAccessValidation> {
    // Check if user is owner of the OU
    const ouOwnerId = await this.getOUOwnerId(organizationUnitId);
    if (user.id === ouOwnerId) {
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

  private async validateOUPermissionRequirements(
    role: Role,
    permissionName: string,
    context: PermissionContext,
    ouValidation: OUAccessValidation
  ): Promise<boolean> {
    // Define permission requirements based on access type
    const permissionRequirements: Record<string, string[]> = {
      'owner': [
        'view_users',
        'edit_users', 
        'invite_users',
        'remove_users',
        'move_users',
        'manage_organization_units',
        'view_organization_units'
      ],
      'manager': [
        'view_users',
        'edit_users',
        'invite_users',
        'move_users',
        'view_organization_units'
      ],
      'member': [
        'view_users',
        'view_organization_units'
      ]
    };

    const allowedPermissions = permissionRequirements[ouValidation.accessType] || [];
    
    // Check if the requested permission is allowed for this access type
    if (!allowedPermissions.includes(permissionName)) {
      await this.auditLogger.logPermissionViolation(
        context.userId, 
        permissionName, 
        `Access type '${ouValidation.accessType}' does not allow permission '${permissionName}'`
      );
      return false;
    }

    // Additional validation for sensitive operations
    if (permissionName === 'remove_users' && ouValidation.accessType === 'manager') {
      return await this.validateManagerUserRemoval(context);
    }

    if (permissionName === 'move_users') {
      return await this.validateUserMovement(context);
    }

    return true;
  }

  private async validateManagerUserRemoval(context: PermissionContext): Promise<boolean> {
    // Managers can only remove users who are not managers or owners
    const targetUser = await this.getUser(context.targetUserId!);
    const targetUserRoles = await this.getUserRoles(targetUser.id);
    
    const hasHigherRole = targetUserRoles.some(userRole => 
      userRole.name === 'OU_OWNER' || userRole.name === 'OU_MANAGER'
    );
    
    if (hasHigherRole) {
      await this.auditLogger.logPermissionViolation(
        context.userId,
        'remove_users',
        'Managers cannot remove users with owner or manager roles'
      );
      return false;
    }
    
    return true;
  }

  private async validateUserMovement(context: PermissionContext): Promise<boolean> {
    // Users can only be moved within the same organization
    const sourceUser = await this.getUser(context.userId);
    const targetUser = await this.getUser(context.targetUserId!);
    
    if (sourceUser.organizationId !== targetUser.organizationId) {
      await this.auditLogger.logPermissionViolation(
        context.userId,
        'move_users',
        'Cannot move users across organizations'
      );
      return false;
    }

    // For cross-OU movement, only admins can perform this operation
    if (context.sourceOrganizationUnitId && context.targetOrganizationUnitId) {
      if (context.sourceOrganizationUnitId !== context.targetOrganizationUnitId) {
        const user = await this.getUser(context.userId);
        const userRoles = await this.getUserRoles(user.id);
        
        const isAdmin = userRoles.some(userRole => 
          userRole.name === 'SUPER_ADMIN' || userRole.name === 'ADMIN'
        );
        
        if (!isAdmin) {
          await this.auditLogger.logPermissionViolation(
            context.userId,
            'move_users',
            'Only admins can move users across organization units'
          );
          return false;
        }
      }
    }
    
    return true;
  }

  private async getOUOwnerId(organizationUnitId: string): Promise<string | null> {
    const result = await this.databaseService.query(
      'SELECT owner_id FROM organization_units WHERE id = $1',
      [organizationUnitId]
    );
    
    return result.rows[0]?.owner_id || null;
  }

  private async isUserManager(userId: string, organizationUnitId: string): Promise<boolean> {
    // Check if user has manager role in the specific OU
    const userRoles = await this.getUserRoles(userId);
    
    return userRoles.some(userRole => 
      userRole.name === 'OU_MANAGER' && 
      userRole.scopeType === ScopeType.ORGANIZATION_UNIT &&
      userRole.scopeId === organizationUnitId
    );
  }

  private async getUser(userId: string): Promise<User> {
    const result = await this.databaseService.query(
      'SELECT * FROM users WHERE id = $1',
      [userId]
    );
    
    return result.rows[0];
  }

  private async getUserRoles(userId: string): Promise<UserRole[]> {
    const result = await this.databaseService.query(`
      SELECT ur.* FROM user_roles ur
      WHERE ur.user_id = $1 AND ur.status = 'active'
    `, [userId]);
    
    return result.rows;
  }

  private async getRole(roleId: string): Promise<Role> {
    const result = await this.databaseService.query(
      'SELECT * FROM roles WHERE id = $1',
      [roleId]
    );
    
    return result.rows[0];
  }

  private async getUserGroups(userId: string): Promise<any[]> {
    const result = await this.databaseService.query(`
      SELECT g.* FROM groups g
      JOIN group_members gm ON g.id = gm.group_id
      WHERE gm.user_id = $1 AND gm.status = 'active'
    `, [userId]);
    
    return result.rows;
  }

  private checkRolePermission(role: Role, permissionName: string): boolean {
    // This would typically check the role's permissions
    // For now, we'll assume the role has the permission if it's in the role's permission list
    return role.permissions?.includes(permissionName) || false;
  }
}