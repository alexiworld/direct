import { injectable, inject } from 'inversify';
import { 
  UUID, 
  User, 
  Role, 
  UserRole, 
  ScopeType, 
  PermissionContext,
  GroupAccessValidation,
  OUAccessValidation
} from '../types';
import { DatabaseService } from './database.service';
import { GroupService } from './group.service';

@injectable()
export class ScopedPermissionService {
  @inject('DatabaseService') private readonly databaseService!: DatabaseService;
  @inject('GroupService') private readonly groupService!: GroupService;

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
      const role = await this.getRole(userRole.roleId);
      
      // Check if role has the requested permission
      const hasPermission = await this.checkRolePermission(role, permissionName);
      
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
      const role = await this.getRole(userRole.roleId);
      
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
    const user = await this.getUser(context.userId);
    
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
  
  private async getUserRoles(userId: UUID): Promise<UserRole[]> {
    const result = await this.databaseService.query(`
      SELECT ur.* FROM user_roles ur
      WHERE ur.user_id = $1 AND ur.status = 'active'
    `, [userId]);
    
    return result.rows;
  }
  
  private async getRole(roleId: UUID): Promise<Role> {
    const result = await this.databaseService.query(
      'SELECT * FROM roles WHERE id = $1',
      [roleId]
    );
    
    return result.rows[0];
  }
  
  private async checkRolePermission(role: Role, permissionName: string): Promise<boolean> {
    const result = await this.databaseService.query(`
      SELECT COUNT(*) as count FROM role_permissions rp
      JOIN permissions p ON rp.permission_id = p.id
      WHERE rp.role_id = $1 AND p.name = $2 AND rp.status = 'active'
    `, [role.id, permissionName]);
    
    return parseInt(result.rows[0].count) > 0;
  }
  
  private async getRolePermissions(roleId: UUID): Promise<any[]> {
    const result = await this.databaseService.query(`
      SELECT p.* FROM permissions p
      JOIN role_permissions rp ON p.id = rp.permission_id
      WHERE rp.role_id = $1 AND rp.status = 'active'
    `, [roleId]);
    
    return result.rows;
  }
  
  private async getUser(userId: UUID): Promise<User> {
    const result = await this.databaseService.query(
      'SELECT * FROM users WHERE id = $1',
      [userId]
    );
    
    return result.rows[0];
  }
}