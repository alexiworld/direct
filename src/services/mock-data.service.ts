import { injectable } from 'inversify';
import { UUID, User, Role, UserRole, ScopeType, PermissionContext } from '../types';

@injectable()
export class MockDataService {
  private mockUsers: User[] = [
    {
      id: 'user-admin-uuid',
      organizationId: 'org-1',
      organizationUnitId: 'ou-engineering-uuid',
      firstName: 'Admin',
      lastName: 'User',
      email: 'admin@example.com',
      phone: '123-456-7890',
      status: 'active',
      lastLoginAt: new Date(),
      failedLoginAttempts: 0,
      lockedUntil: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null
    },
    {
      id: 'user-uuid',
      organizationId: 'org-1',
      organizationUnitId: 'ou-engineering-uuid',
      firstName: 'Test',
      lastName: 'User',
      email: 'user@example.com',
      phone: '098-765-4321',
      status: 'active',
      lastLoginAt: new Date(),
      failedLoginAttempts: 0,
      lockedUntil: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null
    }
  ];

  private mockRoles: Role[] = [
    {
      id: 'role-group-manager-uuid',
      organizationId: 'org-1',
      name: 'Group Manager',
      description: 'Manager of a group',
      type: 'custom',
      isSystemRole: false,
      status: 'active',
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
      scopeType: ScopeType.GROUP,
      scopeId: 'group-parent-uuid'
    },
    {
      id: 'role-ou-manager-uuid',
      organizationId: 'org-1',
      name: 'OU Manager',
      description: 'Manager of an organization unit',
      type: 'custom',
      isSystemRole: false,
      status: 'active',
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
      scopeType: ScopeType.ORGANIZATION_UNIT,
      scopeId: 'ou-engineering-uuid'
    }
  ];

  private mockUserRoles: UserRole[] = [
    {
      id: 'ur-1',
      userId: 'user-admin-uuid',
      roleId: 'role-ou-manager-uuid',
      assignedBy: 'user-admin-uuid',
      assignedAt: new Date(),
      status: 'active',
      createdAt: new Date(),
      updatedAt: new Date(),
      name: 'OU Manager',
      scopeType: ScopeType.ORGANIZATION_UNIT,
      scopeId: 'ou-engineering-uuid'
    }
  ];

  private mockPermissions: string[] = [
    'assign_roles',
    'revoke_roles', 
    'view_users',
    'edit_users',
    'invite_users',
    'remove_users',
    'move_users',
    'manage_organization_units',
    'view_organization_units'
  ];

  getUser(userId: UUID): User | undefined {
    return this.mockUsers.find(u => u.id === userId);
  }

  getRole(roleId: UUID): Role | undefined {
    return this.mockRoles.find(r => r.id === roleId);
  }

  getUserRoles(userId: UUID): UserRole[] {
    return this.mockUserRoles.filter(ur => ur.userId === userId);
  }

  getRolePermissions(roleId: UUID): string[] {
    const role = this.getRole(roleId);
    if (!role) return [];
    
    // Return permissions based on role name
    switch (role.name) {
      case 'Group Manager':
        return ['assign_roles', 'view_users'];
      case 'OU Manager':
        return ['assign_roles', 'revoke_roles', 'view_users'];
      default:
        return [];
    }
  }

  hasPermission(userId: UUID, permissionName: string, context?: PermissionContext): boolean {
    const userRoles = this.getUserRoles(userId);
    
    for (const userRole of userRoles) {
      const rolePermissions = this.getRolePermissions(userRole.roleId);
      if (rolePermissions.includes(permissionName)) {
        // Check scope validation
        if (this.validateScope(userRole, context)) {
          return true;
        }
      }
    }
    
    return false;
  }

  getUserPermissionsInScope(userId: UUID, scopeType: ScopeType, scopeId: UUID): string[] {
    const userRoles = this.getUserRoles(userId);
    const permissions: Set<string> = new Set();
    
    for (const userRole of userRoles) {
      if (userRole.scopeType === scopeType && userRole.scopeId === scopeId) {
        const rolePermissions = this.getRolePermissions(userRole.roleId);
        rolePermissions.forEach(p => permissions.add(p));
      }
    }
    
    return Array.from(permissions);
  }

  validateScope(userRole: UserRole, context?: PermissionContext): boolean {
    if (!context) return false;
    
    // Organization-level roles apply everywhere
    if (userRole.scopeType === ScopeType.ORGANIZATION) {
      return true;
    }
    
    // Scoped roles only apply to their specific scope
    return userRole.scopeType === context.scopeType && userRole.scopeId === context.scopeId;
  }

  validateUserInScope(userId: UUID, scopeType: ScopeType, scopeId?: UUID): boolean {
    const user = this.getUser(userId);
    if (!user) return false;
    
    switch (scopeType) {
      case ScopeType.ORGANIZATION:
        return true; // User belongs to organization
      case ScopeType.GROUP:
        // For demo, assume user is in group if scopeId matches
        return scopeId === 'group-project-alpha-uuid';
      case ScopeType.ORGANIZATION_UNIT:
        return user.organizationUnitId === scopeId;
      default:
        return false;
    }
  }

  validateRoleAssignmentAuthority(assignerId: UUID, roleId: UUID, scopeType: ScopeType, scopeId?: UUID): boolean {
    const assignerRoles = this.getUserRoles(assignerId);
    
    for (const userRole of assignerRoles) {
      const rolePermissions = this.getRolePermissions(userRole.roleId);
      if (rolePermissions.includes('assign_roles')) {
        // Check if assigner has authority in the scope
        if (this.validateScope(userRole, { scopeType, scopeId } as PermissionContext)) {
          return true;
        }
      }
    }
    
    return false;
  }

  createMockUserRole(command: {
    userId: UUID;
    roleId: UUID;
    assignedBy: UUID;
    scopeType: ScopeType;
    scopeId?: UUID;
    expiresAt?: Date;
    reason?: string;
  }): UserRole {
    const userRole: UserRole = {
      id: this.generateUUID(),
      userId: command.userId,
      roleId: command.roleId,
      assignedBy: command.assignedBy,
      assignedAt: new Date(),
      status: 'active',
      createdAt: new Date(),
      updatedAt: new Date(),
      name: this.getRole(command.roleId)?.name,
      scopeType: command.scopeType,
      scopeId: command.scopeId
    };
    
    this.mockUserRoles.push(userRole);
    return userRole;
  }

  private generateUUID(): UUID {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  // Organization mock methods
  createMockOrganization(organization: any): any {
    return {
      id: this.generateUUID(),
      name: organization.name,
      description: organization.description,
      status: organization.status || 'active',
      createdAt: new Date(),
      updatedAt: new Date(),
      metadata: organization.metadata || {}
    };
  }

  getMockOrganization(organizationId: UUID): any {
    console.log("[DEBUG] getMockOrganization");
    console.trace("[DEBUG] getMockOrganization");
    return {
      id: organizationId,
      name: 'Direct Organization',
      description: 'Main organization for testing',
      status: 'active',
      createdAt: new Date(),
      updatedAt: new Date(),
      metadata: {}
    };
  }

  updateMockOrganization(organizationId: UUID, updates: any): any {
    return {
      id: organizationId,
      name: updates.name || 'Direct Organization',
      description: updates.description || 'Main organization for testing',
      status: updates.status || 'active',
      createdAt: new Date(),
      updatedAt: new Date(),
      metadata: updates.metadata || {}
    };
  }

  listMockOrganizations(limit: number, offset: number): any {
    const organizations = [
      {
        id: 'org-1X',
        name: 'Direct Organization',
        description: 'Main organization for testing',
        status: 'active',
        createdAt: new Date(),
        updatedAt: new Date(),
        metadata: {}
      }
    ];
    
    return {
      organizations: organizations.slice(offset, offset + limit),
      total: organizations.length
    };
  }

  // Mock organization setup method
  setupMockOrganization(setupData: any): any {
    const organizationId = this.generateUUID();
    const powerAdminUserId = this.generateUUID();
    const powerAdminRoleId = this.generateUUID();
    const rootOUId = setupData.rootOU ? this.generateUUID() : undefined;

    // Create mock organization
    const organization = {
      id: organizationId,
      name: setupData.name,
      description: setupData.description || null,
      status: setupData.status || 'active',
      createdAt: new Date(),
      updatedAt: new Date(),
      metadata: setupData.metadata || {}
    };

    // Create mock power admin user
    const powerAdminUser = {
      id: powerAdminUserId,
      organizationId: organizationId,
      organizationUnitId: rootOUId,
      firstName: setupData.powerAdmin.firstName,
      lastName: setupData.powerAdmin.lastName,
      email: setupData.powerAdmin.email,
      phone: setupData.powerAdmin.phone || null,
      status: 'active',
      lastLoginAt: null,
      failedLoginAttempts: 0,
      lockedUntil: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null
    };

    // Create mock power admin role
    const powerAdminRole = {
      id: powerAdminRoleId,
      organizationId: organizationId,
      name: 'Power Admin',
      description: 'Organization power administrator with full system access',
      type: 'system',
      isSystemRole: true,
      status: 'active',
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
      scopeType: 'organization' as any,
      scopeId: organizationId
    };

    // Create mock user role assignment
    const powerAdminUserRole = {
      id: this.generateUUID(),
      userId: powerAdminUserId,
      roleId: powerAdminRoleId,
      assignedBy: powerAdminUserId,
      assignedAt: new Date(),
      status: 'active',
      createdAt: new Date(),
      updatedAt: new Date(),
      name: 'Power Admin',
      scopeType: 'organization' as any,
      scopeId: organizationId
    };

    return {
      organizationId,
      powerAdminUserId,
      rootOUId,
      powerAdminRoleId,
      powerAdminUserRole
    };
  }
}
