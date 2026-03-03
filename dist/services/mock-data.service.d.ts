import { UUID, User, Role, UserRole, ScopeType, PermissionContext } from '../types';
export declare class MockDataService {
    private mockUsers;
    private mockRoles;
    private mockUserRoles;
    private mockPermissions;
    getUser(userId: UUID): User | undefined;
    getRole(roleId: UUID): Role | undefined;
    getUserRoles(userId: UUID): UserRole[];
    getRolePermissions(roleId: UUID): string[];
    hasPermission(userId: UUID, permissionName: string, context?: PermissionContext): boolean;
    getUserPermissionsInScope(userId: UUID, scopeType: ScopeType, scopeId: UUID): string[];
    validateScope(userRole: UserRole, context?: PermissionContext): boolean;
    validateUserInScope(userId: UUID, scopeType: ScopeType, scopeId?: UUID): boolean;
    validateRoleAssignmentAuthority(assignerId: UUID, roleId: UUID, scopeType: ScopeType, scopeId?: UUID): boolean;
    createMockUserRole(command: {
        userId: UUID;
        roleId: UUID;
        assignedBy: UUID;
        scopeType: ScopeType;
        scopeId?: UUID;
        expiresAt?: Date;
        reason?: string;
    }): UserRole;
    private generateUUID;
    createMockOrganization(organization: any): any;
    getMockOrganization(organizationId: UUID): any;
    updateMockOrganization(organizationId: UUID, updates: any): any;
    listMockOrganizations(limit: number, offset: number): any;
    setupMockOrganization(setupData: any): any;
}
//# sourceMappingURL=mock-data.service.d.ts.map