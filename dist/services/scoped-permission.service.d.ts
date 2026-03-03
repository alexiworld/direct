import { UUID, ScopeType, PermissionContext } from '../types';
export declare class ScopedPermissionService {
    private readonly databaseService;
    private readonly groupService;
    /**
     * Evaluate if a user has a specific permission within a given context
     */
    hasPermission(userId: UUID, permissionName: string, context?: PermissionContext): Promise<boolean>;
    /**
     * Get all permissions a user has within a specific scope
     */
    getUserPermissionsInScope(userId: UUID, scopeType: ScopeType, scopeId: UUID): Promise<string[]>;
    private validatePermissionScope;
    private validateContextSpecificRules;
    private validateGroupContext;
    private validateOrganizationUnitContext;
    private roleAppliesToScope;
    private getUserRoles;
    private getRole;
    private checkRolePermission;
    private getRolePermissions;
    private getUser;
}
//# sourceMappingURL=scoped-permission.service.d.ts.map