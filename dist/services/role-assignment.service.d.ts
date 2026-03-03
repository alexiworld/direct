import { UserRole, AssignmentContext } from '../types';
export interface RoleAssignmentResult {
    userRole: UserRole;
    success: boolean;
    message: string;
}
export declare class RoleAssignmentService {
    private readonly databaseService;
    private readonly auditLogger;
    private readonly ouValidator;
    assignScopedRole(userId: string, roleId: string, assignedBy: string, context?: AssignmentContext): Promise<RoleAssignmentResult>;
    revokeScopedRole(userId: string, roleId: string, revokedBy: string, reason?: string): Promise<RoleAssignmentResult>;
    private validateAssignmentPermissions;
    private validateRevocationPermissions;
    private validateScopePermissions;
    private validateRevocationScopePermissions;
    private validateGroupAssignmentPermissions;
    private validateOrganizationUnitAssignmentPermissions;
    private validateGroupRevocationPermissions;
    private validateOrganizationUnitRevocationPermissions;
    private validateScopeRequirements;
    private validateGroupScopeRequirements;
    private validateOrganizationUnitScopeRequirements;
    private createUserRoleAssignment;
    private revokeUserRoleAssignment;
    private getUser;
    private getRole;
    private getUserPermissions;
    private getUserRoles;
    private getGroupMemberships;
    private getUserGroups;
    private hasAdminRole;
    private generateUUID;
}
//# sourceMappingURL=role-assignment.service.d.ts.map