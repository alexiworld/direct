import { UUID, ScopeType, UserRole } from '../types';
export declare class ScopedRoleAssignmentService {
    private readonly dataAccessService;
    assignScopedRole(command: {
        userId: UUID;
        roleId: UUID;
        assignedBy: UUID;
        scopeType: ScopeType;
        scopeId?: UUID;
        expiresAt?: Date;
        reason?: string;
    }): Promise<UserRole>;
    revokeScopedRole(command: {
        userId: UUID;
        roleId: UUID;
        revokedBy: UUID;
        scopeType: ScopeType;
        scopeId?: UUID;
        reason?: string;
    }): Promise<void>;
    getUserScopedRoles(userId: UUID, scopeType: ScopeType, scopeId?: UUID): Promise<UserRole[]>;
    private validateRoleAssignmentAuthority;
    private validateRoleRevocationAuthority;
    private validateUserInScope;
    private getUserPermissionsInScope;
    private logRoleAssignment;
}
//# sourceMappingURL=scoped-role-assignment.service.d.ts.map