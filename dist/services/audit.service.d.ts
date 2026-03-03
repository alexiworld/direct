import { UUID, PermissionContext, UserRole } from '../types';
export declare class AuditService {
    private readonly databaseService;
    logScopedRoleAssignment(userRole: UserRole): Promise<void>;
    logScopeViolation(userId: UUID, roleId: UUID, context: PermissionContext, violationType: string): Promise<void>;
    logPermissionViolation(userId: UUID, permissionName: string, reason: string): Promise<void>;
    logRoleAssignment(assignedBy: UUID, userId: UUID, roleId: UUID, status: 'SUCCESS' | 'FAILED', reason: string): Promise<void>;
    logRoleRevocation(revokedBy: UUID, userId: UUID, roleId: UUID, status: 'SUCCESS' | 'FAILED', reason: string): Promise<void>;
}
//# sourceMappingURL=audit.service.d.ts.map