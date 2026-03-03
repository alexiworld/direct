import { PermissionContext } from '../types';
export interface OUAccessValidation {
    hasAccess: boolean;
    accessType: 'owner' | 'manager' | 'member' | 'none';
}
export interface ValidationResult {
    isValid: boolean;
    reason: string;
}
export declare class PermissionEvaluator {
    private readonly databaseService;
    private readonly auditLogger;
    private readonly ouValidator;
    evaluatePermission(userId: string, permissionName: string, context?: PermissionContext): Promise<boolean>;
    private validateScope;
    private validateGroupScope;
    private validateOrganizationUnitScope;
    private validateUserOUAccess;
    private validateOUPermissionRequirements;
    private validateManagerUserRemoval;
    private validateUserMovement;
    private getOUOwnerId;
    private isUserManager;
    private getUser;
    private getUserRoles;
    private getRole;
    private getUserGroups;
    private checkRolePermission;
}
//# sourceMappingURL=permission-evaluator.service.d.ts.map