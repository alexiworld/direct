import { User } from '../types';
export interface OUAccessValidation {
    hasAccess: boolean;
    accessType: 'owner' | 'manager' | 'member' | 'none';
}
export interface ValidationResult {
    isValid: boolean;
    reason: string;
}
export declare class OUContextValidator {
    private readonly databaseService;
    private readonly auditLogger;
    validateOUCrossOperation(userId: string, sourceOUId: string, targetOUId: string, operation: string): Promise<ValidationResult>;
    validateUserOUAccess(user: User, organizationUnitId: string): Promise<OUAccessValidation>;
    validateUserInvitation(inviterUserId: string, targetUserId: string, targetOUId: string): Promise<ValidationResult>;
    validateUserRemoval(removerUserId: string, targetUserId: string, targetOUId: string): Promise<ValidationResult>;
    validateUserMovement(moverUserId: string, sourceOUId: string, targetOUId: string): Promise<ValidationResult>;
    private validateCrossOUOperation;
    private hasAdminPrivileges;
    private getOUOwnerId;
    private isUserManager;
    private getUser;
    private getUserRoles;
}
//# sourceMappingURL=ou-context-validator.service.d.ts.map