"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.OUContextValidator = void 0;
const inversify_1 = require("inversify");
const types_1 = require("../types");
const database_service_1 = require("./database.service");
const audit_service_1 = require("./audit.service");
let OUContextValidator = class OUContextValidator {
    async validateOUCrossOperation(userId, sourceOUId, targetOUId, operation) {
        const user = await this.getUser(userId);
        // Check if user has admin privileges (can bypass OU restrictions)
        if (await this.hasAdminPrivileges(user)) {
            return { isValid: true, reason: 'Admin override' };
        }
        // Check ownership/management of source OU
        const sourceAccess = await this.validateUserOUAccess(user, sourceOUId);
        if (!sourceAccess.hasAccess) {
            return {
                isValid: false,
                reason: `No access to source OU: ${sourceOUId}`
            };
        }
        // For cross-OU operations, check target OU access
        if (sourceOUId !== targetOUId) {
            const targetAccess = await this.validateUserOUAccess(user, targetOUId);
            if (!targetAccess.hasAccess) {
                return {
                    isValid: false,
                    reason: `No access to target OU: ${targetOUId}`
                };
            }
            // Additional validation for cross-OU operations
            return await this.validateCrossOUOperation(user, sourceOUId, targetOUId, operation);
        }
        return { isValid: true, reason: 'Same OU operation allowed' };
    }
    async validateUserOUAccess(user, organizationUnitId) {
        try {
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
        catch (error) {
            // If database fails, assume no access for security
            return { hasAccess: false, accessType: 'none' };
        }
    }
    async validateUserInvitation(inviterUserId, targetUserId, targetOUId) {
        const inviter = await this.getUser(inviterUserId);
        const targetUser = await this.getUser(targetUserId);
        // Check if inviter has admin privileges
        if (await this.hasAdminPrivileges(inviter)) {
            return { isValid: true, reason: 'Admin invitation allowed' };
        }
        // Check inviter's access to target OU
        const inviterAccess = await this.validateUserOUAccess(inviter, targetOUId);
        if (!inviterAccess.hasAccess) {
            return {
                isValid: false,
                reason: `Inviter does not have access to organization unit: ${targetOUId}`
            };
        }
        // Check if inviter has permission to invite users
        if (inviterAccess.accessType !== 'owner' && inviterAccess.accessType !== 'manager') {
            return {
                isValid: false,
                reason: 'Only OU owners and managers can invite users to their organization unit'
            };
        }
        // Check if target user belongs to the same organization
        if (inviter.organizationId !== targetUser.organizationId) {
            return {
                isValid: false,
                reason: 'Cannot invite users from different organizations'
            };
        }
        return { isValid: true, reason: 'Invitation allowed' };
    }
    async validateUserRemoval(removerUserId, targetUserId, targetOUId) {
        const remover = await this.getUser(removerUserId);
        const targetUser = await this.getUser(targetUserId);
        // Check if remover has admin privileges
        if (await this.hasAdminPrivileges(remover)) {
            return { isValid: true, reason: 'Admin removal allowed' };
        }
        // Check remover's access to target OU
        const removerAccess = await this.validateUserOUAccess(remover, targetOUId);
        if (!removerAccess.hasAccess) {
            return {
                isValid: false,
                reason: `Remover does not have access to organization unit: ${targetOUId}`
            };
        }
        // Check if remover has permission to remove users
        if (removerAccess.accessType !== 'owner' && removerAccess.accessType !== 'manager') {
            return {
                isValid: false,
                reason: 'Only OU owners and managers can remove users from their organization unit'
            };
        }
        // Check if target user belongs to the same organization
        if (remover.organizationId !== targetUser.organizationId) {
            return {
                isValid: false,
                reason: 'Cannot remove users from different organizations'
            };
        }
        // Additional validation for manager removing users
        if (removerAccess.accessType === 'manager') {
            const targetUserRoles = await this.getUserRoles(targetUser.id);
            const hasHigherRole = targetUserRoles.some(userRole => userRole.name === 'OU_OWNER' || userRole.name === 'OU_MANAGER');
            if (hasHigherRole) {
                return {
                    isValid: false,
                    reason: 'Managers cannot remove users with owner or manager roles'
                };
            }
        }
        return { isValid: true, reason: 'Removal allowed' };
    }
    async validateUserMovement(moverUserId, sourceOUId, targetOUId) {
        const mover = await this.getUser(moverUserId);
        // Check if mover has admin privileges
        if (await this.hasAdminPrivileges(mover)) {
            return { isValid: true, reason: 'Admin movement allowed' };
        }
        // Check if this is a cross-OU movement
        if (sourceOUId !== targetOUId) {
            return {
                isValid: false,
                reason: 'Only admins can move users across organization units'
            };
        }
        // For same OU movement, check access
        const moverAccess = await this.validateUserOUAccess(mover, sourceOUId);
        if (!moverAccess.hasAccess) {
            return {
                isValid: false,
                reason: `Mover does not have access to organization unit: ${sourceOUId}`
            };
        }
        // Check if mover has permission to move users
        if (moverAccess.accessType !== 'owner' && moverAccess.accessType !== 'manager') {
            return {
                isValid: false,
                reason: 'Only OU owners and managers can move users within their organization unit'
            };
        }
        return { isValid: true, reason: 'Movement allowed' };
    }
    async validateCrossOUOperation(user, sourceOUId, targetOUId, operation) {
        // Only admins can perform cross-OU operations
        return {
            isValid: false,
            reason: 'Cross-OU operations require admin privileges'
        };
    }
    async hasAdminPrivileges(user) {
        try {
            const userRoles = await this.getUserRoles(user.id);
            return userRoles.some(userRole => userRole.name === 'SUPER_ADMIN' || userRole.name === 'ADMIN');
        }
        catch (error) {
            // If database fails, assume no admin privileges for security
            return false;
        }
    }
    async getOUOwnerId(organizationUnitId) {
        const result = await this.databaseService.query('SELECT owner_id FROM organization_units WHERE id = $1', [organizationUnitId]);
        return result.rows[0]?.owner_id || null;
    }
    async isUserManager(userId, organizationUnitId) {
        // Check if user has manager role in the specific OU
        const userRoles = await this.getUserRoles(userId);
        return userRoles.some(userRole => userRole.name === 'OU_MANAGER' &&
            userRole.scopeType === types_1.ScopeType.ORGANIZATION_UNIT &&
            userRole.scopeId === organizationUnitId);
    }
    async getUser(userId) {
        const result = await this.databaseService.query('SELECT * FROM users WHERE id = $1', [userId]);
        return result.rows[0];
    }
    async getUserRoles(userId) {
        const result = await this.databaseService.query(`
      SELECT ur.* FROM user_roles ur
      WHERE ur.user_id = $1 AND ur.status = 'active'
    `, [userId]);
        return result.rows;
    }
};
exports.OUContextValidator = OUContextValidator;
__decorate([
    (0, inversify_1.inject)('DatabaseService'),
    __metadata("design:type", database_service_1.DatabaseService)
], OUContextValidator.prototype, "databaseService", void 0);
__decorate([
    (0, inversify_1.inject)('AuditService'),
    __metadata("design:type", audit_service_1.AuditService)
], OUContextValidator.prototype, "auditLogger", void 0);
exports.OUContextValidator = OUContextValidator = __decorate([
    (0, inversify_1.injectable)()
], OUContextValidator);
//# sourceMappingURL=ou-context-validator.service.js.map