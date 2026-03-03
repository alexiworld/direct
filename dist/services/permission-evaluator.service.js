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
exports.PermissionEvaluator = void 0;
const inversify_1 = require("inversify");
const types_1 = require("../types");
const audit_service_1 = require("./audit.service");
const database_service_1 = require("./database.service");
const ou_context_validator_service_1 = require("./ou-context-validator.service");
let PermissionEvaluator = class PermissionEvaluator {
    async evaluatePermission(userId, permissionName, context) {
        const user = await this.getUser(userId);
        const userRoles = await this.getUserRoles(userId);
        for (const userRole of userRoles) {
            const role = await this.getRole(userRole.roleId);
            const hasPermission = this.checkRolePermission(role, permissionName);
            if (hasPermission) {
                // Check scope validity
                const scopeValid = await this.validateScope(role, context, user);
                if (scopeValid) {
                    return true;
                }
            }
        }
        return false;
    }
    async validateScope(role, context, user) {
        if (role.scopeType === types_1.ScopeType.ORGANIZATION) {
            return true; // No scope restrictions
        }
        if (!context) {
            return false; // Scoped permissions require context
        }
        switch (role.scopeType) {
            case types_1.ScopeType.GROUP:
                return this.validateGroupScope(role, context);
            case types_1.ScopeType.ORGANIZATION_UNIT:
                return this.validateOrganizationUnitScope(role, context, user);
            default:
                return false;
        }
    }
    async validateGroupScope(role, context) {
        if (!context.groupId) {
            return false;
        }
        // Check if the role's scope matches the context
        if (role.scopeId !== context.groupId) {
            return false;
        }
        // Check if user is still a member of the group
        const userGroups = await this.getUserGroups(context.userId);
        const isInGroup = userGroups.some(g => g.id === context.groupId);
        return isInGroup;
    }
    async validateOrganizationUnitScope(role, context, user) {
        if (!context.organizationUnitId) {
            return false;
        }
        // Check if the role's scope matches the context
        if (role.scopeId !== context.organizationUnitId) {
            return false;
        }
        // Enhanced validation: Check user's relationship to the OU
        const ouValidation = await this.validateUserOUAccess(user, context.organizationUnitId);
        if (!ouValidation.hasAccess) {
            await this.auditLogger.logScopeViolation(user.id, role.id, context, 'OU_SCOPE_VIOLATION');
            return false;
        }
        // Check specific permission requirements based on access type
        return await this.validateOUPermissionRequirements(role, 'unknown', context, ouValidation);
    }
    async validateUserOUAccess(user, organizationUnitId) {
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
    async validateOUPermissionRequirements(role, permissionName, context, ouValidation) {
        // Define permission requirements based on access type
        const permissionRequirements = {
            'owner': [
                'view_users',
                'edit_users',
                'invite_users',
                'remove_users',
                'move_users',
                'manage_organization_units',
                'view_organization_units'
            ],
            'manager': [
                'view_users',
                'edit_users',
                'invite_users',
                'move_users',
                'view_organization_units'
            ],
            'member': [
                'view_users',
                'view_organization_units'
            ]
        };
        const allowedPermissions = permissionRequirements[ouValidation.accessType] || [];
        // Check if the requested permission is allowed for this access type
        if (!allowedPermissions.includes(permissionName)) {
            await this.auditLogger.logPermissionViolation(context.userId, permissionName, `Access type '${ouValidation.accessType}' does not allow permission '${permissionName}'`);
            return false;
        }
        // Additional validation for sensitive operations
        if (permissionName === 'remove_users' && ouValidation.accessType === 'manager') {
            return await this.validateManagerUserRemoval(context);
        }
        if (permissionName === 'move_users') {
            return await this.validateUserMovement(context);
        }
        return true;
    }
    async validateManagerUserRemoval(context) {
        // Managers can only remove users who are not managers or owners
        const targetUser = await this.getUser(context.targetUserId);
        const targetUserRoles = await this.getUserRoles(targetUser.id);
        const hasHigherRole = targetUserRoles.some(userRole => userRole.name === 'OU_OWNER' || userRole.name === 'OU_MANAGER');
        if (hasHigherRole) {
            await this.auditLogger.logPermissionViolation(context.userId, 'remove_users', 'Managers cannot remove users with owner or manager roles');
            return false;
        }
        return true;
    }
    async validateUserMovement(context) {
        // Users can only be moved within the same organization
        const sourceUser = await this.getUser(context.userId);
        const targetUser = await this.getUser(context.targetUserId);
        if (sourceUser.organizationId !== targetUser.organizationId) {
            await this.auditLogger.logPermissionViolation(context.userId, 'move_users', 'Cannot move users across organizations');
            return false;
        }
        // For cross-OU movement, only admins can perform this operation
        if (context.sourceOrganizationUnitId && context.targetOrganizationUnitId) {
            if (context.sourceOrganizationUnitId !== context.targetOrganizationUnitId) {
                const user = await this.getUser(context.userId);
                const userRoles = await this.getUserRoles(user.id);
                const isAdmin = userRoles.some(userRole => userRole.name === 'SUPER_ADMIN' || userRole.name === 'ADMIN');
                if (!isAdmin) {
                    await this.auditLogger.logPermissionViolation(context.userId, 'move_users', 'Only admins can move users across organization units');
                    return false;
                }
            }
        }
        return true;
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
    async getRole(roleId) {
        const result = await this.databaseService.query('SELECT * FROM roles WHERE id = $1', [roleId]);
        return result.rows[0];
    }
    async getUserGroups(userId) {
        const result = await this.databaseService.query(`
      SELECT g.* FROM groups g
      JOIN group_members gm ON g.id = gm.group_id
      WHERE gm.user_id = $1 AND gm.status = 'active'
    `, [userId]);
        return result.rows;
    }
    checkRolePermission(role, permissionName) {
        // This would typically check the role's permissions
        // For now, we'll assume the role has the permission if it's in the role's permission list
        return role.permissions?.includes(permissionName) || false;
    }
};
exports.PermissionEvaluator = PermissionEvaluator;
__decorate([
    (0, inversify_1.inject)('DatabaseService'),
    __metadata("design:type", database_service_1.DatabaseService)
], PermissionEvaluator.prototype, "databaseService", void 0);
__decorate([
    (0, inversify_1.inject)('AuditService'),
    __metadata("design:type", audit_service_1.AuditService)
], PermissionEvaluator.prototype, "auditLogger", void 0);
__decorate([
    (0, inversify_1.inject)('OUContextValidator'),
    __metadata("design:type", ou_context_validator_service_1.OUContextValidator)
], PermissionEvaluator.prototype, "ouValidator", void 0);
exports.PermissionEvaluator = PermissionEvaluator = __decorate([
    (0, inversify_1.injectable)()
], PermissionEvaluator);
//# sourceMappingURL=permission-evaluator.service.js.map