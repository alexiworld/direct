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
exports.RoleAssignmentService = void 0;
const inversify_1 = require("inversify");
const types_1 = require("../types");
const database_service_1 = require("./database.service");
const audit_service_1 = require("./audit.service");
const ou_context_validator_service_1 = require("./ou-context-validator.service");
let RoleAssignmentService = class RoleAssignmentService {
    async assignScopedRole(userId, roleId, assignedBy, context) {
        const user = await this.getUser(userId);
        const role = await this.getRole(roleId);
        const assigner = await this.getUser(assignedBy);
        try {
            // 1. Validate organization isolation
            if (user.organizationId !== role.organizationId) {
                throw new Error('User and role must belong to the same organization');
            }
            // 2. Validate assigner permissions
            await this.validateAssignmentPermissions(assigner, role, context);
            // 3. Validate scope-specific requirements
            await this.validateScopeRequirements(user, role, context);
            // 4. Create role assignment
            const userRole = await this.createUserRoleAssignment(userId, roleId, assignedBy);
            // 5. Log successful assignment
            await this.auditLogger.logRoleAssignment(assignedBy, userId, roleId, 'SUCCESS', context?.reason || 'Scoped role assignment');
            return {
                userRole,
                success: true,
                message: 'Role assigned successfully'
            };
        }
        catch (error) {
            // Log failed assignment
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            await this.auditLogger.logRoleAssignment(assignedBy, userId, roleId, 'FAILED', errorMessage);
            return {
                userRole: {},
                success: false,
                message: error.message
            };
        }
    }
    async revokeScopedRole(userId, roleId, revokedBy, reason) {
        const user = await this.getUser(userId);
        const role = await this.getRole(roleId);
        const revoker = await this.getUser(revokedBy);
        try {
            // 1. Validate organization isolation
            if (user.organizationId !== role.organizationId) {
                throw new Error('User and role must belong to the same organization');
            }
            // 2. Validate revoker permissions
            await this.validateRevocationPermissions(revoker, role, userId);
            // 3. Revoke role assignment
            await this.revokeUserRoleAssignment(userId, roleId);
            // 4. Log successful revocation
            await this.auditLogger.logRoleRevocation(revokedBy, userId, roleId, 'SUCCESS', reason || 'Scoped role revocation');
            return {
                userRole: {},
                success: true,
                message: 'Role revoked successfully'
            };
        }
        catch (error) {
            // Log failed revocation
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            await this.auditLogger.logRoleRevocation(revokedBy, userId, roleId, 'FAILED', errorMessage);
            return {
                userRole: {},
                success: false,
                message: error.message
            };
        }
    }
    async validateAssignmentPermissions(assigner, role, context) {
        // Check if assigner has permission to assign roles
        const assignerPermissions = await this.getUserPermissions(assigner.id);
        if (!assignerPermissions.includes('assign_roles')) {
            throw new Error('Assigner does not have permission to assign roles');
        }
        // For scoped roles, check if assigner has appropriate scope permissions
        if (role.scopeType !== types_1.ScopeType.ORGANIZATION) {
            await this.validateScopePermissions(assigner, role, context);
        }
    }
    async validateRevocationPermissions(revoker, role, targetUserId) {
        // Check if revoker has permission to revoke roles
        const revokerPermissions = await this.getUserPermissions(revoker.id);
        if (!revokerPermissions.includes('revoke_roles')) {
            throw new Error('Revoker does not have permission to revoke roles');
        }
        // For scoped roles, check if revoker has appropriate scope permissions
        if (role.scopeType !== types_1.ScopeType.ORGANIZATION) {
            await this.validateRevocationScopePermissions(revoker, role, targetUserId);
        }
    }
    async validateScopePermissions(assigner, role, context) {
        switch (role.scopeType) {
            case types_1.ScopeType.GROUP:
                await this.validateGroupAssignmentPermissions(assigner, role, context);
                break;
            case types_1.ScopeType.ORGANIZATION_UNIT:
                await this.validateOrganizationUnitAssignmentPermissions(assigner, role, context);
                break;
            default:
                throw new Error(`Invalid scope type: ${role.scopeType}`);
        }
    }
    async validateRevocationScopePermissions(revoker, role, targetUserId) {
        switch (role.scopeType) {
            case types_1.ScopeType.GROUP:
                await this.validateGroupRevocationPermissions(revoker, role, targetUserId);
                break;
            case types_1.ScopeType.ORGANIZATION_UNIT:
                await this.validateOrganizationUnitRevocationPermissions(revoker, role, targetUserId);
                break;
            default:
                throw new Error(`Invalid scope type: ${role.scopeType}`);
        }
    }
    async validateGroupAssignmentPermissions(assigner, role, context) {
        // Check if assigner is owner or manager of the group
        const groupMemberships = await this.getGroupMemberships(assigner.id, role.scopeId);
        const membership = groupMemberships.find(m => m.groupId === role.scopeId);
        if (!membership || (membership.roleInGroup !== 'owner' && membership.roleInGroup !== 'manager')) {
            throw new Error('Assigner must be group owner or manager to assign group-scoped roles');
        }
        // Check if assigner has the role being assigned (for non-admin roles)
        const assignerRoles = await this.getUserRoles(assigner.id);
        const hasRole = assignerRoles.some(userRole => userRole.name === role.name || userRole.name === 'GROUP_OWNER');
        if (!hasRole && !this.hasAdminRole(assigner)) {
            throw new Error('Assigner must have the role being assigned');
        }
    }
    async validateOrganizationUnitAssignmentPermissions(assigner, role, context) {
        // Check if assigner is owner or manager of the organization unit
        const assignerAccess = await this.ouValidator.validateUserOUAccess(assigner, role.scopeId);
        if (assignerAccess.accessType !== 'owner' && assignerAccess.accessType !== 'manager') {
            throw new Error('Assigner must be organization unit owner or manager to assign unit-scoped roles');
        }
        // Check if assigner has the role being assigned (for non-admin roles)
        const assignerRoles = await this.getUserRoles(assigner.id);
        const hasRole = assignerRoles.some(userRole => userRole.name === role.name || userRole.name === 'OU_OWNER' || userRole.name === 'OU_MANAGER');
        if (!hasRole && !this.hasAdminRole(assigner)) {
            throw new Error('Assigner must have the role being assigned');
        }
    }
    async validateGroupRevocationPermissions(revoker, role, targetUserId) {
        // Check if revoker is owner or manager of the group
        const groupMemberships = await this.getGroupMemberships(revoker.id, role.scopeId);
        const membership = groupMemberships.find(m => m.groupId === role.scopeId);
        if (!membership || (membership.roleInGroup !== 'owner' && membership.roleInGroup !== 'manager')) {
            throw new Error('Revoker must be group owner or manager to revoke group-scoped roles');
        }
        // Check if revoker has the role being revoked (for non-admin roles)
        const revokerRoles = await this.getUserRoles(revoker.id);
        const hasRole = revokerRoles.some(userRole => userRole.name === role.name || userRole.name === 'GROUP_OWNER');
        if (!hasRole && !this.hasAdminRole(revoker)) {
            throw new Error('Revoker must have the role being revoked');
        }
    }
    async validateOrganizationUnitRevocationPermissions(revoker, role, targetUserId) {
        // Check if revoker is owner or manager of the organization unit
        const revokerAccess = await this.ouValidator.validateUserOUAccess(revoker, role.scopeId);
        if (revokerAccess.accessType !== 'owner' && revokerAccess.accessType !== 'manager') {
            throw new Error('Revoker must be organization unit owner or manager to revoke unit-scoped roles');
        }
        // Check if revoker has the role being revoked (for non-admin roles)
        const revokerRoles = await this.getUserRoles(revoker.id);
        const hasRole = revokerRoles.some(userRole => userRole.name === role.name || userRole.name === 'OU_OWNER' || userRole.name === 'OU_MANAGER');
        if (!hasRole && !this.hasAdminRole(revoker)) {
            throw new Error('Revoker must have the role being revoked');
        }
    }
    async validateScopeRequirements(user, role, context) {
        switch (role.scopeType) {
            case types_1.ScopeType.GROUP:
                await this.validateGroupScopeRequirements(user, role);
                break;
            case types_1.ScopeType.ORGANIZATION_UNIT:
                await this.validateOrganizationUnitScopeRequirements(user, role);
                break;
            case types_1.ScopeType.ORGANIZATION:
                // No additional requirements for organization-level roles
                break;
        }
    }
    async validateGroupScopeRequirements(user, role) {
        // User must be a member of the group to receive group-scoped roles
        const userGroups = await this.getUserGroups(user.id);
        const isInGroup = userGroups.some(g => g.id === role.scopeId);
        if (!isInGroup) {
            throw new Error('User must be a member of the group to receive this scoped role');
        }
    }
    async validateOrganizationUnitScopeRequirements(user, role) {
        // User must belong to the organization unit to receive unit-scoped roles
        if (user.organizationUnitId !== role.scopeId) {
            throw new Error('User must belong to the organization unit to receive this scoped role');
        }
    }
    async createUserRoleAssignment(userId, roleId, assignedBy) {
        const userRole = {
            id: this.generateUUID(),
            userId,
            roleId,
            assignedBy,
            assignedAt: new Date(),
            status: 'active',
            createdAt: new Date(),
            updatedAt: new Date()
        };
        const result = await this.databaseService.query(`
      INSERT INTO user_roles (id, user_id, role_id, assigned_by, assigned_at, status, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
    `, [
            userRole.id,
            userRole.userId,
            userRole.roleId,
            userRole.assignedBy,
            userRole.assignedAt,
            userRole.status,
            userRole.createdAt,
            userRole.updatedAt
        ]);
        return result.rows[0];
    }
    async revokeUserRoleAssignment(userId, roleId) {
        await this.databaseService.query(`
      UPDATE user_roles 
      SET status = 'inactive', updated_at = $1
      WHERE user_id = $2 AND role_id = $3 AND status = 'active'
    `, [new Date(), userId, roleId]);
    }
    async getUser(userId) {
        const result = await this.databaseService.query('SELECT * FROM users WHERE id = $1', [userId]);
        return result.rows[0];
    }
    async getRole(roleId) {
        const result = await this.databaseService.query('SELECT * FROM roles WHERE id = $1', [roleId]);
        return result.rows[0];
    }
    async getUserPermissions(userId) {
        const result = await this.databaseService.query(`
      SELECT DISTINCT p.name 
      FROM permissions p
      JOIN role_permissions rp ON p.id = rp.permission_id
      JOIN user_roles ur ON rp.role_id = ur.role_id
      WHERE ur.user_id = $1 AND ur.status = 'active'
    `, [userId]);
        return result.rows.map((row) => row.name);
    }
    async getUserRoles(userId) {
        const result = await this.databaseService.query(`
      SELECT ur.* FROM user_roles ur
      WHERE ur.user_id = $1 AND ur.status = 'active'
    `, [userId]);
        return result.rows;
    }
    async getGroupMemberships(userId, groupId) {
        const result = await this.databaseService.query(`
      SELECT gm.* FROM group_members gm
      WHERE gm.user_id = $1 AND gm.group_id = $2 AND gm.status = 'active'
    `, [userId, groupId]);
        return result.rows;
    }
    async getUserGroups(userId) {
        const result = await this.databaseService.query(`
      SELECT g.* FROM groups g
      JOIN group_members gm ON g.id = gm.group_id
      WHERE gm.user_id = $1 AND gm.status = 'active'
    `, [userId]);
        return result.rows;
    }
    hasAdminRole(user) {
        // This would typically check the user's roles
        // For now, we'll assume it's implemented elsewhere
        return false;
    }
    generateUUID() {
        // Simple UUID generation for demo purposes
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
            const r = Math.random() * 16 | 0;
            const v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }
};
exports.RoleAssignmentService = RoleAssignmentService;
__decorate([
    (0, inversify_1.inject)('DatabaseService'),
    __metadata("design:type", database_service_1.DatabaseService)
], RoleAssignmentService.prototype, "databaseService", void 0);
__decorate([
    (0, inversify_1.inject)('AuditService'),
    __metadata("design:type", audit_service_1.AuditService)
], RoleAssignmentService.prototype, "auditLogger", void 0);
__decorate([
    (0, inversify_1.inject)('OUContextValidator'),
    __metadata("design:type", ou_context_validator_service_1.OUContextValidator)
], RoleAssignmentService.prototype, "ouValidator", void 0);
exports.RoleAssignmentService = RoleAssignmentService = __decorate([
    (0, inversify_1.injectable)()
], RoleAssignmentService);
//# sourceMappingURL=role-assignment.service.js.map