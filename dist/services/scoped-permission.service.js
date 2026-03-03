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
exports.ScopedPermissionService = void 0;
const inversify_1 = require("inversify");
const types_1 = require("../types");
const database_service_1 = require("./database.service");
const group_service_1 = require("./group.service");
let ScopedPermissionService = class ScopedPermissionService {
    /**
     * Evaluate if a user has a specific permission within a given context
     */
    async hasPermission(userId, permissionName, context) {
        const userRoles = await this.getUserRoles(userId);
        for (const userRole of userRoles) {
            const role = await this.getRole(userRole.roleId);
            // Check if role has the requested permission
            const hasPermission = await this.checkRolePermission(role, permissionName);
            if (hasPermission) {
                // Validate scope context
                const scopeValid = await this.validatePermissionScope(role, context);
                if (scopeValid) {
                    return true;
                }
            }
        }
        return false;
    }
    /**
     * Get all permissions a user has within a specific scope
     */
    async getUserPermissionsInScope(userId, scopeType, scopeId) {
        const userRoles = await this.getUserRoles(userId);
        const permissions = new Set();
        for (const userRole of userRoles) {
            const role = await this.getRole(userRole.roleId);
            // Check if role applies to this scope
            if (this.roleAppliesToScope(role, scopeType, scopeId)) {
                const rolePermissions = await this.getRolePermissions(role.id);
                rolePermissions.forEach(p => permissions.add(p.name));
            }
        }
        return Array.from(permissions);
    }
    async validatePermissionScope(role, context) {
        // If role is organization-level, no scope validation needed
        if (role.scopeType === types_1.ScopeType.ORGANIZATION) {
            return true;
        }
        // If no context provided, scoped permissions cannot be evaluated
        if (!context) {
            return false;
        }
        // Validate scope matches
        if (role.scopeType !== context.scopeType || role.scopeId !== context.scopeId) {
            return false;
        }
        // Additional context-specific validation
        return await this.validateContextSpecificRules(role, context);
    }
    async validateContextSpecificRules(role, context) {
        switch (role.scopeType) {
            case types_1.ScopeType.GROUP:
                return this.validateGroupContext(role, context);
            case types_1.ScopeType.ORGANIZATION_UNIT:
                return this.validateOrganizationUnitContext(role, context);
            default:
                return false;
        }
    }
    async validateGroupContext(role, context) {
        // Check if user is still in the group
        const userGroups = await this.groupService.getUserGroups(context.userId);
        const isInGroup = userGroups.some(g => g.id === role.scopeId);
        if (!isInGroup) {
            return false;
        }
        // Additional group-specific validation could go here
        // For example, checking if the target resource belongs to the group
        return true;
    }
    async validateOrganizationUnitContext(role, context) {
        // Check if user still belongs to the organization unit
        const user = await this.getUser(context.userId);
        if (user.organizationUnitId !== role.scopeId) {
            return false;
        }
        // Additional organization unit-specific validation could go here
        return true;
    }
    roleAppliesToScope(role, scopeType, scopeId) {
        // Organization-level roles apply everywhere
        if (role.scopeType === types_1.ScopeType.ORGANIZATION) {
            return true;
        }
        // Scoped roles only apply to their specific scope
        return role.scopeType === scopeType && role.scopeId === scopeId;
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
    async checkRolePermission(role, permissionName) {
        const result = await this.databaseService.query(`
      SELECT COUNT(*) as count FROM role_permissions rp
      JOIN permissions p ON rp.permission_id = p.id
      WHERE rp.role_id = $1 AND p.name = $2 AND rp.status = 'active'
    `, [role.id, permissionName]);
        return parseInt(result.rows[0].count) > 0;
    }
    async getRolePermissions(roleId) {
        const result = await this.databaseService.query(`
      SELECT p.* FROM permissions p
      JOIN role_permissions rp ON p.id = rp.permission_id
      WHERE rp.role_id = $1 AND rp.status = 'active'
    `, [roleId]);
        return result.rows;
    }
    async getUser(userId) {
        const result = await this.databaseService.query('SELECT * FROM users WHERE id = $1', [userId]);
        return result.rows[0];
    }
};
exports.ScopedPermissionService = ScopedPermissionService;
__decorate([
    (0, inversify_1.inject)('DatabaseService'),
    __metadata("design:type", database_service_1.DatabaseService)
], ScopedPermissionService.prototype, "databaseService", void 0);
__decorate([
    (0, inversify_1.inject)('GroupService'),
    __metadata("design:type", group_service_1.GroupService)
], ScopedPermissionService.prototype, "groupService", void 0);
exports.ScopedPermissionService = ScopedPermissionService = __decorate([
    (0, inversify_1.injectable)()
], ScopedPermissionService);
//# sourceMappingURL=scoped-permission.service.js.map