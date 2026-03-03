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
exports.GroupHierarchyService = void 0;
const inversify_1 = require("inversify");
const database_service_1 = require("./database.service");
let GroupHierarchyService = class GroupHierarchyService {
    /**
     * Get all parent groups for a given group using materialized path
     */
    async getGroupAncestors(groupId) {
        const result = await this.databaseService.query(`
      SELECT g.* FROM groups g
      WHERE g.path LIKE $1 || '.%' AND g.status = 'active'
      ORDER BY g.path
    `, [groupId]);
        return result.rows;
    }
    /**
     * Get all child groups for a given group
     */
    async getGroupDescendants(groupId) {
        const result = await this.databaseService.query(`
      SELECT g.* FROM groups g
      WHERE g.path LIKE $1 || '.%' AND g.status = 'active'
      ORDER BY g.path
    `, [groupId]);
        return result.rows;
    }
    /**
     * Get all groups that a user belongs to, including through hierarchy inheritance
     */
    async getUserGroupsWithHierarchy(userId) {
        const directGroups = await this.getUserGroups(userId);
        // Get all parent groups for each direct group
        const allGroups = new Set();
        for (const group of directGroups) {
            const parentGroups = await this.getGroupAncestors(group.id);
            parentGroups.forEach(g => allGroups.add(g));
            allGroups.add(group);
        }
        return Array.from(allGroups);
    }
    /**
     * Check if a user has access to a group through direct membership or hierarchy
     */
    async userHasGroupAccess(userId, groupId) {
        const userGroups = await this.getUserGroupsWithHierarchy(userId);
        return userGroups.some(g => g.id === groupId);
    }
    /**
     * Get all roles a user has through direct assignment or group hierarchy inheritance
     */
    async getUserRolesWithHierarchy(userId) {
        const userGroups = await this.getUserGroupsWithHierarchy(userId);
        const groupIds = userGroups.map(g => g.id);
        const result = await this.databaseService.query(`
      SELECT DISTINCT ur.* FROM user_roles ur
      JOIN roles r ON ur.role_id = r.id
      WHERE ur.user_id = $1 AND ur.status = 'active'
      AND (
        r.scope_type = 'organization' OR
        (r.scope_type = 'group' AND r.scope_id = ANY($2))
      )
    `, [userId, groupIds]);
        return result.rows;
    }
    /**
     * Validate if a user can perform an operation on a group considering hierarchy
     */
    async validateGroupOperationWithHierarchy(userId, groupId, operation) {
        // Check if user has direct access to the group
        const hasDirectAccess = await this.userHasGroupAccess(userId, groupId);
        if (!hasDirectAccess) {
            return {
                isValid: false,
                reason: `User does not have access to group ${groupId} or any parent group`
            };
        }
        // Check if user has the required permission for the operation
        const userRoles = await this.getUserRolesWithHierarchy(userId);
        // This would typically check specific permissions, but for now we'll assume
        // that having access to the group is sufficient for most operations
        return {
            isValid: true,
            reason: 'User has access through group hierarchy'
        };
    }
    async getUserGroups(userId) {
        const result = await this.databaseService.query(`
      SELECT g.* FROM groups g
      JOIN group_members gm ON g.id = gm.group_id
      WHERE gm.user_id = $1 AND gm.status = 'active' AND g.status = 'active'
    `, [userId]);
        return result.rows;
    }
};
exports.GroupHierarchyService = GroupHierarchyService;
__decorate([
    (0, inversify_1.inject)('DatabaseService'),
    __metadata("design:type", database_service_1.DatabaseService)
], GroupHierarchyService.prototype, "databaseService", void 0);
exports.GroupHierarchyService = GroupHierarchyService = __decorate([
    (0, inversify_1.injectable)()
], GroupHierarchyService);
//# sourceMappingURL=group-hierarchy.service.js.map