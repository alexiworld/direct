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
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ScopedRoleController = void 0;
const common_1 = require("@nestjs/common");
const passport_1 = require("@nestjs/passport");
const has_permission_decorator_1 = require("../decorators/has-permission.decorator");
const scoped_role_assignment_service_1 = require("../services/scoped-role-assignment.service");
const scoped_permission_service_1 = require("../services/scoped-permission.service");
let ScopedRoleController = class ScopedRoleController {
    constructor(scopedRoleService, permissionService) {
        this.scopedRoleService = scopedRoleService;
        this.permissionService = permissionService;
    }
    async assignScopedRole(orgId, userId, assignCommand, req) {
        // Validate organization isolation
        const user = await this.getUser(userId);
        if (user.organizationId !== orgId) {
            throw new Error('User does not belong to the specified organization');
        }
        const command = {
            userId: userId,
            roleId: assignCommand.roleId,
            assignedBy: req.user.id,
            scopeType: assignCommand.scopeType,
            expiresAt: assignCommand.expiresAt,
            reason: assignCommand.reason
        };
        return await this.scopedRoleService.assignScopedRole(command);
    }
    async checkPermission(userId, request) {
        const hasPermission = await this.permissionService.hasPermission(userId, request.permission, request.context);
        return { hasPermission };
    }
    async getPermissionsInScope(userId, request) {
        const permissions = await this.permissionService.getUserPermissionsInScope(userId, request.scopeType, request.scopeId);
        return { permissions };
    }
    async getUser(userId) {
        // This would typically be injected from a UserService
        // For now, returning a mock structure
        return {
            id: userId,
            organizationId: 'org-uuid'
        };
    }
};
exports.ScopedRoleController = ScopedRoleController;
__decorate([
    (0, common_1.Post)('scoped'),
    (0, common_1.UseGuards)(passport_1.AuthGuard),
    (0, has_permission_decorator_1.HasPermission)('assign_roles_to_users'),
    __param(0, (0, common_1.Param)('orgId')),
    __param(1, (0, common_1.Param)('userId')),
    __param(2, (0, common_1.Body)()),
    __param(3, (0, common_1.Request)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object, Object]),
    __metadata("design:returntype", Promise)
], ScopedRoleController.prototype, "assignScopedRole", null);
__decorate([
    (0, common_1.Post)('check-permission'),
    (0, common_1.UseGuards)(passport_1.AuthGuard),
    __param(0, (0, common_1.Param)('userId')),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], ScopedRoleController.prototype, "checkPermission", null);
__decorate([
    (0, common_1.Post)('permissions-in-scope'),
    (0, common_1.UseGuards)(passport_1.AuthGuard),
    __param(0, (0, common_1.Param)('userId')),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], ScopedRoleController.prototype, "getPermissionsInScope", null);
exports.ScopedRoleController = ScopedRoleController = __decorate([
    (0, common_1.Controller)('organizations/:orgId/users/:userId/roles'),
    __metadata("design:paramtypes", [scoped_role_assignment_service_1.ScopedRoleAssignmentService,
        scoped_permission_service_1.ScopedPermissionService])
], ScopedRoleController);
//# sourceMappingURL=scoped-role.controller.js.map