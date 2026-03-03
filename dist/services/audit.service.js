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
exports.AuditService = void 0;
const inversify_1 = require("inversify");
const database_service_1 = require("./database.service");
let AuditService = class AuditService {
    async logScopedRoleAssignment(userRole) {
        const auditEntry = {
            user_id: userRole.userId,
            action: 'ASSIGN_SCOPED_ROLE',
            resource_type: 'USER_ROLE',
            resource_id: userRole.id,
            resource_name: `Role assignment for user ${userRole.userId}`,
            new_values: JSON.stringify({
                roleId: userRole.roleId,
                assignedBy: userRole.assignedBy,
                assignedAt: userRole.assignedAt,
                scopeContext: userRole.scopeType || 'organization'
            }),
            ip_address: null, // Would be passed from request context
            user_agent: null, // Would be passed from request context
            request_id: null, // Would be passed from request context
            created_at: new Date()
        };
        await this.databaseService.query(`
      INSERT INTO audit_logs (
        user_id, action, resource_type, resource_id, resource_name,
        new_values, ip_address, user_agent, request_id, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    `, [
            auditEntry.user_id,
            auditEntry.action,
            auditEntry.resource_type,
            auditEntry.resource_id,
            auditEntry.resource_name,
            auditEntry.new_values,
            auditEntry.ip_address,
            auditEntry.user_agent,
            auditEntry.request_id,
            auditEntry.created_at
        ]);
    }
    async logScopeViolation(userId, roleId, context, violationType) {
        const auditEntry = {
            user_id: userId,
            action: 'SCOPE_VIOLATION',
            resource_type: 'PERMISSION_CHECK',
            resource_id: roleId,
            resource_name: `Permission check for user ${userId}`,
            new_values: JSON.stringify({
                context,
                violationType,
                timestamp: new Date()
            }),
            ip_address: null,
            user_agent: null,
            request_id: null,
            created_at: new Date()
        };
        await this.databaseService.query(`
      INSERT INTO audit_logs (
        user_id, action, resource_type, resource_id, resource_name,
        new_values, ip_address, user_agent, request_id, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    `, [
            auditEntry.user_id,
            auditEntry.action,
            auditEntry.resource_type,
            auditEntry.resource_id,
            auditEntry.resource_name,
            auditEntry.new_values,
            auditEntry.ip_address,
            auditEntry.user_agent,
            auditEntry.request_id,
            auditEntry.created_at
        ]);
    }
    async logPermissionViolation(userId, permissionName, reason) {
        const auditEntry = {
            user_id: userId,
            action: 'PERMISSION_VIOLATION',
            resource_type: 'PERMISSION_CHECK',
            resource_id: null,
            resource_name: `Permission check for user ${userId}`,
            new_values: JSON.stringify({
                permissionName,
                reason,
                timestamp: new Date()
            }),
            ip_address: null,
            user_agent: null,
            request_id: null,
            created_at: new Date()
        };
        await this.databaseService.query(`
      INSERT INTO audit_logs (
        user_id, action, resource_type, resource_id, resource_name,
        new_values, ip_address, user_agent, request_id, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    `, [
            auditEntry.user_id,
            auditEntry.action,
            auditEntry.resource_type,
            auditEntry.resource_id,
            auditEntry.resource_name,
            auditEntry.new_values,
            auditEntry.ip_address,
            auditEntry.user_agent,
            auditEntry.request_id,
            auditEntry.created_at
        ]);
    }
    async logRoleAssignment(assignedBy, userId, roleId, status, reason) {
        const auditEntry = {
            user_id: assignedBy,
            action: 'ROLE_ASSIGNMENT',
            resource_type: 'USER_ROLE',
            resource_id: roleId,
            resource_name: `Role assignment for user ${userId}`,
            new_values: JSON.stringify({
                userId,
                roleId,
                status,
                reason,
                timestamp: new Date()
            }),
            ip_address: null,
            user_agent: null,
            request_id: null,
            created_at: new Date()
        };
        await this.databaseService.query(`
      INSERT INTO audit_logs (
        user_id, action, resource_type, resource_id, resource_name,
        new_values, ip_address, user_agent, request_id, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    `, [
            auditEntry.user_id,
            auditEntry.action,
            auditEntry.resource_type,
            auditEntry.resource_id,
            auditEntry.resource_name,
            auditEntry.new_values,
            auditEntry.ip_address,
            auditEntry.user_agent,
            auditEntry.request_id,
            auditEntry.created_at
        ]);
    }
    async logRoleRevocation(revokedBy, userId, roleId, status, reason) {
        const auditEntry = {
            user_id: revokedBy,
            action: 'ROLE_REVOCATION',
            resource_type: 'USER_ROLE',
            resource_id: roleId,
            resource_name: `Role revocation for user ${userId}`,
            new_values: JSON.stringify({
                userId,
                roleId,
                status,
                reason,
                timestamp: new Date()
            }),
            ip_address: null,
            user_agent: null,
            request_id: null,
            created_at: new Date()
        };
        await this.databaseService.query(`
      INSERT INTO audit_logs (
        user_id, action, resource_type, resource_id, resource_name,
        new_values, ip_address, user_agent, request_id, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    `, [
            auditEntry.user_id,
            auditEntry.action,
            auditEntry.resource_type,
            auditEntry.resource_id,
            auditEntry.resource_name,
            auditEntry.new_values,
            auditEntry.ip_address,
            auditEntry.user_agent,
            auditEntry.request_id,
            auditEntry.created_at
        ]);
    }
};
exports.AuditService = AuditService;
__decorate([
    (0, inversify_1.inject)('DatabaseService'),
    __metadata("design:type", database_service_1.DatabaseService)
], AuditService.prototype, "databaseService", void 0);
exports.AuditService = AuditService = __decorate([
    (0, inversify_1.injectable)()
], AuditService);
//# sourceMappingURL=audit.service.js.map