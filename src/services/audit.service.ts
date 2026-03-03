import { injectable, inject } from 'inversify';
import { DatabaseService } from './database.service';
import { UUID, PermissionContext, UserRole } from '../types';

@injectable()
export class AuditService {
  @inject('DatabaseService') private readonly databaseService!: DatabaseService;

  async logScopedRoleAssignment(userRole: UserRole): Promise<void> {
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

  async logScopeViolation(
    userId: UUID,
    roleId: UUID,
    context: PermissionContext,
    violationType: string
  ): Promise<void> {
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

  async logPermissionViolation(
    userId: UUID,
    permissionName: string,
    reason: string
  ): Promise<void> {
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

  async logRoleAssignment(
    assignedBy: UUID,
    userId: UUID,
    roleId: UUID,
    status: 'SUCCESS' | 'FAILED',
    reason: string
  ): Promise<void> {
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

  async logRoleRevocation(
    revokedBy: UUID,
    userId: UUID,
    roleId: UUID,
    status: 'SUCCESS' | 'FAILED',
    reason: string
  ): Promise<void> {
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
}