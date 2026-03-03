import { injectable, inject } from 'inversify';
import { DataAccessService } from './data-access.service';
import { UUID, ScopeType, UserRole, Role, User, ValidationError } from '../types';

@injectable()
export class ScopedRoleAssignmentService {
  @inject('DataAccessService') private readonly dataAccessService!: DataAccessService;

  async assignScopedRole(command: {
    userId: UUID;
    roleId: UUID;
    assignedBy: UUID;
    scopeType: ScopeType;
    scopeId?: UUID;
    expiresAt?: Date;
    reason?: string;
  }): Promise<UserRole> {
    return await this.dataAccessService.transaction(async (client) => {
      // Get role details
      const roleResult = await client.query(
        'SELECT * FROM roles WHERE id = $1 AND status = $2',
        [command.roleId, 'active']
      );

      if (roleResult.rows.length === 0) {
        throw new Error(`Role ${command.roleId} not found or inactive`);
      }

      const role: Role = roleResult.rows[0];

      // Validate scope type matches role
      if (role.scopeType !== command.scopeType) {
        throw new Error(
          `Role scope type ${role.scopeType} does not match assignment scope type ${command.scopeType}`
        );
      }

      // Validate assigner has permission to assign this role
      await this.validateRoleAssignmentAuthority(
        client,
        command.assignedBy,
        command.roleId,
        command.scopeType,
        command.scopeId
      );

      // Validate user belongs to the scope
      await this.validateUserInScope(
        client,
        command.userId,
        command.scopeType,
        command.scopeId
      );

      // Check if user already has this role in this scope
      const existingRoleResult = await client.query(
        `SELECT * FROM user_roles 
         WHERE user_id = $1 AND role_id = $2 AND scope_type = $3 
         AND scope_id = $4 AND status = $5`,
        [command.userId, command.roleId, command.scopeType, command.scopeId, 'active']
      );

      if (existingRoleResult.rows.length > 0) {
        throw new Error(
          `User ${command.userId} already has role ${command.roleId} in scope ${command.scopeId}`
        );
      }

      // Create user role assignment
      const userRoleResult = await client.query(
        `INSERT INTO user_roles 
         (user_id, role_id, assigned_by, scope_type, scope_id, expires_at, reason, status, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
         RETURNING *`,
        [
          command.userId,
          command.roleId,
          command.assignedBy,
          command.scopeType,
          command.scopeId,
          command.expiresAt,
          command.reason,
          'active'
        ]
      );

      const userRole: UserRole = userRoleResult.rows[0];

      // Log the assignment
      await this.logRoleAssignment(
        client,
        command.assignedBy,
        command.userId,
        command.roleId,
        'assigned',
        command.scopeType,
        command.scopeId,
        command.reason
      );

      return userRole;
    });
  }

  async revokeScopedRole(command: {
    userId: UUID;
    roleId: UUID;
    revokedBy: UUID;
    scopeType: ScopeType;
    scopeId?: UUID;
    reason?: string;
  }): Promise<void> {
    return await this.dataAccessService.transaction(async (client) => {
      // Validate revoker has permission to revoke this role
      await this.validateRoleRevocationAuthority(
        client,
        command.revokedBy,
        command.roleId,
        command.scopeType,
        command.scopeId
      );

      // Update user role status to revoked
      const result = await client.query(
        `UPDATE user_roles 
         SET status = $1, updated_at = NOW()
         WHERE user_id = $2 AND role_id = $3 AND scope_type = $4 
         AND scope_id = $5 AND status = $6`,
        ['revoked', command.userId, command.roleId, command.scopeType, command.scopeId, 'active']
      );

      if (result.rowCount === 0) {
        throw new Error(
          `No active role assignment found for user ${command.userId} with role ${command.roleId} in scope ${command.scopeId}`
        );
      }

      // Log the revocation
      await this.logRoleAssignment(
        client,
        command.revokedBy,
        command.userId,
        command.roleId,
        'revoked',
        command.scopeType,
        command.scopeId,
        command.reason
      );
    });
  }

  async getUserScopedRoles(userId: UUID, scopeType: ScopeType, scopeId?: UUID): Promise<UserRole[]> {
    let query = `
      SELECT ur.*, r.name as role_name, r.description as role_description
      FROM user_roles ur
      JOIN roles r ON ur.role_id = r.id
      WHERE ur.user_id = $1 AND ur.status = $2 AND ur.scope_type = $3
    `;
    const params = [userId, 'active', scopeType];

    if (scopeId) {
      query += ' AND ur.scope_id = $4';
      params.push(scopeId);
    }

    const result = await this.dataAccessService.query(query, params);
    return result.rows;
  }

  private async validateRoleAssignmentAuthority(
    client: any,
    assignerId: UUID,
    roleId: UUID,
    scopeType: ScopeType,
    scopeId?: UUID
  ): Promise<void> {
    // Check if assigner has permission to assign roles
    const permissions = await this.getUserPermissionsInScope(client, assignerId, scopeType, scopeId);
    
    const hasAssignPermission = permissions.some((p: any) => 
      p.permission_name === 'assign_roles' || p.permission_name === 'manage_roles'
    );

    if (!hasAssignPermission) {
        throw new Error(
        `User ${assignerId} does not have permission to assign roles in scope ${scopeId}`
      );
    }
  }

  private async validateRoleRevocationAuthority(
    client: any,
    revokerId: UUID,
    roleId: UUID,
    scopeType: ScopeType,
    scopeId?: UUID
  ): Promise<void> {
    // Check if revoker has permission to revoke roles
    const permissions = await this.getUserPermissionsInScope(client, revokerId, scopeType, scopeId);
    
    const hasRevokePermission = permissions.some((p: any) => 
      p.permission_name === 'revoke_roles' || p.permission_name === 'manage_roles'
    );

    if (!hasRevokePermission) {
        throw new Error(
        `User ${revokerId} does not have permission to revoke roles in scope ${scopeId}`
      );
    }
  }

  private async validateUserInScope(
    client: any,
    userId: UUID,
    scopeType: ScopeType,
    scopeId?: UUID
  ): Promise<void> {
    switch (scopeType) {
      case 'organization':
        // User should belong to the organization
        const orgResult = await client.query(
          'SELECT id FROM users WHERE id = $1 AND status = $2',
          [userId, 'active']
        );
        if (orgResult.rows.length === 0) {
        throw new Error(`User ${userId} not found or inactive`);
        }
        break;

      case 'group':
        if (!scopeId) {
        throw new Error('Group scope requires scope_id');
        }
        // Check if user is member of the group
        const groupResult = await client.query(
          `SELECT gm.id FROM group_members gm
           WHERE gm.user_id = $1 AND gm.group_id = $2 AND gm.status = $3`,
          [userId, scopeId, 'active']
        );
        if (groupResult.rows.length === 0) {
        throw new Error(
            `User ${userId} is not a member of group ${scopeId}`
          );
        }
        break;

      case 'organization_unit':
        if (!scopeId) {
        throw new Error('Organization unit scope requires scope_id');
        }
        // Check if user belongs to the organization unit
        const ouResult = await client.query(
          'SELECT id FROM users WHERE id = $1 AND organization_unit_id = $2 AND status = $3',
          [userId, scopeId, 'active']
        );
        if (ouResult.rows.length === 0) {
        throw new Error(
            `User ${userId} does not belong to organization unit ${scopeId}`
          );
        }
        break;
    }
  }

  private async getUserPermissionsInScope(
    client: any,
    userId: UUID,
    scopeType: ScopeType,
    scopeId?: UUID
  ): Promise<any[]> {
    let query = `
      SELECT DISTINCT p.permission_name, p.description
      FROM user_roles ur
      JOIN role_permissions rp ON ur.role_id = rp.role_id
      JOIN permissions p ON rp.permission_id = p.id
      WHERE ur.user_id = $1 AND ur.status = $2 AND ur.scope_type = $3
    `;
    const params = [userId, 'active', scopeType];

    if (scopeId) {
      query += ' AND ur.scope_id = $4';
      params.push(scopeId);
    }

    const result = await client.query(query, params);
    return result.rows;
  }

  private async logRoleAssignment(
    client: any,
    actorId: UUID,
    targetUserId: UUID,
    roleId: UUID,
    action: 'assigned' | 'revoked',
    scopeType: ScopeType,
    scopeId?: UUID,
    reason?: string
  ): Promise<void> {
    await client.query(
      `INSERT INTO audit_logs 
       (actor_id, action, resource_type, resource_id, details, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW())`,
      [
        actorId,
        action,
        'user_role',
        `${targetUserId}:${roleId}`,
        JSON.stringify({
          targetUserId,
          roleId,
          scopeType,
          scopeId,
          reason
        })
      ]
    );
  }
}
