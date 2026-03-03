import { injectable, inject } from 'inversify';
import { UUID, Group, User, GroupAccessValidation } from '../types';
import { DatabaseService } from './database.service';

@injectable()
export class GroupService {
  @inject('DatabaseService') private readonly databaseService!: DatabaseService;

  async getGroup(groupId: UUID): Promise<Group> {
    const result = await this.databaseService.query(
      'SELECT * FROM groups WHERE id = $1 AND status = $2',
      [groupId, 'active']
    );
    
    if (result.rows.length === 0) {
      throw new Error(`Group with ID ${groupId} not found`);
    }
    
    return result.rows[0];
  }

  async getUserGroups(userId: UUID): Promise<Group[]> {
    const result = await this.databaseService.query(`
      SELECT g.* FROM groups g
      JOIN group_members gm ON g.id = gm.group_id
      WHERE gm.user_id = $1 AND gm.status = 'active' AND g.status = 'active'
    `, [userId]);
    
    return result.rows;
  }

  async getGroupMembership(userId: UUID, groupId: UUID): Promise<any> {
    const result = await this.databaseService.query(`
      SELECT gm.* FROM group_members gm
      WHERE gm.user_id = $1 AND gm.group_id = $2 AND gm.status = 'active'
    `, [userId, groupId]);
    
    return result.rows[0] || null;
  }

  async validateUserGroupAccess(
    user: User, 
    groupId: UUID
  ): Promise<GroupAccessValidation> {
    // Check if user is owner of the group (supports multiple owners)
    const userRoles = await this.getUserRolesInGroup(user.id, groupId);
    const hasOwnerRole = userRoles.some(role => role.role_type === 'GROUP_OWNER');
    
    if (hasOwnerRole) {
      return { hasAccess: true, accessType: 'owner' };
    }
    
    // Check if user is manager of the group
    const hasManagerRole = userRoles.some(role => role.role_type === 'GROUP_MANAGER');
    if (hasManagerRole) {
      return { hasAccess: true, accessType: 'manager' };
    }
    
    // Check if user is member of the group
    const userGroups = await this.getUserGroups(user.id);
    const isInGroup = userGroups.some(g => g.id === groupId);
    
    if (isInGroup) {
      return { hasAccess: true, accessType: 'member' };
    }
    
    return { hasAccess: false, accessType: 'none' };
  }

  async getUserRolesInGroup(userId: UUID, groupId: UUID): Promise<any[]> {
    const result = await this.databaseService.query(`
      SELECT r.* FROM roles r
      JOIN user_roles ur ON r.id = ur.role_id
      WHERE ur.user_id = $1 AND ur.status = 'active'
      AND r.scope_type = 'group' AND r.scope_id = $2
    `, [userId, groupId]);
    
    return result.rows;
  }

  async createGroupScopedRole(
    groupId: UUID,
    roleDefinition: any,
    createdBy: UUID
  ): Promise<any> {
    // Validate group exists and creator has authority
    const group = await this.getGroup(groupId);
    const creatorAccess = await this.validateUserGroupAccess({ id: createdBy } as User, groupId);
    
    if (!creatorAccess.hasAccess || 
        creatorAccess.accessType !== 'owner' && 
        creatorAccess.accessType !== 'manager') {
      throw new Error(
        'Only group owners and managers can create group-scoped roles'
      );
    }
    
    // Create the group-scoped role
    const role: Partial<any> = {
      id: this.generateUUID(),
      organizationId: group.organizationId,
      name: roleDefinition.name,
      description: roleDefinition.description,
      type: 'custom',
      scopeType: 'group',
      scopeId: groupId,
      status: 'active',
      createdAt: new Date(),
      updatedAt: new Date()
    };
    
    const result = await this.databaseService.query(`
      INSERT INTO roles (id, organization_id, name, description, type, scope_type, scope_id, status, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING *
    `, [
      role.id,
      role.organizationId,
      role.name,
      role.description,
      role.type,
      role.scopeType,
      role.scopeId,
      role.status,
      role.createdAt,
      role.updatedAt
    ]);
    
    return result.rows[0];
  }

  async assignGroupScopedRole(
    groupId: UUID,
    userId: UUID,
    roleId: UUID,
    assignedBy: UUID
  ): Promise<any> {
    // Validate group membership
    const userGroups = await this.getUserGroups(userId);
    const isInGroup = userGroups.some(g => g.id === groupId);
    
    if (!isInGroup) {
      throw new Error(
        `User ${userId} is not a member of group ${groupId}`
      );
    }
    
    // Validate role is group-scoped for this group
    const result = await this.databaseService.query(
      'SELECT * FROM roles WHERE id = $1 AND scope_type = $2 AND scope_id = $3',
      [roleId, 'group', groupId]
    );
    
    if (result.rows.length === 0) {
      throw new Error(
        `Role ${roleId} is not a group-scoped role for group ${groupId}`
      );
    }
    
    // Create user role assignment
    const userRole: Partial<any> = {
      id: this.generateUUID(),
      userId: userId,
      roleId: roleId,
      assignedBy: assignedBy,
      assignedAt: new Date(),
      status: 'active',
      scopeContext: {
        scopeType: 'group',
        scopeId: groupId
      }
    };
    
    const insertResult = await this.databaseService.query(`
      INSERT INTO user_roles (id, user_id, role_id, assigned_by, assigned_at, status, scope_context)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *
    `, [
      userRole.id,
      userRole.userId,
      userRole.roleId,
      userRole.assignedBy,
      userRole.assignedAt,
      userRole.status,
      JSON.stringify(userRole.scopeContext)
    ]);
    
    return insertResult.rows[0];
  }

  private generateUUID(): UUID {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }
}