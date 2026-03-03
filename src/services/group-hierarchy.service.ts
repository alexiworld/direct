import { injectable, inject } from 'inversify';
import { UUID, Group } from '../types';
import { DatabaseService } from './database.service';

@injectable()
export class GroupHierarchyService {
  @inject('DatabaseService') private readonly databaseService!: DatabaseService;

  /**
   * Get all parent groups for a given group using materialized path
   */
  async getGroupAncestors(groupId: UUID): Promise<Group[]> {
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
  async getGroupDescendants(groupId: UUID): Promise<Group[]> {
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
  async getUserGroupsWithHierarchy(userId: UUID): Promise<Group[]> {
    const directGroups = await this.getUserGroups(userId);
    
    // Get all parent groups for each direct group
    const allGroups = new Set<Group>();
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
  async userHasGroupAccess(userId: UUID, groupId: UUID): Promise<boolean> {
    const userGroups = await this.getUserGroupsWithHierarchy(userId);
    return userGroups.some(g => g.id === groupId);
  }

  /**
   * Get all roles a user has through direct assignment or group hierarchy inheritance
   */
  async getUserRolesWithHierarchy(userId: UUID): Promise<any[]> {
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
  async validateGroupOperationWithHierarchy(
    userId: UUID,
    groupId: UUID,
    operation: string
  ): Promise<{ isValid: boolean; reason: string }> {
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

  private async getUserGroups(userId: UUID): Promise<Group[]> {
    const result = await this.databaseService.query(`
      SELECT g.* FROM groups g
      JOIN group_members gm ON g.id = gm.group_id
      WHERE gm.user_id = $1 AND gm.status = 'active' AND g.status = 'active'
    `, [userId]);
    
    return result.rows;
  }
}