import { UUID, Group } from '../types';
export declare class GroupHierarchyService {
    private readonly databaseService;
    /**
     * Get all parent groups for a given group using materialized path
     */
    getGroupAncestors(groupId: UUID): Promise<Group[]>;
    /**
     * Get all child groups for a given group
     */
    getGroupDescendants(groupId: UUID): Promise<Group[]>;
    /**
     * Get all groups that a user belongs to, including through hierarchy inheritance
     */
    getUserGroupsWithHierarchy(userId: UUID): Promise<Group[]>;
    /**
     * Check if a user has access to a group through direct membership or hierarchy
     */
    userHasGroupAccess(userId: UUID, groupId: UUID): Promise<boolean>;
    /**
     * Get all roles a user has through direct assignment or group hierarchy inheritance
     */
    getUserRolesWithHierarchy(userId: UUID): Promise<any[]>;
    /**
     * Validate if a user can perform an operation on a group considering hierarchy
     */
    validateGroupOperationWithHierarchy(userId: UUID, groupId: UUID, operation: string): Promise<{
        isValid: boolean;
        reason: string;
    }>;
    private getUserGroups;
}
//# sourceMappingURL=group-hierarchy.service.d.ts.map