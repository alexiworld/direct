import { UUID, Group, User, GroupAccessValidation } from '../types';
export declare class GroupService {
    private readonly databaseService;
    getGroup(groupId: UUID): Promise<Group>;
    getUserGroups(userId: UUID): Promise<Group[]>;
    getGroupMembership(userId: UUID, groupId: UUID): Promise<any>;
    validateUserGroupAccess(user: User, groupId: UUID): Promise<GroupAccessValidation>;
    getUserRolesInGroup(userId: UUID, groupId: UUID): Promise<any[]>;
    createGroupScopedRole(groupId: UUID, roleDefinition: any, createdBy: UUID): Promise<any>;
    assignGroupScopedRole(groupId: UUID, userId: UUID, roleId: UUID, assignedBy: UUID): Promise<any>;
    private generateUUID;
}
//# sourceMappingURL=group.service.d.ts.map