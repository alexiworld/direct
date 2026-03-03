import { ScopedRoleAssignmentService } from '../services/scoped-role-assignment.service';
import { ScopedPermissionService } from '../services/scoped-permission.service';
import { UUID, AssignScopedRoleDto, PermissionContext } from '../types';
export declare class ScopedRoleController {
    private readonly scopedRoleService;
    private readonly permissionService;
    constructor(scopedRoleService: ScopedRoleAssignmentService, permissionService: ScopedPermissionService);
    assignScopedRole(orgId: string, userId: string, assignCommand: AssignScopedRoleDto, req: any): Promise<any>;
    checkPermission(userId: string, request: {
        permission: string;
        context: PermissionContext;
    }): Promise<{
        hasPermission: boolean;
    }>;
    getPermissionsInScope(userId: string, request: {
        scopeType: string;
        scopeId: UUID;
    }): Promise<{
        permissions: string[];
    }>;
    private getUser;
}
//# sourceMappingURL=scoped-role.controller.d.ts.map