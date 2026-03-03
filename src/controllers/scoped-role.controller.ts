import { Controller, Post, Body, Param, UseGuards, Request } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { HasPermission } from '../decorators/has-permission.decorator';
import { ScopedRoleAssignmentService } from '../services/scoped-role-assignment.service';
import { ScopedPermissionService } from '../services/scoped-permission.service';
import { 
  UUID, 
  AssignScopedRoleCommand, 
  AssignScopedRoleDto,
  PermissionContext
} from '../types';

@Controller('organizations/:orgId/users/:userId/roles')
export class ScopedRoleController {
  constructor(
    private readonly scopedRoleService: ScopedRoleAssignmentService,
    private readonly permissionService: ScopedPermissionService
  ) {}

  @Post('scoped')
  @UseGuards(AuthGuard)
  @HasPermission('assign_roles_to_users')
  async assignScopedRole(
    @Param('orgId') orgId: string,
    @Param('userId') userId: string,
    @Body() assignCommand: AssignScopedRoleDto,
    @Request() req: any
  ): Promise<any> {
    // Validate organization isolation
    const user = await this.getUser(userId);
    if (user.organizationId !== orgId) {
      throw new Error('User does not belong to the specified organization');
    }
    
    const command: AssignScopedRoleCommand = {
      userId: userId,
      roleId: assignCommand.roleId,
      assignedBy: req.user.id,
      scopeType: assignCommand.scopeType,
      expiresAt: assignCommand.expiresAt,
      reason: assignCommand.reason
    };
    
    return await this.scopedRoleService.assignScopedRole(command);
  }

  @Post('check-permission')
  @UseGuards(AuthGuard)
  async checkPermission(
    @Param('userId') userId: string,
    @Body() request: {
      permission: string;
      context: PermissionContext;
    }
  ): Promise<{ hasPermission: boolean }> {
    const hasPermission = await this.permissionService.hasPermission(
      userId,
      request.permission,
      request.context
    );
    
    return { hasPermission };
  }

  @Post('permissions-in-scope')
  @UseGuards(AuthGuard)
  async getPermissionsInScope(
    @Param('userId') userId: string,
    @Body() request: {
      scopeType: string;
      scopeId: UUID;
    }
  ): Promise<{ permissions: string[] }> {
    const permissions = await this.permissionService.getUserPermissionsInScope(
      userId,
      request.scopeType as any,
      request.scopeId
    );
    
    return { permissions };
  }

  private async getUser(userId: UUID): Promise<any> {
    // This would typically be injected from a UserService
    // For now, returning a mock structure
    return {
      id: userId,
      organizationId: 'org-uuid'
    };
  }
}