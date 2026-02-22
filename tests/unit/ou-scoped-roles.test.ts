import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { PermissionEvaluator } from '../../src/services/permission-evaluator.service';
import { OUContextValidator } from '../../src/services/ou-context-validator.service';
import { RoleAssignmentService } from '../../src/services/role-assignment.service';
import { 
  User, 
  Role, 
  UserRole, 
  PermissionContext, 
  OUAccessValidation,
  ScopeType 
} from '../../src/types';

// Mock dependencies
jest.mock('../../src/services/database.service');
jest.mock('../../src/services/audit-logger.service');

describe('OU Scoped Roles Implementation', () => {
  let permissionEvaluator: PermissionEvaluator;
  let ouContextValidator: OUContextValidator;
  let roleAssignmentService: RoleAssignmentService;
  
  const mockUser: User = {
    id: 'user-1',
    organizationId: 'org-1',
    organizationUnitId: 'ou-dept-1',
    firstName: 'John',
    lastName: 'Doe',
    email: 'john.doe@example.com',
    phone: '+1234567890',
    status: 'active',
    lastLoginAt: new Date(),
    failedLoginAttempts: 0,
    lockedUntil: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    deletedAt: null
  };

  const mockRole: Role = {
    id: 'role-ou-manager',
    organizationId: 'org-1',
    name: 'OU_MANAGER',
    description: 'Organization Unit Manager',
    type: 'custom',
    isSystemRole: false,
    status: 'active',
    createdAt: new Date(),
    updatedAt: new Date(),
    deletedAt: null,
    permissions: ['view_users', 'edit_users', 'invite_users', 'move_users'],
    scopeType: ScopeType.ORGANIZATION_UNIT,
    scopeId: 'ou-dept-1'
  };

  const mockUserRole: UserRole = {
    id: 'user-role-1',
    userId: 'user-1',
    roleId: 'role-ou-manager',
    assignedBy: 'admin-1',
    assignedAt: new Date(),
    status: 'active',
    createdAt: new Date(),
    updatedAt: new Date(),
    name: 'OU_MANAGER',
    scopeType: ScopeType.ORGANIZATION_UNIT,
    scopeId: 'ou-dept-1'
  };

  const mockPermissionContext: PermissionContext = {
    userId: 'user-1',
    organizationUnitId: 'ou-dept-1',
    targetUserId: 'user-2',
    action: 'invite_users'
  };

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();
    
    // Create service instances (with mocked dependencies)
    permissionEvaluator = new PermissionEvaluator();
    ouContextValidator = new OUContextValidator();
    roleAssignmentService = new RoleAssignmentService();
  });

  describe('PermissionEvaluator', () => {
    it('should validate OU owner access correctly', async () => {
      // Mock database calls
      jest.spyOn(permissionEvaluator as any, 'getOUOwnerId').mockResolvedValue('user-1');
      jest.spyOn(permissionEvaluator as any, 'getUserRoles').mockResolvedValue([]);
      jest.spyOn(permissionEvaluator as any, 'getUser').mockResolvedValue(mockUser);

      const result = await (permissionEvaluator as any).validateUserOUAccess(
        mockUser, 
        'ou-dept-1'
      );

      expect(result).toEqual({
        hasAccess: true,
        accessType: 'owner'
      });
    });

    it('should validate OU manager access correctly', async () => {
      // Mock database calls
      jest.spyOn(permissionEvaluator as any, 'getOUOwnerId').mockResolvedValue('user-2');
      jest.spyOn(permissionEvaluator as any, 'isUserManager').mockResolvedValue(true);
      jest.spyOn(permissionEvaluator as any, 'getUser').mockResolvedValue(mockUser);

      const result = await (permissionEvaluator as any).validateUserOUAccess(
        mockUser, 
        'ou-dept-1'
      );

      expect(result).toEqual({
        hasAccess: true,
        accessType: 'manager'
      });
    });

    it('should validate OU member access correctly', async () => {
      // Mock database calls
      jest.spyOn(permissionEvaluator as any, 'getOUOwnerId').mockResolvedValue('user-2');
      jest.spyOn(permissionEvaluator as any, 'isUserManager').mockResolvedValue(false);
      jest.spyOn(permissionEvaluator as any, 'getUser').mockResolvedValue(mockUser);

      const result = await (permissionEvaluator as any).validateUserOUAccess(
        mockUser, 
        'ou-dept-1'
      );

      expect(result).toEqual({
        hasAccess: true,
        accessType: 'member'
      });
    });

    it('should deny access for users outside OU', async () => {
      const userOutsideOU: User = {
        ...mockUser,
        organizationUnitId: 'ou-dept-2'
      };

      // Mock database calls
      jest.spyOn(permissionEvaluator as any, 'getOUOwnerId').mockResolvedValue('user-2');
      jest.spyOn(permissionEvaluator as any, 'isUserManager').mockResolvedValue(false);
      jest.spyOn(permissionEvaluator as any, 'getUser').mockResolvedValue(userOutsideOU);

      const result = await (permissionEvaluator as any).validateUserOUAccess(
        userOutsideOU, 
        'ou-dept-1'
      );

      expect(result).toEqual({
        hasAccess: false,
        accessType: 'none'
      });
    });

    it('should validate manager user removal correctly', async () => {
      const mockTargetUser: User = {
        id: 'user-2',
        organizationId: 'org-1',
        organizationUnitId: 'ou-dept-1',
        firstName: 'Jane',
        lastName: 'Smith',
        email: 'jane.smith@example.com',
        phone: '+1234567891',
        status: 'active',
        lastLoginAt: new Date(),
        failedLoginAttempts: 0,
        lockedUntil: null,
        createdAt: new Date(),
        updatedAt: new Date(),
        deletedAt: null
      };

      const mockTargetUserRole: UserRole = {
        id: 'user-role-2',
        userId: 'user-2',
        roleId: 'role-ou-owner',
        assignedBy: 'admin-1',
        assignedAt: new Date(),
        status: 'active',
        createdAt: new Date(),
        updatedAt: new Date(),
        name: 'OU_OWNER',
        scopeType: ScopeType.ORGANIZATION_UNIT,
        scopeId: 'ou-dept-1'
      };

      // Mock database calls
      jest.spyOn(permissionEvaluator as any, 'getUser').mockResolvedValue(mockTargetUser);
      jest.spyOn(permissionEvaluator as any, 'getUserRoles').mockResolvedValue([mockTargetUserRole]);

      const result = await (permissionEvaluator as any).validateManagerUserRemoval({
        userId: 'user-1',
        organizationUnitId: 'ou-dept-1',
        targetUserId: 'user-2',
        action: 'remove_users'
      });

      expect(result).toBe(false);
    });

    it('should validate user movement correctly', async () => {
      const mockSourceUser: User = {
        ...mockUser,
        organizationUnitId: 'ou-dept-1'
      };

      const mockTargetUser: User = {
        ...mockUser,
        organizationUnitId: 'ou-dept-1'
      };

      // Mock database calls
      jest.spyOn(permissionEvaluator as any, 'getUser').mockResolvedValueOnce(mockSourceUser).mockResolvedValueOnce(mockTargetUser);

      const result = await (permissionEvaluator as any).validateUserMovement({
        userId: 'user-1',
        sourceOrganizationUnitId: 'ou-dept-1',
        targetOrganizationUnitId: 'ou-dept-1',
        action: 'move_users'
      });

      expect(result).toBe(true);
    });

    it('should deny cross-OU movement for non-admins', async () => {
      const mockSourceUser: User = {
        ...mockUser,
        organizationUnitId: 'ou-dept-1'
      };

      const mockTargetUser: User = {
        ...mockUser,
        organizationUnitId: 'ou-dept-1'
      };

      // Mock database calls
      jest.spyOn(permissionEvaluator as any, 'getUser').mockResolvedValueOnce(mockSourceUser).mockResolvedValueOnce(mockTargetUser);
      jest.spyOn(permissionEvaluator as any, 'getUserRoles').mockResolvedValue([]);

      const result = await (permissionEvaluator as any).validateUserMovement({
        userId: 'user-1',
        sourceOrganizationUnitId: 'ou-dept-1',
        targetOrganizationUnitId: 'ou-dept-2',
        action: 'move_users'
      });

      expect(result).toBe(false);
    });
  });

  describe('OUContextValidator', () => {
    it('should validate user invitation correctly', async () => {
      const mockInviter: User = {
        ...mockUser,
        organizationUnitId: 'ou-dept-1'
      };

      const mockTargetUser: User = {
        id: 'user-2',
        organizationId: 'org-1',
        organizationUnitId: 'ou-dept-1',
        firstName: 'Jane',
        lastName: 'Smith',
        email: 'jane.smith@example.com',
        phone: '+1234567891',
        status: 'active',
        lastLoginAt: new Date(),
        failedLoginAttempts: 0,
        lockedUntil: null,
        createdAt: new Date(),
        updatedAt: new Date(),
        deletedAt: null
      };

      // Mock database calls
      jest.spyOn(ouContextValidator as any, 'getUser').mockResolvedValueOnce(mockInviter).mockResolvedValueOnce(mockTargetUser);
      jest.spyOn(ouContextValidator as any, 'validateUserOUAccess').mockResolvedValue({
        hasAccess: true,
        accessType: 'manager'
      });

      const result = await ouContextValidator.validateUserInvitation(
        'user-1',
        'user-2',
        'ou-dept-1'
      );

      expect(result).toEqual({
        isValid: true,
        reason: 'Invitation allowed'
      });
    });

    it('should deny invitation for users without proper access', async () => {
      const mockInviter: User = {
        ...mockUser,
        organizationUnitId: 'ou-dept-2'
      };

      const mockTargetUser: User = {
        id: 'user-2',
        organizationId: 'org-1',
        organizationUnitId: 'ou-dept-1',
        firstName: 'Jane',
        lastName: 'Smith',
        email: 'jane.smith@example.com',
        phone: '+1234567891',
        status: 'active',
        lastLoginAt: new Date(),
        failedLoginAttempts: 0,
        lockedUntil: null,
        createdAt: new Date(),
        updatedAt: new Date(),
        deletedAt: null
      };

      // Mock database calls
      jest.spyOn(ouContextValidator as any, 'getUser').mockResolvedValueOnce(mockInviter).mockResolvedValueOnce(mockTargetUser);
      jest.spyOn(ouContextValidator as any, 'validateUserOUAccess').mockResolvedValue({
        hasAccess: false,
        accessType: 'none'
      });

      const result = await ouContextValidator.validateUserInvitation(
        'user-1',
        'user-2',
        'ou-dept-1'
      );

      expect(result).toEqual({
        isValid: false,
        reason: 'Inviter does not have access to organization unit: ou-dept-1'
      });
    });

    it('should validate user removal correctly', async () => {
      const mockRemover: User = {
        ...mockUser,
        organizationUnitId: 'ou-dept-1'
      };

      const mockTargetUser: User = {
        id: 'user-2',
        organizationId: 'org-1',
        organizationUnitId: 'ou-dept-1',
        firstName: 'Jane',
        lastName: 'Smith',
        email: 'jane.smith@example.com',
        phone: '+1234567891',
        status: 'active',
        lastLoginAt: new Date(),
        failedLoginAttempts: 0,
        lockedUntil: null,
        createdAt: new Date(),
        updatedAt: new Date(),
        deletedAt: null
      };

      // Mock database calls
      jest.spyOn(ouContextValidator as any, 'getUser').mockResolvedValueOnce(mockRemover).mockResolvedValueOnce(mockTargetUser);
      jest.spyOn(ouContextValidator as any, 'validateUserOUAccess').mockResolvedValue({
        hasAccess: true,
        accessType: 'manager'
      });
      jest.spyOn(ouContextValidator as any, 'getUserRoles').mockResolvedValue([]);

      const result = await ouContextValidator.validateUserRemoval(
        'user-1',
        'user-2',
        'ou-dept-1'
      );

      expect(result).toEqual({
        isValid: true,
        reason: 'Removal allowed'
      });
    });

    it('should deny removal of higher-level users by managers', async () => {
      const mockRemover: User = {
        ...mockUser,
        organizationUnitId: 'ou-dept-1'
      };

      const mockTargetUser: User = {
        id: 'user-2',
        organizationId: 'org-1',
        organizationUnitId: 'ou-dept-1',
        firstName: 'Jane',
        lastName: 'Smith',
        email: 'jane.smith@example.com',
        phone: '+1234567891',
        status: 'active',
        lastLoginAt: new Date(),
        failedLoginAttempts: 0,
        lockedUntil: null,
        createdAt: new Date(),
        updatedAt: new Date(),
        deletedAt: null
      };

      const mockTargetUserRole: UserRole = {
        id: 'user-role-2',
        userId: 'user-2',
        roleId: 'role-ou-owner',
        assignedBy: 'admin-1',
        assignedAt: new Date(),
        status: 'active',
        createdAt: new Date(),
        updatedAt: new Date(),
        name: 'OU_OWNER',
        scopeType: ScopeType.ORGANIZATION_UNIT,
        scopeId: 'ou-dept-1'
      };

      // Mock database calls
      jest.spyOn(ouContextValidator as any, 'getUser').mockResolvedValueOnce(mockRemover).mockResolvedValueOnce(mockTargetUser);
      jest.spyOn(ouContextValidator as any, 'validateUserOUAccess').mockResolvedValue({
        hasAccess: true,
        accessType: 'manager'
      });
      jest.spyOn(ouContextValidator as any, 'getUserRoles').mockResolvedValue([mockTargetUserRole]);

      const result = await ouContextValidator.validateUserRemoval(
        'user-1',
        'user-2',
        'ou-dept-1'
      );

      expect(result).toEqual({
        isValid: false,
        reason: 'Managers cannot remove users with owner or manager roles'
      });
    });

    it('should validate user movement correctly', async () => {
      const mockMover: User = {
        ...mockUser,
        organizationUnitId: 'ou-dept-1'
      };

      // Mock database calls
      jest.spyOn(ouContextValidator as any, 'getUser').mockResolvedValue(mockMover);
      jest.spyOn(ouContextValidator as any, 'validateUserOUAccess').mockResolvedValue({
        hasAccess: true,
        accessType: 'manager'
      });

      const result = await ouContextValidator.validateUserMovement(
        'user-1',
        'ou-dept-1',
        'ou-dept-1'
      );

      expect(result).toEqual({
        isValid: true,
        reason: 'Movement allowed'
      });
    });

    it('should deny cross-OU movement for non-admins', async () => {
      const mockMover: User = {
        ...mockUser,
        organizationUnitId: 'ou-dept-1'
      };

      // Mock database calls
      jest.spyOn(ouContextValidator as any, 'getUser').mockResolvedValue(mockMover);
      jest.spyOn(ouContextValidator as any, 'validateUserOUAccess').mockResolvedValue({
        hasAccess: true,
        accessType: 'manager'
      });

      const result = await ouContextValidator.validateUserMovement(
        'user-1',
        'ou-dept-1',
        'ou-dept-2'
      );

      expect(result).toEqual({
        isValid: false,
        reason: 'Only admins can move users across organization units'
      });
    });
  });

  describe('RoleAssignmentService', () => {
    it('should assign scoped role correctly', async () => {
      const mockAssigner: User = {
        ...mockUser,
        organizationUnitId: 'ou-dept-1'
      };

      // Mock database calls
      jest.spyOn(roleAssignmentService as any, 'getUser').mockResolvedValueOnce(mockUser).mockResolvedValueOnce(mockAssigner);
      jest.spyOn(roleAssignmentService as any, 'getRole').mockResolvedValue(mockRole);
      jest.spyOn(roleAssignmentService as any, 'validateAssignmentPermissions').mockResolvedValue(undefined);
      jest.spyOn(roleAssignmentService as any, 'validateScopeRequirements').mockResolvedValue(undefined);
      jest.spyOn(roleAssignmentService as any, 'createUserRoleAssignment').mockResolvedValue(mockUserRole);
      jest.spyOn(roleAssignmentService as any, 'auditLogger').mockResolvedValue(undefined);

      const result = await roleAssignmentService.assignScopedRole(
        'user-1',
        'role-ou-manager',
        'user-1'
      );

      expect(result.success).toBe(true);
      expect(result.message).toBe('Role assigned successfully');
    });

    it('should deny role assignment for users outside OU scope', async () => {
      const mockUserOutsideOU: User = {
        ...mockUser,
        organizationUnitId: 'ou-dept-2'
      };

      const mockAssigner: User = {
        ...mockUser,
        organizationUnitId: 'ou-dept-1'
      };

      // Mock database calls
      jest.spyOn(roleAssignmentService as any, 'getUser').mockResolvedValueOnce(mockUserOutsideOU).mockResolvedValueOnce(mockAssigner);
      jest.spyOn(roleAssignmentService as any, 'getRole').mockResolvedValue(mockRole);
      jest.spyOn(roleAssignmentService as any, 'validateAssignmentPermissions').mockResolvedValue(undefined);

      const result = await roleAssignmentService.assignScopedRole(
        'user-1',
        'role-ou-manager',
        'user-1'
      );

      expect(result.success).toBe(false);
      expect(result.message).toBe('User must belong to the organization unit to receive this scoped role');
    });

    it('should revoke scoped role correctly', async () => {
      const mockRevoker: User = {
        ...mockUser,
        organizationUnitId: 'ou-dept-1'
      };

      // Mock database calls
      jest.spyOn(roleAssignmentService as any, 'getUser').mockResolvedValueOnce(mockUser).mockResolvedValueOnce(mockRevoker);
      jest.spyOn(roleAssignmentService as any, 'getRole').mockResolvedValue(mockRole);
      jest.spyOn(roleAssignmentService as any, 'validateRevocationPermissions').mockResolvedValue(undefined);
      jest.spyOn(roleAssignmentService as any, 'revokeUserRoleAssignment').mockResolvedValue(undefined);
      jest.spyOn(roleAssignmentService as any, 'auditLogger').mockResolvedValue(undefined);

      const result = await roleAssignmentService.revokeScopedRole(
        'user-1',
        'role-ou-manager',
        'user-1'
      );

      expect(result.success).toBe(true);
      expect(result.message).toBe('Role revoked successfully');
    });

    it('should deny role revocation for users outside OU scope', async () => {
      const mockUserOutsideOU: User = {
        ...mockUser,
        organizationUnitId: 'ou-dept-2'
      };

      const mockRevoker: User = {
        ...mockUser,
        organizationUnitId: 'ou-dept-1'
      };

      // Mock database calls
      jest.spyOn(roleAssignmentService as any, 'getUser').mockResolvedValueOnce(mockUserOutsideOU).mockResolvedValueOnce(mockRevoker);
      jest.spyOn(roleAssignmentService as any, 'getRole').mockResolvedValue(mockRole);
      jest.spyOn(roleAssignmentService as any, 'validateRevocationPermissions').mockResolvedValue(undefined);

      const result = await roleAssignmentService.revokeScopedRole(
        'user-1',
        'role-ou-manager',
        'user-1'
      );

      expect(result.success).toBe(false);
      expect(result.message).toBe('User must belong to the organization unit to receive this scoped role');
    });
  });

  describe('Integration Tests', () => {
    it('should handle complete OU-scoped role workflow', async () => {
      // Test the complete flow: assignment -> permission evaluation -> operations -> revocation
      
      const mockAssigner: User = {
        ...mockUser,
        organizationUnitId: 'ou-dept-1'
      };

      const mockTargetUser: User = {
        id: 'user-2',
        organizationId: 'org-1',
        organizationUnitId: 'ou-dept-1',
        firstName: 'Jane',
        lastName: 'Smith',
        email: 'jane.smith@example.com',
        phone: '+1234567891',
        status: 'active',
        lastLoginAt: new Date(),
        failedLoginAttempts: 0,
        lockedUntil: null,
        createdAt: new Date(),
        updatedAt: new Date(),
        deletedAt: null
      };

      // 1. Assign role
      jest.spyOn(roleAssignmentService as any, 'getUser').mockResolvedValueOnce(mockTargetUser).mockResolvedValueOnce(mockAssigner);
      jest.spyOn(roleAssignmentService as any, 'getRole').mockResolvedValue(mockRole);
      jest.spyOn(roleAssignmentService as any, 'validateAssignmentPermissions').mockResolvedValue(undefined);
      jest.spyOn(roleAssignmentService as any, 'validateScopeRequirements').mockResolvedValue(undefined);
      jest.spyOn(roleAssignmentService as any, 'createUserRoleAssignment').mockResolvedValue(mockUserRole);
      jest.spyOn(roleAssignmentService as any, 'auditLogger').mockResolvedValue(undefined);

      const assignResult = await roleAssignmentService.assignScopedRole(
        'user-2',
        'role-ou-manager',
        'user-1'
      );

      expect(assignResult.success).toBe(true);

      // 2. Validate permissions
      jest.spyOn(permissionEvaluator as any, 'getUser').mockResolvedValue(mockTargetUser);
      jest.spyOn(permissionEvaluator as any, 'getUserRoles').mockResolvedValue([mockUserRole]);
      jest.spyOn(permissionEvaluator as any, 'getRole').mockResolvedValue(mockRole);
      jest.spyOn(permissionEvaluator as any, 'getOUOwnerId').mockResolvedValue('user-3');
      jest.spyOn(permissionEvaluator as any, 'isUserManager').mockResolvedValue(true);
      jest.spyOn(permissionEvaluator as any, 'checkRolePermission').mockReturnValue(true);

      const hasPermission = await permissionEvaluator.evaluatePermission(
        'user-2',
        'invite_users',
        mockPermissionContext
      );

      expect(hasPermission).toBe(true);

      // 3. Validate operations
      jest.spyOn(ouContextValidator as any, 'getUser').mockResolvedValueOnce(mockAssigner).mockResolvedValueOnce(mockTargetUser);
      jest.spyOn(ouContextValidator as any, 'validateUserOUAccess').mockResolvedValue({
        hasAccess: true,
        accessType: 'manager'
      });
      jest.spyOn(ouContextValidator as any, 'getUserRoles').mockResolvedValue([]);

      const invitationResult = await ouContextValidator.validateUserInvitation(
        'user-1',
        'user-2',
        'ou-dept-1'
      );

      expect(invitationResult.isValid).toBe(true);

      // 4. Revoke role
      jest.spyOn(roleAssignmentService as any, 'getUser').mockResolvedValueOnce(mockTargetUser).mockResolvedValueOnce(mockAssigner);
      jest.spyOn(roleAssignmentService as any, 'getRole').mockResolvedValue(mockRole);
      jest.spyOn(roleAssignmentService as any, 'validateRevocationPermissions').mockResolvedValue(undefined);
      jest.spyOn(roleAssignmentService as any, 'revokeUserRoleAssignment').mockResolvedValue(undefined);
      jest.spyOn(roleAssignmentService as any, 'auditLogger').mockResolvedValue(undefined);

      const revokeResult = await roleAssignmentService.revokeScopedRole(
        'user-2',
        'role-ou-manager',
        'user-1'
      );

      expect(revokeResult.success).toBe(true);
    });
  });
});