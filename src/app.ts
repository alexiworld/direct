import { Container } from 'inversify';
import { DatabaseService } from './services/database.service';
import { MockDataService } from './services/mock-data.service';
import { DataAccessService } from './services/data-access.service';
import { ScopedRoleAssignmentService } from './services/scoped-role-assignment.service';
import { ScopedPermissionService } from './services/scoped-permission.service';
import { GroupService } from './services/group.service';
import { GroupHierarchyService } from './services/group-hierarchy.service';
import { AuditService } from './services/audit.service';
import { OUContextValidator } from './services/ou-context-validator.service';
import { PermissionEvaluator } from './services/permission-evaluator.service';
import { RoleAssignmentService } from './services/role-assignment.service';

// Example usage demonstrating the complete scoped roles implementation
export class ScopedRolesExample {
  private container: Container;
  private databaseService: DatabaseService;

  constructor() {
    this.databaseService = new DatabaseService();
    this.container = new Container();
    this.setupContainer();
  }

  private setupContainer() {
    // Bind services to container with proper dependencies
    this.container.bind<DatabaseService>('DatabaseService').toConstantValue(this.databaseService);
    this.container.bind<MockDataService>('MockDataService').to(MockDataService);
    this.container.bind<DataAccessService>('DataAccessService').to(DataAccessService);
    this.container.bind<ScopedRoleAssignmentService>('ScopedRoleAssignmentService').to(ScopedRoleAssignmentService);
    this.container.bind<ScopedPermissionService>('ScopedPermissionService').to(ScopedPermissionService);
    this.container.bind<GroupService>('GroupService').to(GroupService);
    this.container.bind<GroupHierarchyService>('GroupHierarchyService').to(GroupHierarchyService);
    this.container.bind<AuditService>('AuditService').to(AuditService);
    this.container.bind<OUContextValidator>('OUContextValidator').to(OUContextValidator);
    this.container.bind<PermissionEvaluator>('PermissionEvaluator').to(PermissionEvaluator);
    this.container.bind<RoleAssignmentService>('RoleAssignmentService').to(RoleAssignmentService);
  }

  /**
   * Example: Assign a group-scoped role to a user
   */
  async assignGroupScopedRoleExample(): Promise<void> {
    const scopedRoleService = this.container.get<ScopedRoleAssignmentService>('ScopedRoleAssignmentService');
    
    // Use OU-scoped role that the admin user has permission for
    const command = {
      userId: 'user-uuid',
      roleId: 'role-ou-manager-uuid',
      assignedBy: 'user-admin-uuid',
      scopeType: 'organization_unit' as any,
      scopeId: 'ou-engineering-uuid',
      expiresAt: new Date('2024-12-31'),
      reason: 'Project lead assignment'
    };

    try {
      const userRole = await scopedRoleService.assignScopedRole(command as any);
      console.log('✅ OU-scoped role assigned successfully:', {
        userId: command.userId,
        roleId: command.roleId,
        scopeType: command.scopeType,
        scopeId: command.scopeId,
        assignedBy: command.assignedBy,
        reason: command.reason
      });
    } catch (error) {
      console.error('❌ Failed to assign OU-scoped role:', (error as Error).message);
    }
  }

  /**
   * Example: Check if a user has permission within a specific scope
   */
  async checkPermissionExample(): Promise<void> {
    const permissionService = this.container.get<ScopedPermissionService>('ScopedPermissionService');
    
    const hasPermission = await permissionService.hasPermission(
      'user-uuid',
      'view_user_details',
      {
        userId: 'user-uuid',
        scopeType: 'group' as any,
        scopeId: 'group-project-alpha-uuid',
        targetUserId: 'target-user-uuid',
        action: 'view'
      }
    );

    console.log('User has permission:', hasPermission);
  }

  /**
   * Example: Get all permissions a user has within a specific scope
   */
  async getUserPermissionsInScopeExample(): Promise<void> {
    const permissionService = this.container.get<ScopedPermissionService>('ScopedPermissionService');
    
    const permissions = await permissionService.getUserPermissionsInScope(
      'user-uuid',
      'group' as any,
      'group-project-alpha-uuid'
    );

    console.log('User permissions in scope:', permissions);
  }

  /**
   * Example: Validate group operation with hierarchy support
   */
  async validateGroupOperationWithHierarchyExample(): Promise<void> {
    const groupHierarchyService = this.container.get<GroupHierarchyService>('GroupHierarchyService');
    
    const validation = await groupHierarchyService.validateGroupOperationWithHierarchy(
      'user-uuid',
      'group-parent-uuid',
      'view_group_details'
    );

    console.log('Group operation validation:', validation);
  }

  /**
   * Example: Complete workflow demonstrating role inheritance
   */
  async completeRoleInheritanceExample(): Promise<void> {
    console.log('=== Complete Role Inheritance Example ===');

    // 1. Create group hierarchy
    console.log('1. Creating group hierarchy...');
    
    // 2. Assign user to child group
    console.log('2. Assigning user to child group...');
    
    // 3. Assign role to parent group
    console.log('3. Assigning role to parent group...');
    
    // 4. Check if user inherits role through hierarchy
    console.log('4. Checking role inheritance...');
    
    const groupHierarchyService = this.container.get<GroupHierarchyService>('GroupHierarchyService');
    const userRoles = await groupHierarchyService.getUserRolesWithHierarchy('user-uuid');
    
    console.log('User roles with hierarchy:', userRoles);
    console.log('Role inheritance working:', userRoles.length > 0);
  }

  /**
   * Example: Organization unit scoped operations
   */
  async organizationUnitScopedExample(): Promise<void> {
    console.log('=== Organization Unit Scoped Example ===');

    const ouValidator = this.container.get<OUContextValidator>('OUContextValidator');
    
    // Validate cross-OU operation
    const validation = await ouValidator.validateOUCrossOperation(
      'user-uuid',
      'ou-engineering-uuid',
      'ou-marketing-uuid',
      'move_user'
    );

    console.log('Cross-OU operation validation:', validation);
    
    // Only admins should be able to perform cross-OU operations
    console.log('Cross-OU operations require admin privileges:', !validation.isValid);
  }

  /**
   * Run all examples
   */
  async runAllExamples(): Promise<void> {
    console.log('Starting Scoped Roles Implementation Examples...\n');

    await this.assignGroupScopedRoleExample();
    console.log('\n' + '='.repeat(50) + '\n');
    
    await this.checkPermissionExample();
    console.log('\n' + '='.repeat(50) + '\n');
    
    await this.getUserPermissionsInScopeExample();
    console.log('\n' + '='.repeat(50) + '\n');
    
    await this.validateGroupOperationWithHierarchyExample();
    console.log('\n' + '='.repeat(50) + '\n');
    
    await this.completeRoleInheritanceExample();
    console.log('\n' + '='.repeat(50) + '\n');
    
    await this.organizationUnitScopedExample();
    
    console.log('\n=== Examples Complete ===');
  }
}

// Export for use in other modules
export default ScopedRolesExample;

// Main application entry point
async function main() {
  console.log('🚀 Starting Direct Organization Management System Backend...');
  
  try {
    // Initialize the scoped roles example
    const scopedRolesExample = new ScopedRolesExample();
    
    // Run the examples
    await scopedRolesExample.runAllExamples();
    
    console.log('✅ Application completed successfully');
  } catch (error) {
    console.error('❌ Application failed:', error);
    process.exit(1);
  }
}

// Only run if this file is executed directly (not imported)
if (require.main === module) {
  main();
}
