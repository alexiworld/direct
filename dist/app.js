"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ScopedRolesExample = void 0;
const inversify_1 = require("inversify");
const database_service_1 = require("./services/database.service");
const mock_data_service_1 = require("./services/mock-data.service");
const data_access_service_1 = require("./services/data-access.service");
const scoped_role_assignment_service_1 = require("./services/scoped-role-assignment.service");
const scoped_permission_service_1 = require("./services/scoped-permission.service");
const group_service_1 = require("./services/group.service");
const group_hierarchy_service_1 = require("./services/group-hierarchy.service");
const audit_service_1 = require("./services/audit.service");
const ou_context_validator_service_1 = require("./services/ou-context-validator.service");
const permission_evaluator_service_1 = require("./services/permission-evaluator.service");
const role_assignment_service_1 = require("./services/role-assignment.service");
// Example usage demonstrating the complete scoped roles implementation
class ScopedRolesExample {
    constructor() {
        this.databaseService = new database_service_1.DatabaseService();
        this.container = new inversify_1.Container();
        this.setupContainer();
    }
    setupContainer() {
        // Bind services to container with proper dependencies
        this.container.bind('DatabaseService').toConstantValue(this.databaseService);
        this.container.bind('MockDataService').to(mock_data_service_1.MockDataService);
        this.container.bind('DataAccessService').to(data_access_service_1.DataAccessService);
        this.container.bind('ScopedRoleAssignmentService').to(scoped_role_assignment_service_1.ScopedRoleAssignmentService);
        this.container.bind('ScopedPermissionService').to(scoped_permission_service_1.ScopedPermissionService);
        this.container.bind('GroupService').to(group_service_1.GroupService);
        this.container.bind('GroupHierarchyService').to(group_hierarchy_service_1.GroupHierarchyService);
        this.container.bind('AuditService').to(audit_service_1.AuditService);
        this.container.bind('OUContextValidator').to(ou_context_validator_service_1.OUContextValidator);
        this.container.bind('PermissionEvaluator').to(permission_evaluator_service_1.PermissionEvaluator);
        this.container.bind('RoleAssignmentService').to(role_assignment_service_1.RoleAssignmentService);
    }
    /**
     * Example: Assign a group-scoped role to a user
     */
    async assignGroupScopedRoleExample() {
        const scopedRoleService = this.container.get('ScopedRoleAssignmentService');
        // Use OU-scoped role that the admin user has permission for
        const command = {
            userId: 'user-uuid',
            roleId: 'role-ou-manager-uuid',
            assignedBy: 'user-admin-uuid',
            scopeType: 'organization_unit',
            scopeId: 'ou-engineering-uuid',
            expiresAt: new Date('2024-12-31'),
            reason: 'Project lead assignment'
        };
        try {
            const userRole = await scopedRoleService.assignScopedRole(command);
            console.log('✅ OU-scoped role assigned successfully:', {
                userId: command.userId,
                roleId: command.roleId,
                scopeType: command.scopeType,
                scopeId: command.scopeId,
                assignedBy: command.assignedBy,
                reason: command.reason
            });
        }
        catch (error) {
            console.error('❌ Failed to assign OU-scoped role:', error.message);
        }
    }
    /**
     * Example: Check if a user has permission within a specific scope
     */
    async checkPermissionExample() {
        const permissionService = this.container.get('ScopedPermissionService');
        const hasPermission = await permissionService.hasPermission('user-uuid', 'view_user_details', {
            userId: 'user-uuid',
            scopeType: 'group',
            scopeId: 'group-project-alpha-uuid',
            targetUserId: 'target-user-uuid',
            action: 'view'
        });
        console.log('User has permission:', hasPermission);
    }
    /**
     * Example: Get all permissions a user has within a specific scope
     */
    async getUserPermissionsInScopeExample() {
        const permissionService = this.container.get('ScopedPermissionService');
        const permissions = await permissionService.getUserPermissionsInScope('user-uuid', 'group', 'group-project-alpha-uuid');
        console.log('User permissions in scope:', permissions);
    }
    /**
     * Example: Validate group operation with hierarchy support
     */
    async validateGroupOperationWithHierarchyExample() {
        const groupHierarchyService = this.container.get('GroupHierarchyService');
        const validation = await groupHierarchyService.validateGroupOperationWithHierarchy('user-uuid', 'group-parent-uuid', 'view_group_details');
        console.log('Group operation validation:', validation);
    }
    /**
     * Example: Complete workflow demonstrating role inheritance
     */
    async completeRoleInheritanceExample() {
        console.log('=== Complete Role Inheritance Example ===');
        // 1. Create group hierarchy
        console.log('1. Creating group hierarchy...');
        // 2. Assign user to child group
        console.log('2. Assigning user to child group...');
        // 3. Assign role to parent group
        console.log('3. Assigning role to parent group...');
        // 4. Check if user inherits role through hierarchy
        console.log('4. Checking role inheritance...');
        const groupHierarchyService = this.container.get('GroupHierarchyService');
        const userRoles = await groupHierarchyService.getUserRolesWithHierarchy('user-uuid');
        console.log('User roles with hierarchy:', userRoles);
        console.log('Role inheritance working:', userRoles.length > 0);
    }
    /**
     * Example: Organization unit scoped operations
     */
    async organizationUnitScopedExample() {
        console.log('=== Organization Unit Scoped Example ===');
        const ouValidator = this.container.get('OUContextValidator');
        // Validate cross-OU operation
        const validation = await ouValidator.validateOUCrossOperation('user-uuid', 'ou-engineering-uuid', 'ou-marketing-uuid', 'move_user');
        console.log('Cross-OU operation validation:', validation);
        // Only admins should be able to perform cross-OU operations
        console.log('Cross-OU operations require admin privileges:', !validation.isValid);
    }
    /**
     * Run all examples
     */
    async runAllExamples() {
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
exports.ScopedRolesExample = ScopedRolesExample;
// Export for use in other modules
exports.default = ScopedRolesExample;
// Main application entry point
async function main() {
    console.log('🚀 Starting Direct Organization Management System Backend...');
    try {
        // Initialize the scoped roles example
        const scopedRolesExample = new ScopedRolesExample();
        // Run the examples
        await scopedRolesExample.runAllExamples();
        console.log('✅ Application completed successfully');
    }
    catch (error) {
        console.error('❌ Application failed:', error);
        process.exit(1);
    }
}
// Only run if this file is executed directly (not imported)
if (require.main === module) {
    main();
}
//# sourceMappingURL=app.js.map