"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
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
const organization_setup_controller_1 = require("./controllers/organization-setup.controller");
const organization_controller_1 = require("./controllers/organization.controller");
const organization_unit_controller_1 = require("./controllers/organization-unit.controller");
const user_controller_1 = require("./controllers/user.controller");
// Create Express app
const app = (0, express_1.default)();
const port = process.env.PORT || 3000;
// Middleware
app.use(express_1.default.json());
// Dependency Injection Container
const container = new inversify_1.Container();
function setupContainer() {
    const databaseService = new database_service_1.DatabaseService();
    // Bind services to container with proper dependencies
    container.bind('DatabaseService').toConstantValue(databaseService);
    container.bind('MockDataService').to(mock_data_service_1.MockDataService);
    container.bind('DataAccessService').to(data_access_service_1.DataAccessService);
    container.bind('ScopedRoleAssignmentService').to(scoped_role_assignment_service_1.ScopedRoleAssignmentService);
    container.bind('ScopedPermissionService').to(scoped_permission_service_1.ScopedPermissionService);
    container.bind('GroupService').to(group_service_1.GroupService);
    container.bind('GroupHierarchyService').to(group_hierarchy_service_1.GroupHierarchyService);
    container.bind('AuditService').to(audit_service_1.AuditService);
    container.bind('OUContextValidator').to(ou_context_validator_service_1.OUContextValidator);
    container.bind('PermissionEvaluator').to(permission_evaluator_service_1.PermissionEvaluator);
    container.bind('RoleAssignmentService').to(role_assignment_service_1.RoleAssignmentService);
    container.bind('OrganizationSetupController').to(organization_setup_controller_1.OrganizationSetupController);
    container.bind('OrganizationController').to(organization_controller_1.OrganizationController);
    container.bind('OrganizationUnitController').to(organization_unit_controller_1.OrganizationUnitController);
    container.bind('UserController').to(user_controller_1.UserController);
}
// API Routes
// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        message: 'Direct Organization Management System Backend is running'
    });
});
// Scoped Role Assignment endpoints
app.post('/api/scoped-roles/assign', async (req, res) => {
    try {
        const scopedRoleService = container.get('ScopedRoleAssignmentService');
        const command = {
            userId: req.body.userId,
            roleId: req.body.roleId,
            assignedBy: req.body.assignedBy,
            scopeType: req.body.scopeType,
            scopeId: req.body.scopeId,
            expiresAt: req.body.expiresAt ? new Date(req.body.expiresAt) : undefined,
            reason: req.body.reason
        };
        const userRole = await scopedRoleService.assignScopedRole(command);
        res.json({ success: true, data: userRole });
    }
    catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});
app.post('/api/scoped-roles/revoke', async (req, res) => {
    try {
        const scopedRoleService = container.get('ScopedRoleAssignmentService');
        const command = {
            userId: req.body.userId,
            roleId: req.body.roleId,
            revokedBy: req.body.revokedBy,
            scopeType: req.body.scopeType,
            scopeId: req.body.scopeId,
            reason: req.body.reason
        };
        await scopedRoleService.revokeScopedRole(command);
        res.json({ success: true, message: 'Role revoked successfully' });
    }
    catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});
app.get('/api/scoped-roles/user/:userId', async (req, res) => {
    try {
        const scopedRoleService = container.get('ScopedRoleAssignmentService');
        const userId = req.params.userId;
        const scopeType = req.query.scopeType;
        const scopeId = req.query.scopeId;
        const userRoles = await scopedRoleService.getUserScopedRoles(userId, scopeType, scopeId);
        res.json({ success: true, data: userRoles });
    }
    catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});
// Permission checking endpoints
app.post('/api/permissions/check', async (req, res) => {
    try {
        const permissionService = container.get('ScopedPermissionService');
        const hasPermission = await permissionService.hasPermission(req.body.userId, req.body.permissionName, req.body.context);
        res.json({ success: true, hasPermission });
    }
    catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});
app.get('/api/permissions/user/:userId/scope/:scopeType/:scopeId', async (req, res) => {
    try {
        const permissionService = container.get('ScopedPermissionService');
        const userId = req.params.userId;
        const scopeType = req.params.scopeType;
        const scopeId = req.params.scopeId;
        const permissions = await permissionService.getUserPermissionsInScope(userId, scopeType, scopeId);
        res.json({ success: true, data: permissions });
    }
    catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});
// Group hierarchy endpoints
app.get('/api/groups/hierarchy/user/:userId', async (req, res) => {
    try {
        const groupHierarchyService = container.get('GroupHierarchyService');
        const userId = req.params.userId;
        const userRoles = await groupHierarchyService.getUserRolesWithHierarchy(userId);
        res.json({ success: true, data: userRoles });
    }
    catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});
app.post('/api/groups/validate-operation', async (req, res) => {
    try {
        const groupHierarchyService = container.get('GroupHierarchyService');
        const validation = await groupHierarchyService.validateGroupOperationWithHierarchy(req.body.userId, req.body.groupId, req.body.permission);
        res.json({ success: true, data: validation });
    }
    catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});
// Organization Unit endpoints
app.post('/api/ous/validate-cross-operation', async (req, res) => {
    try {
        const ouValidator = container.get('OUContextValidator');
        const validation = await ouValidator.validateOUCrossOperation(req.body.userId, req.body.sourceOUId, req.body.targetOUId, req.body.action);
        res.json({ success: true, data: validation });
    }
    catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});
// Organization Setup endpoints
app.post('/api/organizations/setup', async (req, res) => {
    try {
        const organizationSetupController = container.get('OrganizationSetupController');
        await organizationSetupController.setupOrganization(req, res);
    }
    catch (error) {
        console.error('Organization setup endpoint error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});
app.get('/api/organizations/:organizationId/setup-status', async (req, res) => {
    try {
        const organizationSetupController = container.get('OrganizationSetupController');
        await organizationSetupController.getOrganizationSetupStatus(req, res);
    }
    catch (error) {
        console.error('Organization setup status endpoint error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});
// Organization Management endpoints
app.post('/api/organizations', async (req, res) => {
    try {
        const organizationController = container.get('OrganizationController');
        await organizationController.createOrganization(req, res);
    }
    catch (error) {
        console.error('Create organization endpoint error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});
app.get('/api/organizations/:organizationId', async (req, res) => {
    try {
        const organizationController = container.get('OrganizationController');
        await organizationController.getOrganization(req, res);
    }
    catch (error) {
        console.error('Get organization endpoint error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});
app.put('/api/organizations/:organizationId', async (req, res) => {
    try {
        const organizationController = container.get('OrganizationController');
        await organizationController.updateOrganization(req, res);
    }
    catch (error) {
        console.error('Update organization endpoint error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});
app.get('/api/organizations', async (req, res) => {
    try {
        const organizationController = container.get('OrganizationController');
        await organizationController.listOrganizations(req, res);
    }
    catch (error) {
        console.error('List organizations endpoint error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});
// Organization Unit Management endpoints
app.post('/api/organizations/:organizationId/units', async (req, res) => {
    try {
        const organizationUnitController = container.get('OrganizationUnitController');
        await organizationUnitController.createOrganizationUnit(req, res);
    }
    catch (error) {
        console.error('Create organization unit endpoint error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});
app.get('/api/organizations/:organizationId/units/:ouId', async (req, res) => {
    try {
        const organizationUnitController = container.get('OrganizationUnitController');
        await organizationUnitController.getOrganizationUnit(req, res);
    }
    catch (error) {
        console.error('Get organization unit endpoint error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});
app.put('/api/organizations/:organizationId/units/:ouId', async (req, res) => {
    try {
        const organizationUnitController = container.get('OrganizationUnitController');
        await organizationUnitController.updateOrganizationUnit(req, res);
    }
    catch (error) {
        console.error('Update organization unit endpoint error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});
app.get('/api/organizations/:organizationId/units', async (req, res) => {
    try {
        const organizationUnitController = container.get('OrganizationUnitController');
        await organizationUnitController.listOrganizationUnits(req, res);
    }
    catch (error) {
        console.error('List organization units endpoint error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});
app.delete('/api/organizations/:organizationId/units/:ouId', async (req, res) => {
    try {
        const organizationUnitController = container.get('OrganizationUnitController');
        await organizationUnitController.deleteOrganizationUnit(req, res);
    }
    catch (error) {
        console.error('Delete organization unit endpoint error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});
// User Management endpoints
app.post('/api/users', async (req, res) => {
    try {
        const userController = container.get('UserController');
        await userController.createUser(req, res);
    }
    catch (error) {
        console.error('Create user endpoint error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});
app.get('/api/users/:userId', async (req, res) => {
    try {
        const userController = container.get('UserController');
        await userController.getUser(req, res);
    }
    catch (error) {
        console.error('Get user endpoint error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});
app.put('/api/users/:userId', async (req, res) => {
    try {
        const userController = container.get('UserController');
        await userController.updateUser(req, res);
    }
    catch (error) {
        console.error('Update user endpoint error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});
app.get('/api/users', async (req, res) => {
    try {
        const userController = container.get('UserController');
        await userController.listUsers(req, res);
    }
    catch (error) {
        console.error('List users endpoint error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});
app.patch('/api/users/:userId/move', async (req, res) => {
    try {
        const userController = container.get('UserController');
        await userController.moveUserToOU(req, res);
    }
    catch (error) {
        console.error('Move user endpoint error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});
app.delete('/api/users/:userId/remove', async (req, res) => {
    try {
        const userController = container.get('UserController');
        await userController.removeUserFromOrganization(req, res);
    }
    catch (error) {
        console.error('Remove user endpoint error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});
// Error handling middleware
app.use((error, req, res, next) => {
    console.error('API Error:', error);
    res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: error.message
    });
});
// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found',
        path: req.path
    });
});
require('dotenv').config();
const { Pool } = require('pg');
// Database configuration from environment variables
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || 'postgres',
    database: process.env.DB_NAME || 'direct_organizations',
    ssl: process.env.DB_SSL === 'true',
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30000
};
async function testDatabaseConnection() {
    console.log('🔍 Testing PostgreSQL connection...\n');
    // Display connection info (without password)
    console.log('📊 Connection Configuration:');
    console.log(`   Host: ${dbConfig.host}`);
    console.log(`   Port: ${dbConfig.port}`);
    console.log(`   User: ${dbConfig.user}`);
    console.log(`   Database: ${dbConfig.database}`);
    console.log(`   SSL: ${dbConfig.ssl ? 'Enabled' : 'Disabled'}`);
    console.log('');
    const pool = new Pool(dbConfig);
    try {
        // Test connection
        console.log('🔌 Attempting to connect...');
        const client = await pool.connect();
        // Test basic query
        console.log('✅ Connection successful!');
        console.log('🔍 Running basic queries...');
        // Get PostgreSQL version
        const versionResult = await client.query('SELECT version()');
        console.log(`   PostgreSQL Version: ${versionResult.rows[0].version.split(' ')[0]} ${versionResult.rows[0].version.split(' ')[1]}`);
        // Get current time
        const timeResult = await client.query('SELECT NOW() as current_time');
        console.log(`   Current Time: ${timeResult.rows[0].current_time}`);
        // Check if database exists
        const dbCheckResult = await client.query('SELECT datname FROM pg_database WHERE datname = $1', [dbConfig.database]);
        if (dbCheckResult.rows.length > 0) {
            console.log(`✅ Database '${dbConfig.database}' exists`);
        }
        else {
            console.log(`❌ Database '${dbConfig.database}' does not exist`);
            console.log('💡 You need to create the database first:');
            console.log(`   CREATE DATABASE ${dbConfig.database};`);
        }
        // Check if tables exist
        const tableCheckResult = await client.query(`SELECT table_name FROM information_schema.tables 
       WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`);
        if (tableCheckResult.rows.length > 0) {
            console.log(`✅ Found ${tableCheckResult.rows.length} tables in database:`);
            tableCheckResult.rows.forEach((row) => {
                console.log(`   - ${row.table_name}`);
            });
        }
        else {
            console.log('⚠️  No tables found in database');
            console.log('💡 Run the migration script to create tables:');
            console.log('   node setup-database.js');
        }
        client.release();
        console.log('\n🎉 Database connection test completed successfully!');
    }
    catch (error) {
        console.log('❌ Database connection failed!');
        console.log(`   Error: ${error instanceof Error ? error.message : String(error)}`);
        // Type guard to check if error has a code property
        if (typeof error === 'object' && error !== null && 'code' in error) {
            const errorCode = error.code;
            if (errorCode === 'ECONNREFUSED') {
                console.log('\n💡 Troubleshooting:');
                console.log('   - PostgreSQL service may not be running');
                console.log('   - Check if PostgreSQL is installed and started');
                console.log('   - Verify the port (default: 5432) is correct');
            }
            else if (errorCode === '28000') {
                console.log('\n💡 Troubleshooting:');
                console.log('   - Authentication failed');
                console.log('   - Check username and password in .env file');
                console.log('   - Verify PostgreSQL authentication settings');
            }
            else if (errorCode === '3D000') {
                console.log('\n💡 Troubleshooting:');
                console.log('   - Database does not exist');
                console.log('   - Create the database: CREATE DATABASE direct_organizations;');
            }
            else if (errorCode === 'ENOTFOUND') {
                console.log('\n💡 Troubleshooting:');
                console.log('   - Host not found');
                console.log('   - Check DB_HOST in .env file');
                console.log('   - Ensure PostgreSQL is accessible at the specified host');
            }
        }
        console.log('\n🔧 Quick fixes:');
        console.log('   1. Start PostgreSQL service');
        console.log('   2. Verify .env configuration');
        console.log('   3. Create database if needed');
        console.log('   4. Run migrations to create tables');
    }
    finally {
        await pool.end();
    }
}
// Start server
async function startServer() {
    try {
        console.log('🚀 Starting Direct Organization Management System Backend...');
        // Setup dependency injection
        setupContainer();
        // Start the server
        app.listen(port, () => {
            console.log(`✅ Server running on port ${port}`);
            console.log(`🏥 Health check: http://localhost:${port}/health`);
            console.log(`📚 API Documentation:`);
            console.log(`   - Assign scoped role: POST /api/scoped-roles/assign`);
            console.log(`   - Revoke scoped role: POST /api/scoped-roles/revoke`);
            console.log(`   - Get user roles: GET /api/scoped-roles/user/:userId`);
            console.log(`   - Check permissions: POST /api/permissions/check`);
            console.log(`   - Get user permissions: GET /api/permissions/user/:userId/scope/:scopeType/:scopeId`);
            console.log(`   - Group hierarchy: GET /api/groups/hierarchy/user/:userId`);
            console.log(`   - Validate group operation: POST /api/groups/validate-operation`);
            console.log(`   - Validate OU cross operation: POST /api/ous/validate-cross-operation`);
            console.log(`   - Setup organization: POST /api/organizations/setup`);
            console.log(`   - Get setup status: GET /api/organizations/:organizationId/setup-status`);
            console.log(`   - Create organization: POST /api/organizations`);
            console.log(`   - Get organization: GET /api/organizations/:organizationId`);
            console.log(`   - Update organization: PUT /api/organizations/:organizationId`);
            console.log(`   - List organizations: GET /api/organizations`);
            console.log(`   - Create organization unit: POST /api/organizations/:organizationId/units`);
            console.log(`   - Get organization unit: GET /api/organizations/:organizationId/units/:ouId`);
            console.log(`   - Update organization unit: PUT /api/organizations/:organizationId/units/:ouId`);
            console.log(`   - List organization units: GET /api/organizations/:organizationId/units`);
            console.log(`   - Delete organization unit: DELETE /api/organizations/:organizationId/units/:ouId`);
            console.log(`   - Create user: POST /api/users`);
            console.log(`   - Get user: GET /api/users/:userId`);
            console.log(`   - Update user: PUT /api/users/:userId`);
            console.log(`   - List users: GET /api/users`);
            console.log(`   - Move user: PATCH /api/users/:userId/move`);
            console.log(`   - Remove user: DELETE /api/users/:userId/remove`);
        });
    }
    catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
}
// Only start server if this file is executed directly
if (require.main === module) {
    // Run the test
    //testDatabaseConnection().catch(console.error);
    startServer();
}
exports.default = app;
//# sourceMappingURL=server.js.map