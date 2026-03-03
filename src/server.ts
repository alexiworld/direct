import express, { Request, Response, NextFunction } from 'express';
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
import { OrganizationSetupController } from './controllers/organization-setup.controller';
import { OrganizationController } from './controllers/organization.controller';
import { OrganizationUnitController } from './controllers/organization-unit.controller';
import { UserController } from './controllers/user.controller';
import { UUID, ScopeType, UserRole, Role, User, ValidationError, PermissionContext } from './types';

// Create Express app
const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// Dependency Injection Container
const container = new Container();

function setupContainer() {
  const databaseService = new DatabaseService();
  
  // Bind services to container with proper dependencies
  container.bind<DatabaseService>('DatabaseService').toConstantValue(databaseService);
  container.bind<MockDataService>('MockDataService').to(MockDataService);
  container.bind<DataAccessService>('DataAccessService').to(DataAccessService);
  container.bind<ScopedRoleAssignmentService>('ScopedRoleAssignmentService').to(ScopedRoleAssignmentService);
  container.bind<ScopedPermissionService>('ScopedPermissionService').to(ScopedPermissionService);
  container.bind<GroupService>('GroupService').to(GroupService);
  container.bind<GroupHierarchyService>('GroupHierarchyService').to(GroupHierarchyService);
  container.bind<AuditService>('AuditService').to(AuditService);
  container.bind<OUContextValidator>('OUContextValidator').to(OUContextValidator);
  container.bind<PermissionEvaluator>('PermissionEvaluator').to(PermissionEvaluator);
  container.bind<RoleAssignmentService>('RoleAssignmentService').to(RoleAssignmentService);
container.bind<OrganizationSetupController>('OrganizationSetupController').to(OrganizationSetupController);
container.bind<OrganizationController>('OrganizationController').to(OrganizationController);
container.bind<OrganizationUnitController>('OrganizationUnitController').to(OrganizationUnitController);
container.bind<UserController>('UserController').to(UserController);
}

// API Routes

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    message: 'Direct Organization Management System Backend is running'
  });
});

// Scoped Role Assignment endpoints
app.post('/api/scoped-roles/assign', async (req: Request, res: Response) => {
  try {
    const scopedRoleService = container.get<ScopedRoleAssignmentService>('ScopedRoleAssignmentService');
    
    const command = {
      userId: req.body.userId,
      roleId: req.body.roleId,
      assignedBy: req.body.assignedBy,
      scopeType: req.body.scopeType as ScopeType,
      scopeId: req.body.scopeId,
      expiresAt: req.body.expiresAt ? new Date(req.body.expiresAt) : undefined,
      reason: req.body.reason
    };

    const userRole = await scopedRoleService.assignScopedRole(command);
    res.json({ success: true, data: userRole });
  } catch (error) {
    res.status(400).json({ success: false, error: (error as Error).message });
  }
});

app.post('/api/scoped-roles/revoke', async (req: Request, res: Response) => {
  try {
    const scopedRoleService = container.get<ScopedRoleAssignmentService>('ScopedRoleAssignmentService');
    
    const command = {
      userId: req.body.userId,
      roleId: req.body.roleId,
      revokedBy: req.body.revokedBy,
      scopeType: req.body.scopeType as ScopeType,
      scopeId: req.body.scopeId,
      reason: req.body.reason
    };

    await scopedRoleService.revokeScopedRole(command);
    res.json({ success: true, message: 'Role revoked successfully' });
  } catch (error) {
    res.status(400).json({ success: false, error: (error as Error).message });
  }
});

app.get('/api/scoped-roles/user/:userId', async (req: Request, res: Response) => {
  try {
    const scopedRoleService = container.get<ScopedRoleAssignmentService>('ScopedRoleAssignmentService');
    
    const userId = req.params.userId;
    const scopeType = req.query.scopeType as ScopeType;
    const scopeId = req.query.scopeId as UUID;

    const userRoles = await scopedRoleService.getUserScopedRoles(userId, scopeType, scopeId);
    res.json({ success: true, data: userRoles });
  } catch (error) {
    res.status(400).json({ success: false, error: (error as Error).message });
  }
});

// Permission checking endpoints
app.post('/api/permissions/check', async (req: Request, res: Response) => {
  try {
    const permissionService = container.get<ScopedPermissionService>('ScopedPermissionService');
    
    const hasPermission = await permissionService.hasPermission(
      req.body.userId,
      req.body.permissionName,
      req.body.context
    );

    res.json({ success: true, hasPermission });
  } catch (error) {
    res.status(400).json({ success: false, error: (error as Error).message });
  }
});

app.get('/api/permissions/user/:userId/scope/:scopeType/:scopeId', async (req: Request, res: Response) => {
  try {
    const permissionService = container.get<ScopedPermissionService>('ScopedPermissionService');
    
    const userId = req.params.userId;
    const scopeType = req.params.scopeType as ScopeType;
    const scopeId = req.params.scopeId as UUID;

    const permissions = await permissionService.getUserPermissionsInScope(userId, scopeType, scopeId);
    res.json({ success: true, data: permissions });
  } catch (error) {
    res.status(400).json({ success: false, error: (error as Error).message });
  }
});

// Group hierarchy endpoints
app.get('/api/groups/hierarchy/user/:userId', async (req: Request, res: Response) => {
  try {
    const groupHierarchyService = container.get<GroupHierarchyService>('GroupHierarchyService');
    
    const userId = req.params.userId;
    const userRoles = await groupHierarchyService.getUserRolesWithHierarchy(userId);
    
    res.json({ success: true, data: userRoles });
  } catch (error) {
    res.status(400).json({ success: false, error: (error as Error).message });
  }
});

app.post('/api/groups/validate-operation', async (req: Request, res: Response) => {
  try {
    const groupHierarchyService = container.get<GroupHierarchyService>('GroupHierarchyService');
    
    const validation = await groupHierarchyService.validateGroupOperationWithHierarchy(
      req.body.userId,
      req.body.groupId,
      req.body.permission
    );

    res.json({ success: true, data: validation });
  } catch (error) {
    res.status(400).json({ success: false, error: (error as Error).message });
  }
});

// Organization Unit endpoints
app.post('/api/ous/validate-cross-operation', async (req: Request, res: Response) => {
  try {
    const ouValidator = container.get<OUContextValidator>('OUContextValidator');
    
    const validation = await ouValidator.validateOUCrossOperation(
      req.body.userId,
      req.body.sourceOUId,
      req.body.targetOUId,
      req.body.action
    );

    res.json({ success: true, data: validation });
  } catch (error) {
    res.status(400).json({ success: false, error: (error as Error).message });
  }
});

// Organization Setup endpoints
app.post('/api/organizations/setup', async (req: Request, res: Response) => {
  try {
    const organizationSetupController = container.get<OrganizationSetupController>('OrganizationSetupController');
    await organizationSetupController.setupOrganization(req, res);
  } catch (error) {
    console.error('Organization setup endpoint error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/organizations/:organizationId/setup-status', async (req: Request, res: Response) => {
  try {
    const organizationSetupController = container.get<OrganizationSetupController>('OrganizationSetupController');
    await organizationSetupController.getOrganizationSetupStatus(req, res);
  } catch (error) {
    console.error('Organization setup status endpoint error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Organization Management endpoints
app.post('/api/organizations', async (req: Request, res: Response) => {
  try {
    const organizationController = container.get<OrganizationController>('OrganizationController');
    await organizationController.createOrganization(req, res);
  } catch (error) {
    console.error('Create organization endpoint error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/organizations/:organizationId', async (req: Request, res: Response) => {
  try {
    const organizationController = container.get<OrganizationController>('OrganizationController');
    await organizationController.getOrganization(req, res);
  } catch (error) {
    console.error('Get organization endpoint error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.put('/api/organizations/:organizationId', async (req: Request, res: Response) => {
  try {
    const organizationController = container.get<OrganizationController>('OrganizationController');
    await organizationController.updateOrganization(req, res);
  } catch (error) {
    console.error('Update organization endpoint error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/organizations', async (req: Request, res: Response) => {
  try {
    const organizationController = container.get<OrganizationController>('OrganizationController');
    await organizationController.listOrganizations(req, res);
  } catch (error) {
    console.error('List organizations endpoint error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Organization Unit Management endpoints
app.post('/api/organizations/:organizationId/units', async (req: Request, res: Response) => {
  try {
    const organizationUnitController = container.get<OrganizationUnitController>('OrganizationUnitController');
    await organizationUnitController.createOrganizationUnit(req, res);
  } catch (error) {
    console.error('Create organization unit endpoint error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/organizations/:organizationId/units/:ouId', async (req: Request, res: Response) => {
  try {
    const organizationUnitController = container.get<OrganizationUnitController>('OrganizationUnitController');
    await organizationUnitController.getOrganizationUnit(req, res);
  } catch (error) {
    console.error('Get organization unit endpoint error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.put('/api/organizations/:organizationId/units/:ouId', async (req: Request, res: Response) => {
  try {
    const organizationUnitController = container.get<OrganizationUnitController>('OrganizationUnitController');
    await organizationUnitController.updateOrganizationUnit(req, res);
  } catch (error) {
    console.error('Update organization unit endpoint error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/organizations/:organizationId/units', async (req: Request, res: Response) => {
  try {
    const organizationUnitController = container.get<OrganizationUnitController>('OrganizationUnitController');
    await organizationUnitController.listOrganizationUnits(req, res);
  } catch (error) {
    console.error('List organization units endpoint error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.delete('/api/organizations/:organizationId/units/:ouId', async (req: Request, res: Response) => {
  try {
    const organizationUnitController = container.get<OrganizationUnitController>('OrganizationUnitController');
    await organizationUnitController.deleteOrganizationUnit(req, res);
  } catch (error) {
    console.error('Delete organization unit endpoint error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// User Management endpoints
app.post('/api/users', async (req: Request, res: Response) => {
  try {
    const userController = container.get<UserController>('UserController');
    await userController.createUser(req, res);
  } catch (error) {
    console.error('Create user endpoint error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/users/:userId', async (req: Request, res: Response) => {
  try {
    const userController = container.get<UserController>('UserController');
    await userController.getUser(req, res);
  } catch (error) {
    console.error('Get user endpoint error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.put('/api/users/:userId', async (req: Request, res: Response) => {
  try {
    const userController = container.get<UserController>('UserController');
    await userController.updateUser(req, res);
  } catch (error) {
    console.error('Update user endpoint error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/users', async (req: Request, res: Response) => {
  try {
    const userController = container.get<UserController>('UserController');
    await userController.listUsers(req, res);
  } catch (error) {
    console.error('List users endpoint error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.patch('/api/users/:userId/move', async (req: Request, res: Response) => {
  try {
    const userController = container.get<UserController>('UserController');
    await userController.moveUserToOU(req, res);
  } catch (error) {
    console.error('Move user endpoint error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.delete('/api/users/:userId/remove', async (req: Request, res: Response) => {
  try {
    const userController = container.get<UserController>('UserController');
    await userController.removeUserFromOrganization(req, res);
  } catch (error) {
    console.error('Remove user endpoint error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Error handling middleware
app.use((error: Error, req: Request, res: Response, next: NextFunction) => {
  console.error('API Error:', error);
  res.status(500).json({ 
    success: false, 
    error: 'Internal server error',
    message: error.message 
  });
});

// 404 handler
app.use((req: Request, res: Response) => {
  res.status(404).json({ 
    success: false, 
    error: 'Endpoint not found',
    path: req.path 
  });
});

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
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

// Only start server if this file is executed directly
if (require.main === module) {
  startServer();
}

export default app;