import { injectable, inject } from 'inversify';
import { DatabaseService } from './database.service';
import { MockDataService } from './mock-data.service';
import { UUID, ScopeType, UserRole, Role, User, ValidationError, PermissionContext, Organization } from '../types';

@injectable()
export class DataAccessService {
  private readonly databaseService: DatabaseService;
  private readonly mockDataService: MockDataService;

  constructor(
    @inject('DatabaseService') databaseService: DatabaseService,
    @inject('MockDataService') mockDataService: MockDataService
  ) {
    this.databaseService = databaseService;
    this.mockDataService = mockDataService;
    // Initialize asynchronously to check database availability
    this.initializationPromise = this.checkDatabaseAvailability();
  }

  private isDatabaseAvailable = false;
  private initializationPromise: Promise<void> | null = null;

  private async checkDatabaseAvailability(): Promise<void> {
    try {
      console.log('🔍 Checking database connection...');
      await this.databaseService.query('SELECT 1');
      this.isDatabaseAvailable = true;
      console.log('✅ Database connection successful');
    } catch (error) {
      this.isDatabaseAvailable = false;
      console.error('⚠️  Database connection failed:', error);
      console.log('⚠️  Database connection failed, using mock data');
    }
  }

  async query(text: string, params?: any[]): Promise<any> {
    await this.ensureInitialized();
    
    console.log(`🔍 Query called. Database available: ${this.isDatabaseAvailable}, Text: ${text.substring(0, 50)}...`);
    
    if (this.isDatabaseAvailable) {
      try {
        const result = await this.databaseService.query(text, params);
        console.log(`✅ Database query successful, rows: ${result.rows?.length || 0}`);
        return result;
      } catch (error) {
        console.error(`❌ Database query failed:`, error);
        // Fall back to mock data if database query fails
        return this.getMockQueryResult(text, params);
      }
    } else {
      console.log(`📝 Using mock data for query`);
      // Return mock data based on query type
      return this.getMockQueryResult(text, params);
    }
  }

  async ensureInitialized(): Promise<void> {
    if (this.initializationPromise) {
      await this.initializationPromise;
    }
  }

  async transaction<T>(callback: (client: any) => Promise<T>): Promise<T> {
    if (this.isDatabaseAvailable) {
      return await this.databaseService.transaction(callback);
    } else {
      // Create a mock client for transactions
      const mockClient = {
        query: async (text: string, params?: any[]) => this.getMockQueryResult(text, params),
        release: () => {}
      };
      return await callback(mockClient);
    }
  }

  private getMockQueryResult(text: string, params?: any[]): any {
    // Return mock results based on query patterns
    if (text.includes('SELECT * FROM roles WHERE id =')) {
      const roleId = params?.[0];
      const role = this.mockDataService.getRole(roleId);
      return {
        rows: role ? [role] : [],
        fields: [],
        command: 'SELECT',
        rowCount: role ? 1 : 0,
        oid: 0
      };
    }

    if (text.includes('SELECT * FROM users WHERE id =')) {
      const userId = params?.[0];
      const user = this.mockDataService.getUser(userId);
      return {
        rows: user ? [user] : [],
        fields: [],
        command: 'SELECT',
        rowCount: user ? 1 : 0,
        oid: 0
      };
    }

    if (text.includes('SELECT * FROM user_roles WHERE user_id =')) {
      const userId = params?.[0];
      const userRoles = this.mockDataService.getUserRoles(userId);
      return {
        rows: userRoles,
        fields: [],
        command: 'SELECT',
        rowCount: userRoles.length,
        oid: 0
      };
    }

    if (text.includes('INSERT INTO user_roles')) {
      // Mock successful insert
      return {
        rows: [{
          id: this.generateUUID(),
          userId: params?.[0],
          roleId: params?.[1],
          assignedBy: params?.[2],
          assignedAt: new Date(),
          status: 'active',
          createdAt: new Date(),
          updatedAt: new Date()
        }],
        fields: [],
        command: 'INSERT',
        rowCount: 1,
        oid: 0
      };
    }

    if (text.includes('UPDATE user_roles')) {
      // Mock successful update
      return {
        rows: [],
        fields: [],
        command: 'UPDATE',
        rowCount: 1,
        oid: 0
      };
    }

    // Default mock result
    return {
      rows: [],
      fields: [],
      command: '',
      rowCount: 0,
      oid: 0
    };
  }

  private generateUUID(): UUID {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  // Mock data access methods
  getUser(userId: UUID): User | undefined {
    return this.mockDataService.getUser(userId);
  }

  getRole(roleId: UUID): Role | undefined {
    return this.mockDataService.getRole(roleId);
  }

  getUserRoles(userId: UUID): UserRole[] {
    return this.mockDataService.getUserRoles(userId);
  }

  hasPermission(userId: UUID, permissionName: string, context?: PermissionContext): boolean {
    return this.mockDataService.hasPermission(userId, permissionName, context);
  }

  getUserPermissionsInScope(userId: UUID, scopeType: ScopeType, scopeId: UUID): string[] {
    return this.mockDataService.getUserPermissionsInScope(userId, scopeType, scopeId);
  }

  validateUserInScope(userId: UUID, scopeType: ScopeType, scopeId?: UUID): boolean {
    return this.mockDataService.validateUserInScope(userId, scopeType, scopeId);
  }

  validateRoleAssignmentAuthority(assignerId: UUID, roleId: UUID, scopeType: ScopeType, scopeId?: UUID): boolean {
    return this.mockDataService.validateRoleAssignmentAuthority(assignerId, roleId, scopeType, scopeId);
  }

  createMockUserRole(command: {
    userId: UUID;
    roleId: UUID;
    assignedBy: UUID;
    scopeType: ScopeType;
    scopeId?: UUID;
    expiresAt?: Date;
    reason?: string;
  }): UserRole {
    return this.mockDataService.createMockUserRole(command);
  }

  // Organization methods
  async createOrganization(organization: Omit<Organization, 'id' | 'createdAt' | 'updatedAt'>): Promise<Organization> {
    await this.ensureInitialized();
    
    if (this.isDatabaseAvailable) {
      const result = await this.databaseService.query(
        `INSERT INTO organizations (name, description, status, metadata, created_at, updated_at)
         VALUES ($1, $2, $3, $4, NOW(), NOW())
         RETURNING *`,
        [organization.name, organization.description, organization.status, organization.metadata]
      );
      return result.rows[0];
    } else {
      return this.mockDataService.createMockOrganization(organization);
    }
  }

  async getOrganization(organizationId: UUID): Promise<Organization | null> {
    await this.ensureInitialized();
    
    if (this.isDatabaseAvailable) {
      console.log("DB is available. No mock!")
      const result = await this.databaseService.query(
        'SELECT * FROM organizations WHERE id = $1',
        [organizationId]
      );
      return result.rows[0] || null;
    } else {
      console.log("DB is not available. Do mock!")
      return this.mockDataService.getMockOrganization(organizationId);
    }
  }

  async updateOrganization(organizationId: UUID, updates: Partial<Organization>): Promise<Organization | null> {
    await this.ensureInitialized();
    
    if (this.isDatabaseAvailable) {
      const setClause = Object.keys(updates)
        .map((key, index) => `${key} = $${index + 2}`)
        .join(', ');
      
      const values = [organizationId, ...Object.values(updates)];
      
      const result = await this.databaseService.query(
        `UPDATE organizations 
         SET ${setClause}, updated_at = NOW()
         WHERE id = $1
         RETURNING *`,
        values
      );
      return result.rows[0] || null;
    } else {
      return this.mockDataService.updateMockOrganization(organizationId, updates);
    }
  }

  async listOrganizations(limit: number, offset: number): Promise<{ organizations: Organization[]; total: number }> {
    await this.ensureInitialized();
    
    if (this.isDatabaseAvailable) {
      console.log("DB is available. No mock!")
      const countResult = await this.databaseService.query('SELECT COUNT(*) FROM organizations');
      const total = parseInt(countResult.rows[0].count);
      
      const result = await this.databaseService.query(
        'SELECT * FROM organizations ORDER BY created_at DESC LIMIT $1 OFFSET $2',
        [limit, offset]
      );
      
      return {
        organizations: result.rows,
        total
      };
    } else {
      console.log("DB is not available. Do mock!")
      return this.mockDataService.listMockOrganizations(limit, offset);
    }
  }

  // Organization setup method
  async setupOrganization(setupData: any): Promise<any> {
    await this.ensureInitialized();
    
    if (this.isDatabaseAvailable) {
      return await this.databaseService.transaction(async (client) => {
        // 1. Create Organization
        const orgResult = await client.query(
          `INSERT INTO organizations 
           (name, description, status, metadata, created_at, updated_at)
           VALUES ($1, $2, $3, $4, NOW(), NOW())
           RETURNING *`,
          [
            setupData.name,
            setupData.description || null,
            setupData.status || 'active',
            setupData.metadata || {}
          ]
        );

        if (!orgResult.rows || orgResult.rows.length === 0) {
          throw new Error('Failed to create organization - no result returned');
        }
        const organization = orgResult.rows[0];

        // 2. Create Root Organization Unit (if specified)
        let rootOU: any = null;
        if (setupData.rootOU) {
          const ouResult = await client.query(
            `INSERT INTO organization_units 
             (organization_id, name, description, parent_id, status, created_at, updated_at)
             VALUES ($1, $2, $3, NULL, $4, NOW(), NOW())
             RETURNING *`,
            [
              organization.id,
              setupData.rootOU.name,
              setupData.rootOU.description || null,
              'active'
            ]
          );
          rootOU = ouResult.rows[0];
        }

        // 3. Create Power Admin User
        const userResult = await client.query(
          `INSERT INTO users 
           (organization_id, organization_unit_id, first_name, last_name, email, phone, status, metadata, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
           RETURNING *`,
          [
            organization.id,
            rootOU ? rootOU.id : null,
            setupData.powerAdmin.firstName,
            setupData.powerAdmin.lastName,
            setupData.powerAdmin.email,
            setupData.powerAdmin.phone || null,
            'active',
            setupData.powerAdmin.metadata || {}
          ]
        );

        if (!userResult.rows || userResult.rows.length === 0) {
          throw new Error('Failed to create power admin user - no result returned');
        }
        const powerAdminUser = userResult.rows[0];

        // 4. Create Power Admin Role
        const roleResult = await client.query(
          `INSERT INTO roles 
           (organization_id, name, description, type, is_system_role, status, scope_type, scope_id, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
           RETURNING *`,
          [
            organization.id,
            'Power Admin',
            'Organization power administrator with full system access',
            'system',
            true,
            'active',
            ScopeType.ORGANIZATION,
            organization.id
          ]
        );

        const powerAdminRole = roleResult.rows[0];

        // 5. Assign Power Admin Role to User
        const userRoleResult = await client.query(
          `INSERT INTO user_roles 
           (user_id, role_id, assigned_by, scope_context, status, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
           RETURNING *`,
          [
            powerAdminUser.id,
            powerAdminRole.id,
            powerAdminUser.id, // Self-assigned during setup
            JSON.stringify({
              scopeType: ScopeType.ORGANIZATION,
              scopeId: organization.id
            }),
            'active'
          ]
        );

        const powerAdminUserRole = userRoleResult.rows[0];

        // 6. Create Audit Log Entry
        await client.query(
          `INSERT INTO audit_logs 
           (actor_id, action, resource_type, resource_id, details, created_at)
           VALUES ($1, $2, $3, $4, $5, NOW())`,
          [
            powerAdminUser.id,
            'organization_setup',
            'organization',
            organization.id,
            JSON.stringify({
              organizationName: organization.name,
              powerAdminEmail: powerAdminUser.email,
              rootOUName: rootOU ? rootOU.name : null,
              setupTimestamp: new Date().toISOString()
            })
          ]
        );

        return {
          organizationId: organization.id,
          powerAdminUserId: powerAdminUser.id,
          rootOUId: rootOU ? rootOU.id : undefined,
          powerAdminRoleId: powerAdminRole.id,
          powerAdminUserRole
        };
      });
    } else {
      return this.mockDataService.setupMockOrganization(setupData);
    }
  }
}
