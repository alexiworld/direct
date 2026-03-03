import { DatabaseService } from './database.service';
import { MockDataService } from './mock-data.service';
import { UUID, ScopeType, UserRole, Role, User, PermissionContext, Organization } from '../types';
export declare class DataAccessService {
    private readonly databaseService;
    private readonly mockDataService;
    constructor(databaseService: DatabaseService, mockDataService: MockDataService);
    private isDatabaseAvailable;
    private initializationPromise;
    private checkDatabaseAvailability;
    query(text: string, params?: any[]): Promise<any>;
    ensureInitialized(): Promise<void>;
    transaction<T>(callback: (client: any) => Promise<T>): Promise<T>;
    private getMockQueryResult;
    private generateUUID;
    getUser(userId: UUID): User | undefined;
    getRole(roleId: UUID): Role | undefined;
    getUserRoles(userId: UUID): UserRole[];
    hasPermission(userId: UUID, permissionName: string, context?: PermissionContext): boolean;
    getUserPermissionsInScope(userId: UUID, scopeType: ScopeType, scopeId: UUID): string[];
    validateUserInScope(userId: UUID, scopeType: ScopeType, scopeId?: UUID): boolean;
    validateRoleAssignmentAuthority(assignerId: UUID, roleId: UUID, scopeType: ScopeType, scopeId?: UUID): boolean;
    createMockUserRole(command: {
        userId: UUID;
        roleId: UUID;
        assignedBy: UUID;
        scopeType: ScopeType;
        scopeId?: UUID;
        expiresAt?: Date;
        reason?: string;
    }): UserRole;
    createOrganization(organization: Omit<Organization, 'id' | 'createdAt' | 'updatedAt'>): Promise<Organization>;
    getOrganization(organizationId: UUID): Promise<Organization | null>;
    updateOrganization(organizationId: UUID, updates: Partial<Organization>): Promise<Organization | null>;
    listOrganizations(limit: number, offset: number): Promise<{
        organizations: Organization[];
        total: number;
    }>;
    setupOrganization(setupData: any): Promise<any>;
}
//# sourceMappingURL=data-access.service.d.ts.map