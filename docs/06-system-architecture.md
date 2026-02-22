# Direct Organization Management System - System Architecture

**Document Version**: 1.0  
**Created**: February 2026  
**Last Updated**: February 2026  
**Status**: Draft

## Table of Contents

1. [System Architecture Overview](#system-architecture-overview)
2. [Architecture Principles](#architecture-principles)
3. [Technology Stack](#technology-stack)
4. [System Components](#system-components)
5. [Data Flow Architecture](#data-flow-architecture)
6. [Deployment Architecture](#deployment-architecture)
7. [Scalability and Performance](#scalability-and-performance)
8. [Security Architecture](#security-architecture)
9. [Monitoring and Observability](#monitoring-and-observability)
10. [Integration Patterns](#integration-patterns)

## System Architecture Overview

The Direct Organization Management System follows a microservices architecture with domain-driven design principles. The system is designed for high availability, scalability, and maintainability while ensuring strong data isolation between organizations.

### Architecture Style

- **Microservices**: Independent, loosely-coupled services
- **Domain-Driven Design (DDD)**: Clear domain boundaries and ubiquitous language
- **Event-Driven Architecture**: Asynchronous communication between services
- **API Gateway Pattern**: Centralized entry point for all client requests
- **CQRS**: Command Query Responsibility Segregation for optimized read/write operations

### High-Level Architecture Diagram

```mermaid
graph TB
    subgraph "Client Layer"
        WebApp[Web Application]
        MobileApp[Mobile App]
        ThirdParty[Third-party Integrations]
    end
    
    subgraph "API Gateway Layer"
        APIGateway[API Gateway]
        AuthMiddleware[Authentication Middleware]
    end
    
    subgraph "Service Layer"
        AuthSvc[Authentication Service]
        UserSvc[User Management Service]
        OrgSvc[Organization Service]
        RoleSvc[Role & Permission Service]
        GroupSvc[Group Management Service]
        AuditSvc[Audit Service]
        NotificationSvc[Notification Service]
    end
    
    subgraph "Data Layer"
        PostgreSQL[(PostgreSQL Database)]
        Redis[(Redis Cache)]
        AuditDB[(Audit Database)]
    end
    
    subgraph "Message Layer"
        MessageBroker[Message Broker]
        EventStore[Event Store]
    end
    
    subgraph "Infrastructure"
        LoadBalancer[Load Balancer]
        ServiceDiscovery[Service Discovery]
        ConfigServer[Configuration Server]
    end
    
    WebApp --> APIGateway
    MobileApp --> APIGateway
    ThirdParty --> APIGateway
    
    APIGateway --> AuthMiddleware
    AuthMiddleware --> AuthSvc
    AuthMiddleware --> UserSvc
    AuthMiddleware --> OrgSvc
    AuthMiddleware --> RoleSvc
    AuthMiddleware --> GroupSvc
    AuthMiddleware --> AuditSvc
    AuthMiddleware --> NotificationSvc
    
    AuthSvc --> PostgreSQL
    UserSvc --> PostgreSQL
    OrgSvc --> PostgreSQL
    RoleSvc --> PostgreSQL
    GroupSvc --> PostgreSQL
    AuditSvc --> AuditDB
    
    AuthSvc --> Redis
    UserSvc --> Redis
    RoleSvc --> Redis
    
    AuthSvc --> MessageBroker
    UserSvc --> MessageBroker
    OrgSvc --> MessageBroker
    RoleSvc --> MessageBroker
    GroupSvc --> MessageBroker
    NotificationSvc --> MessageBroker
    
    MessageBroker --> EventStore
    MessageBroker --> NotificationSvc
    
    APIGateway --> LoadBalancer
    AuthSvc --> ServiceDiscovery
    UserSvc --> ServiceDiscovery
    OrgSvc --> ServiceDiscovery
    RoleSvc --> ServiceDiscovery
    GroupSvc --> ServiceDiscovery
    AuditSvc --> ServiceDiscovery
    NotificationSvc --> ServiceDiscovery
    
    AuthSvc --> ConfigServer
    UserSvc --> ConfigServer
    OrgSvc --> ConfigServer
    RoleSvc --> ConfigServer
    GroupSvc --> ConfigServer
    AuditSvc --> ConfigServer
    NotificationSvc --> ConfigServer
```

## Architecture Principles

### Core Principles

1. **Single Responsibility**: Each service has a single, well-defined responsibility
2. **Domain-Driven Design**: Clear domain boundaries with ubiquitous language
3. **Event Sourcing**: All state changes are captured as events
4. **CQRS**: Separate read and write models for optimal performance
5. **Eventual Consistency**: Accept eventual consistency for better scalability
6. **Fail Fast**: Services fail quickly and gracefully
7. **Observability**: Comprehensive logging, monitoring, and tracing

### Design Patterns

#### Domain-Driven Design Patterns

```typescript
// Aggregate Root
class Organization extends AggregateRoot {
  private units: OrganizationUnit[] = [];
  private users: User[] = [];
  
  public addUnit(unit: OrganizationUnit): void {
    this.ensureUnitNameUnique(unit.name);
    this.units.push(unit);
    this.addDomainEvent(new OrganizationUnitAdded(this.id, unit.id));
  }
  
  private ensureUnitNameUnique(name: string): void {
    if (this.units.some(u => u.name === name)) {
      throw new DomainException('Unit name must be unique within organization');
    }
  }
}

// Value Object
class ContactInfo extends ValueObject {
  public readonly email: string;
  public readonly phone: string;
  public readonly address: Address;
  
  constructor(email: string, phone: string, address: Address) {
    super();
    this.ensureValidEmail(email);
    this.email = email;
    this.phone = phone;
    this.address = address;
  }
  
  private ensureValidEmail(email: string): void {
    if (!email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
      throw new DomainException('Invalid email format');
    }
  }
}

// Repository Interface
interface OrganizationRepository {
  findById(id: UUID): Promise<Organization | null>;
  save(organization: Organization): Promise<void>;
  delete(id: UUID): Promise<void>;
}
```

#### CQRS Implementation

```typescript
// Command
class CreateUserCommand {
  constructor(
    public readonly organizationId: UUID,
    public readonly email: string,
    public readonly firstName: string,
    public readonly lastName: string
  ) {}
}

// Command Handler
class CreateUserCommandHandler {
  constructor(
    private userRepository: UserRepository,
    private eventPublisher: EventPublisher
  ) {}
  
  async handle(command: CreateUserCommand): Promise<void> {
    const user = new User(
      command.organizationId,
      command.email,
      command.firstName,
      command.lastName
    );
    
    await this.userRepository.save(user);
    
    await this.eventPublisher.publish(
      new UserCreatedEvent(user.id, user.organizationId, user.email)
    );
  }
}

// Query
class GetUserQuery {
  constructor(public readonly userId: UUID) {}
}

// Query Handler
class GetUserQueryHandler {
  constructor(private userReadModel: UserReadModel) {}
  
  async handle(query: GetUserQuery): Promise<UserDto> {
    return await this.userReadModel.findById(query.userId);
  }
}
```

#### Event-Driven Architecture

```typescript
// Domain Event
class UserCreatedEvent extends DomainEvent {
  constructor(
    public readonly userId: UUID,
    public readonly organizationId: UUID,
    public readonly email: string
  ) {
    super();
  }
}

// Event Handler
class UserCreatedEventHandler implements EventHandler<UserCreatedEvent> {
  constructor(
    private notificationService: NotificationService,
    private auditService: AuditService
  ) {}
  
  async handle(event: UserCreatedEvent): Promise<void> {
    // Send welcome email
    await this.notificationService.sendWelcomeEmail(
      event.email,
      event.userId
    );
    
    // Log audit event
    await this.auditService.logEvent({
      userId: event.userId,
      action: 'USER_CREATED',
      resourceType: 'USER',
      resourceId: event.userId,
      details: { email: event.email }
    });
  }
}

// Event Publisher
class EventPublisher {
  constructor(private messageBroker: MessageBroker) {}
  
  async publish(event: DomainEvent): Promise<void> {
    await this.messageBroker.publish(event.type, event);
  }
}
```

## Technology Stack

### Backend Technologies

#### Core Framework
- **Node.js**: Runtime environment
- **TypeScript**: Primary programming language
- **NestJS**: Application framework with dependency injection
- **Express.js**: HTTP server framework

#### Database Technologies
- **PostgreSQL**: Primary relational database
- **Redis**: Caching and session storage
- **pgBouncer**: Connection pooling

#### Message Broker
- **RabbitMQ**: Message queuing and event streaming
- **Kafka**: Event streaming for high-throughput scenarios

#### Authentication & Authorization
- **JWT**: Stateless authentication tokens
- **bcrypt**: Password hashing
- **TOTP**: Two-factor authentication

### Frontend Technologies

#### Web Application
- **React**: UI framework
- **TypeScript**: Type-safe JavaScript
- **Redux Toolkit**: State management
- **React Router**: Client-side routing
- **Material-UI**: Component library

#### Mobile Application
- **React Native**: Cross-platform mobile development
- **TypeScript**: Type-safe mobile development
- **React Navigation**: Mobile navigation
- **AsyncStorage**: Local storage

### Infrastructure Technologies

#### Containerization
- **Docker**: Application containerization
- **Docker Compose**: Multi-container development environment

#### Orchestration
- **Kubernetes**: Container orchestration
- **Helm**: Kubernetes package manager

#### Monitoring & Observability
- **Prometheus**: Metrics collection
- **Grafana**: Metrics visualization
- **ELK Stack**: Log aggregation and analysis
- **Jaeger**: Distributed tracing

#### CI/CD
- **GitHub Actions**: Continuous integration and deployment
- **Docker Registry**: Container image storage

## System Components

### Authentication Service

Handles user authentication, authorization, and session management.

```typescript
@Injectable()
export class AuthService {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly jwtService: JwtService,
    private readonly mfaService: MfaService,
    private readonly auditService: AuditService
  ) {}

  async login(credentials: LoginCredentials): Promise<AuthResult> {
    const user = await this.validateCredentials(credentials);
    
    if (user.requiresMfa) {
      return this.handleMfaRequired(user);
    }
    
    const tokens = await this.generateTokens(user);
    await this.auditService.logLogin(user.id, 'SUCCESS');
    
    return {
      user: this.mapToUserDto(user),
      tokens,
      mfaRequired: false
    };
  }
  
  private async validateCredentials(credentials: LoginCredentials): Promise<User> {
    const user = await this.userRepository.findByEmail(credentials.email);
    
    if (!user || !await this.verifyPassword(credentials.password, user.passwordHash)) {
      await this.auditService.logLogin(null, 'FAILED', { reason: 'Invalid credentials' });
      throw new UnauthorizedException('Invalid credentials');
    }
    
    if (user.isLocked) {
      throw new ForbiddenException('Account is locked');
    }
    
    return user;
  }
}
```

### User Management Service

Manages user lifecycle, organization units, and user relationships.

```typescript
@Injectable()
export class UserService {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly organizationUnitRepository: OrganizationUnitRepository,
    private readonly eventPublisher: EventPublisher,
    private readonly auditService: AuditService
  ) {}

  async createUser(command: CreateUserCommand): Promise<UserDto> {
    const organizationUnit = await this.validateOrganizationUnit(command.organizationUnitId);
    
    const user = new User({
      organizationId: command.organizationId,
      organizationUnitId: command.organizationUnitId,
      email: command.email,
      firstName: command.firstName,
      lastName: command.lastName
    });
    
    await this.userRepository.save(user);
    
    await this.eventPublisher.publish(new UserCreatedEvent(user));
    await this.auditService.logUserCreation(user.id, command);
    
    return this.mapToDto(user);
  }
  
  async moveUser(command: MoveUserCommand): Promise<void> {
    const user = await this.userRepository.findById(command.userId);
    const targetUnit = await this.organizationUnitRepository.findById(command.targetUnitId);
    
    this.validateMove(user, targetUnit);
    
    user.moveOrganizationUnit(targetUnit.id);
    
    await this.userRepository.save(user);
    
    await this.eventPublisher.publish(new UserMovedEvent(user.id, command.targetUnitId));
    await this.auditService.logUserMove(user.id, command);
  }
}
```

### Role and Permission Service

Manages roles, permissions, and access control.

```typescript
@Injectable()
export class RoleService {
  constructor(
    private readonly roleRepository: RoleRepository,
    private readonly permissionRepository: PermissionRepository,
    private readonly userRoleRepository: UserRoleRepository,
    private readonly groupRoleRepository: GroupRoleRepository
  ) {}

  async createRole(command: CreateRoleCommand): Promise<RoleDto> {
    const role = new Role({
      organizationId: command.organizationId,
      name: command.name,
      description: command.description,
      scopeType: command.scopeType,
      scopeId: command.scopeId
    });
    
    await this.roleRepository.save(role);
    
    return this.mapToDto(role);
  }
  
  async assignRoleToUser(command: AssignRoleToUserCommand): Promise<void> {
    const user = await this.validateUser(command.userId, command.organizationId);
    const role = await this.validateRole(command.roleId, command.organizationId);
    
    this.validateRoleAssignment(user, role, command);
    
    const userRole = new UserRole({
      userId: command.userId,
      roleId: command.roleId,
      assignedBy: command.assignedBy,
      expiresAt: command.expiresAt
    });
    
    await this.userRoleRepository.save(userRole);
  }
  
  async evaluatePermission(userId: UUID, permission: string, context?: PermissionContext): Promise<boolean> {
    const userRoles = await this.getUserRoles(userId);
    
    for (const userRole of userRoles) {
      const role = await this.roleRepository.findById(userRole.roleId);
      const hasPermission = this.checkRolePermission(role, permission);
      
      if (hasPermission && await this.validateScope(role, context)) {
        return true;
      }
    }
    
    return false;
  }
}
```

### Organization Service

Manages organization structure and organization units.

```typescript
@Injectable()
export class OrganizationService {
  constructor(
    private readonly organizationRepository: OrganizationRepository,
    private readonly organizationUnitRepository: OrganizationUnitRepository,
    private readonly eventPublisher: EventPublisher
  ) {}

  async createOrganizationUnit(command: CreateOrganizationUnitCommand): Promise<OrganizationUnitDto> {
    const organization = await this.organizationRepository.findById(command.organizationId);
    const parentUnit = command.parentId 
      ? await this.organizationUnitRepository.findById(command.parentId)
      : null;
    
    this.validateHierarchyDepth(parentUnit);
    this.validateNameUniqueness(command.organizationId, command.parentId, command.name);
    
    const unit = new OrganizationUnit({
      organizationId: command.organizationId,
      parentId: command.parentId,
      name: command.name,
      description: command.description,
      ownerId: command.ownerId
    });
    
    await this.organizationUnitRepository.save(unit);
    
    await this.eventPublisher.publish(new OrganizationUnitCreatedEvent(unit));
    
    return this.mapToDto(unit);
  }
  
  async moveOrganizationUnit(command: MoveOrganizationUnitCommand): Promise<void> {
    const unit = await this.organizationUnitRepository.findById(command.unitId);
    const newParent = command.newParentId 
      ? await this.organizationUnitRepository.findById(command.newParentId)
      : null;
    
    this.validateMove(unit, newParent);
    
    unit.move(newParent?.id, newParent?.hierarchyLevel + 1);
    
    await this.updateChildUnitsHierarchy(unit.id, unit.path);
    await this.organizationUnitRepository.save(unit);
    
    await this.eventPublisher.publish(new OrganizationUnitMovedEvent(unit.id, command.newParentId));
  }
}
```

### Group Management Service

Manages user groups and group-based permissions.

```typescript
@Injectable()
export class GroupService {
  constructor(
    private readonly groupRepository: GroupRepository,
    private readonly groupMemberRepository: GroupMemberRepository,
    private readonly eventPublisher: EventPublisher
  ) {}

  async createGroup(command: CreateGroupCommand): Promise<GroupDto> {
    const group = new Group({
      organizationId: command.organizationId,
      parentId: command.parentId,
      name: command.name,
      description: command.description,
      type: command.type
    });
    
    await this.groupRepository.save(group);
    
    await this.eventPublisher.publish(new GroupCreatedEvent(group));
    
    return this.mapToDto(group);
  }
  
  async addMemberToGroup(command: AddGroupMemberCommand): Promise<void> {
    const group = await this.groupRepository.findById(command.groupId);
    const user = await this.validateUser(command.userId, group.organizationId);
    
    this.validateGroupMembership(user, group);
    
    const member = new GroupMember({
      groupId: command.groupId,
      userId: command.userId,
      addedBy: command.addedBy,
      roleInGroup: command.roleInGroup
    });
    
    await this.groupMemberRepository.save(member);
    
    await this.eventPublisher.publish(new GroupMemberAddedEvent(member));
  }
}
```

### Audit Service

Provides comprehensive audit logging and compliance reporting.

```typescript
@Injectable()
export class AuditService {
  constructor(
    private readonly auditLogRepository: AuditLogRepository,
    private readonly auditEventPublisher: AuditEventPublisher
  ) {}

  async logEvent(event: AuditEvent): Promise<void> {
    const auditLog = new AuditLog({
      userId: event.userId,
      action: event.action,
      resourceType: event.resourceType,
      resourceId: event.resourceId,
      resourceName: event.resourceName,
      oldValues: event.oldValues,
      newValues: event.newValues,
      changes: this.calculateChanges(event.oldValues, event.newValues),
      ipAddress: event.ipAddress,
      userAgent: event.userAgent,
      requestId: event.requestId
    });
    
    await this.auditLogRepository.save(auditLog);
    await this.auditEventPublisher.publish(auditLog);
  }
  
  async getAuditLogs(query: AuditLogQuery): Promise<PaginatedResult<AuditLogDto>> {
    const logs = await this.auditLogRepository.findWithFilters(query);
    const totalCount = await this.auditLogRepository.countWithFilters(query);
    
    return {
      data: logs.map(log => this.mapToDto(log)),
      pagination: {
        page: query.page,
        limit: query.limit,
        total: totalCount,
        hasNext: logs.length === query.limit,
        hasPrev: query.page > 1
      }
    };
  }
  
  private calculateChanges(oldValues: any, newValues: any): any {
    if (!oldValues || !newValues) return {};
    
    const changes: any = {};
    const allKeys = new Set([...Object.keys(oldValues), ...Object.keys(newValues)]);
    
    for (const key of allKeys) {
      if (oldValues[key] !== newValues[key]) {
        changes[key] = {
          old: oldValues[key],
          new: newValues[key]
        };
      }
    }
    
    return changes;
  }
}
```

## Data Flow Architecture

### Request Flow

```mermaid
sequenceDiagram
    participant Client
    participant APIGateway
    participant AuthService
    participant UserService
    participant Database
    participant MessageBroker
    participant NotificationService
    
    Client->>APIGateway: POST /api/v1/users
    APIGateway->>AuthService: Validate JWT token
    AuthService-->>APIGateway: User context
    APIGateway->>UserService: CreateUserCommand
    UserService->>Database: Check organization unit
    Database-->>UserService: Unit details
    UserService->>Database: Save user
    Database-->>UserService: Success
    UserService->>MessageBroker: Publish UserCreatedEvent
    MessageBroker->>NotificationService: Handle event
    NotificationService->>NotificationService: Send welcome email
    UserService-->>APIGateway: User created
    APIGateway-->>Client: 201 Created
```

### Event Flow

```mermaid
sequenceDiagram
    participant UserService
    participant MessageBroker
    participant NotificationService
    participant AuditService
    participant EmailService
    
    UserService->>MessageBroker: Publish UserCreatedEvent
    MessageBroker->>NotificationService: Consume event
    NotificationService->>EmailService: Send welcome email
    EmailService-->>NotificationService: Email sent
    NotificationService->>MessageBroker: Publish EmailSentEvent
    
    MessageBroker->>AuditService: Consume UserCreatedEvent
    AuditService->>AuditService: Log audit event
    AuditService->>AuditService: Store in audit database
```

### CQRS Flow

```mermaid
graph TB
    subgraph "Command Side"
        Command[CreateUserCommand]
        CommandHandler[CreateUserCommandHandler]
        Aggregate[User Aggregate]
        Repository[User Repository]
        Event[UserCreatedEvent]
    end
    
    subgraph "Query Side"
        ReadModel[User Read Model]
        Query[GetUserQuery]
        QueryHandler[GetUserQueryHandler]
        Cache[Redis Cache]
    end
    
    Command --> CommandHandler
    CommandHandler --> Aggregate
    Aggregate --> Repository
    Aggregate --> Event
    
    Event --> ReadModel
    Query --> QueryHandler
    QueryHandler --> Cache
    QueryHandler --> ReadModel
```

## Deployment Architecture

### Development Environment

```yaml
# docker-compose.yml
version: '3.8'
services:
  api-gateway:
    build: ./api-gateway
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=development
      - DATABASE_URL=postgresql://user:password@postgres:5432/direct_dev
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis
      - auth-service
      - user-service
      - role-service

  auth-service:
    build: ./services/auth
    environment:
      - NODE_ENV=development
      - DATABASE_URL=postgresql://user:password@postgres:5432/direct_dev
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis

  user-service:
    build: ./services/user
    environment:
      - NODE_ENV=development
      - DATABASE_URL=postgresql://user:password@postgres:5432/direct_dev
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:14
    environment:
      POSTGRES_DB: direct_dev
      POSTGRES_USER: user
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:6-alpine
    volumes:
      - redis_data:/data

  rabbitmq:
    image: rabbitmq:3-management
    environment:
      RABBITMQ_DEFAULT_USER: user
      RABBITMQ_DEFAULT_PASS: password
    ports:
      - "5672:5672"
      - "15672:15672"

volumes:
  postgres_data:
  redis_data:
```

### Production Environment

```yaml
# kubernetes/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-gateway
  namespace: direct
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api-gateway
  template:
    metadata:
      labels:
        app: api-gateway
    spec:
      containers:
      - name: api-gateway
        image: direct/api-gateway:latest
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: "production"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: database-secret
              key: url
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: redis-secret
              key: url
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"

---
apiVersion: v1
kind: Service
metadata:
  name: api-gateway-service
  namespace: direct
spec:
  selector:
    app: api-gateway
  ports:
  - protocol: TCP
    port: 80
    targetPort: 3000
  type: LoadBalancer
```

### Database Configuration

```yaml
# kubernetes/database.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: database-config
  namespace: direct
data:
  POSTGRES_DB: "direct_prod"
  POSTGRES_USER: "direct_user"
  POSTGRES_PASSWORD_FILE: "/secrets/postgres-password"

---
apiVersion: v1
kind: Secret
metadata:
  name: database-secret
  namespace: direct
type: Opaque
data:
  url: <base64-encoded-database-url>

---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: direct
spec:
  serviceName: postgres
  replicas: 3
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:14
        envFrom:
        - configMapRef:
            name: database-config
        - secretRef:
            name: database-secret
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
  volumeClaimTemplates:
  - metadata:
      name: postgres-storage
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 100Gi
```

## Scalability and Performance

### Horizontal Scaling

```typescript
// Service scaling configuration
const scalingConfig = {
  minReplicas: 3,
  maxReplicas: 20,
  targetCPUUtilizationPercentage: 70,
  targetMemoryUtilizationPercentage: 80,
  scaleUpStabilizationWindowSeconds: 60,
  scaleDownStabilizationWindowSeconds: 300
};

// Kubernetes HPA configuration
const hpaConfig = {
  apiVersion: 'autoscaling/v2',
  kind: 'HorizontalPodAutoscaler',
  metadata: {
    name: 'user-service-hpa',
    namespace: 'direct'
  },
  spec: {
    scaleTargetRef: {
      apiVersion: 'apps/v1',
      kind: 'Deployment',
      name: 'user-service'
    },
    minReplicas: scalingConfig.minReplicas,
    maxReplicas: scalingConfig.maxReplicas,
    metrics: [
      {
        type: 'Resource',
        resource: {
          name: 'cpu',
          target: {
            type: 'Utilization',
            averageUtilization: scalingConfig.targetCPUUtilizationPercentage
          }
        }
      },
      {
        type: 'Resource',
        resource: {
          name: 'memory',
          target: {
            type: 'Utilization',
            averageUtilization: scalingConfig.targetMemoryUtilizationPercentage
          }
        }
      }
    ]
  }
};
```

### Caching Strategy

```typescript
@Injectable()
export class CacheService {
  constructor(private readonly redis: Redis) {}

  async getUserPermissions(userId: UUID): Promise<string[]> {
    const cacheKey = `user:${userId}:permissions`;
    
    // Try cache first
    const cached = await this.redis.get(cacheKey);
    if (cached) {
      return JSON.parse(cached);
    }
    
    // Fetch from database
    const permissions = await this.permissionService.getUserPermissions(userId);
    
    // Cache for 5 minutes
    await this.redis.setex(cacheKey, 300, JSON.stringify(permissions));
    
    return permissions;
  }
  
  async invalidateUserPermissions(userId: UUID): Promise<void> {
    const cacheKey = `user:${userId}:permissions`;
    await this.redis.del(cacheKey);
  }
  
  async invalidateRolePermissions(roleId: UUID): Promise<void> {
    const cacheKey = `role:${roleId}:permissions`;
    await this.redis.del(cacheKey);
    
    // Invalidate all user permissions that might be affected
    const usersWithRole = await this.userRoleRepository.findUsersWithRole(roleId);
    for (const user of usersWithRole) {
      await this.invalidateUserPermissions(user.id);
    }
  }
}
```

### Database Optimization

```sql
-- Connection pooling configuration
ALTER SYSTEM SET max_connections = 200;
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;

-- Query optimization
CREATE INDEX CONCURRENTLY idx_user_roles_active_status 
ON user_roles(user_id, role_id) WHERE status = 'active';

CREATE INDEX CONCURRENTLY idx_group_members_active_status 
ON group_members(user_id, group_id) WHERE status = 'active';

-- Partitioning for audit logs
CREATE TABLE audit_logs_2026_q1 PARTITION OF audit_logs
FOR VALUES FROM ('2026-01-01') TO ('2026-04-01');

-- Materialized views for reporting
CREATE MATERIALIZED VIEW user_role_summary AS
SELECT 
  u.id as user_id,
  u.email,
  u.first_name,
  u.last_name,
  array_agg(r.name) as roles,
  array_agg(r.scope_type) as scope_types
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id AND ur.status = 'active'
LEFT JOIN roles r ON ur.role_id = r.id
WHERE u.status = 'active'
GROUP BY u.id, u.email, u.first_name, u.last_name;
```

### Load Balancing

```yaml
# nginx.conf
upstream api_gateway {
    least_conn;
    server api-gateway-1:3000 max_fails=3 fail_timeout=30s;
    server api-gateway-2:3000 max_fails=3 fail_timeout=30s;
    server api-gateway-3:3000 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    server_name api.direct.example.com;
    
    location / {
        proxy_pass http://api_gateway;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Health check
        proxy_next_upstream error timeout http_502 http_503 http_504;
        proxy_connect_timeout 5s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;
    }
}
```

## Security Architecture

### Authentication Flow

```mermaid
sequenceDiagram
    participant Client
    participant APIGateway
    participant AuthService
    participant Redis
    participant Database
    
    Client->>APIGateway: Request with JWT
    APIGateway->>AuthService: Validate token
    AuthService->>Redis: Check token blacklist
    Redis-->>AuthService: Token status
    alt Token valid
        AuthService->>Database: Get user permissions
        Database-->>AuthService: Permissions
        AuthService-->>APIGateway: User context
        APIGateway->>APIGateway: Process request
    else Token invalid
        AuthService-->>APIGateway: 401 Unauthorized
        APIGateway-->>Client: 401 Unauthorized
    end
```

### Security Headers

```typescript
const securityMiddleware = (req: Request, res: Response, next: NextFunction) => {
  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // Rate limiting
  const clientIp = req.ip || req.connection.remoteAddress;
  const rateLimit = await rateLimiter.checkRateLimit(clientIp, 100, 60000);
  
  if (!rateLimit.allowed) {
    return res.status(429).json({
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many requests',
        retryAfter: rateLimit.resetTime
      }
    });
  }
  
  next();
};
```

### Data Encryption

```typescript
class EncryptionService {
  private readonly algorithm = 'aes-256-gcm';
  private readonly key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
  
  encrypt(text: string): EncryptedData {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher(this.algorithm, this.key);
    cipher.setAAD(Buffer.from('direct-organization-system', 'utf8'));
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return {
      encryptedData: encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    };
  }
  
  decrypt(encryptedData: EncryptedData): string {
    const decipher = crypto.createDecipher(this.algorithm, this.key);
    decipher.setAAD(Buffer.from('direct-organization-system', 'utf8'));
    decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
    
    let decrypted = decipher.update(encryptedData.encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
}
```

## Monitoring and Observability

### Metrics Collection

```typescript
@Injectable()
export class MetricsService {
  private readonly httpRequestDuration = new prometheus.Histogram({
    name: 'http_request_duration_seconds',
    help: 'Duration of HTTP requests in seconds',
    labelNames: ['method', 'route', 'status_code']
  });
  
  private readonly activeUsers = new prometheus.Gauge({
    name: 'active_users_total',
    help: 'Number of active users',
    labelNames: ['organization_id']
  });
  
  private readonly databaseConnections = new prometheus.Gauge({
    name: 'database_connections_active',
    help: 'Number of active database connections',
    labelNames: ['database_name']
  });
  
  recordHttpRequest(method: string, route: string, statusCode: number, duration: number): void {
    this.httpRequestDuration
      .labels(method, route, statusCode.toString())
      .observe(duration);
  }
  
  updateActiveUsers(organizationId: string, count: number): void {
    this.activeUsers.labels(organizationId).set(count);
  }
  
  updateDatabaseConnections(databaseName: string, count: number): void {
    this.databaseConnections.labels(databaseName).set(count);
  }
}
```

### Logging Strategy

```typescript
@Injectable()
export class LoggerService {
  private readonly logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.errors({ stack: true }),
      winston.format.json()
    ),
    transports: [
      new winston.transports.File({ filename: 'error.log', level: 'error' }),
      new winston.transports.File({ filename: 'combined.log' }),
      new winston.transports.Console({
        format: winston.format.simple()
      })
    ]
  });
  
  logAuditEvent(event: AuditEvent): void {
    this.logger.info('AUDIT_EVENT', {
      userId: event.userId,
      action: event.action,
      resourceType: event.resourceType,
      resourceId: event.resourceId,
      ipAddress: event.ipAddress,
      userAgent: event.userAgent,
      timestamp: new Date().toISOString()
    });
  }
  
  logSecurityEvent(event: SecurityEvent): void {
    this.logger.warn('SECURITY_EVENT', {
      type: event.type,
      userId: event.userId,
      details: event.details,
      ipAddress: event.ipAddress,
      timestamp: new Date().toISOString()
    });
  }
}
```

### Distributed Tracing

```typescript
@Injectable()
export class TracingService {
  private readonly tracer = opentelemetry.trace.getTracer('direct-organization-system');
  
  async traceOperation<T>(
    operationName: string,
    operation: (span: Span) => Promise<T>
  ): Promise<T> {
    return this.tracer.startActiveSpan(operationName, async (span) => {
      try {
        const result = await operation(span);
        span.setStatus({ code: SpanStatusCode.OK });
        return result;
      } catch (error) {
        span.recordException(error);
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: error.message
        });
        throw error;
      } finally {
        span.end();
      }
    });
  }
  
  addSpanAttributes(attributes: Record<string, string | number | boolean>): void {
    const span = opentelemetry.trace.getActiveSpan();
    if (span) {
      Object.entries(attributes).forEach(([key, value]) => {
        span.setAttribute(key, value);
      });
    }
  }
}
```

## Integration Patterns

### API Gateway Pattern

```typescript
@Injectable()
export class ApiGatewayService {
  constructor(
    private readonly authService: AuthService,
    private readonly userService: UserService,
    private readonly roleService: RoleService,
    private readonly groupService: GroupService
  ) {}

  @Post('/users')
  @UseGuards(AuthGuard)
  @Roles('ADMIN', 'OU_OWNER')
  async createUser(@Body() createUserDto: CreateUserDto): Promise<UserDto> {
    return this.userService.createUser({
      organizationId: createUserDto.organizationId,
      organizationUnitId: createUserDto.organizationUnitId,
      email: createUserDto.email,
      firstName: createUserDto.firstName,
      lastName: createUserDto.lastName
    });
  }
  
  @Get('/users/:id')
  @UseGuards(AuthGuard)
  @HasPermission('view_users')
  async getUser(@Param('id') userId: string): Promise<UserDto> {
    return this.userService.getUser(userId);
  }
}
```

### Service Mesh Integration

```yaml
# istio-virtual-service.yaml
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: direct-api-gateway
  namespace: direct
spec:
  hosts:
  - api.direct.example.com
  http:
  - match:
    - uri:
        prefix: /api/v1/
    route:
    - destination:
        host: api-gateway
        port:
          number: 3000
    fault:
      delay:
        percentage:
          value: 0.1
        fixedDelay: 5s
    retries:
      attempts: 3
      perTryTimeout: 2s
      retryOn: 5xx,reset,connect-failure,refused-stream
```

### Event Sourcing

```typescript
@Injectable()
export class EventStoreService {
  constructor(private readonly eventRepository: EventRepository) {}

  async saveEvent(event: DomainEvent): Promise<void> {
    const eventRecord = new EventRecord({
      aggregateId: event.aggregateId,
      eventType: event.type,
      eventData: JSON.stringify(event),
      eventVersion: event.version,
      timestamp: new Date(),
      metadata: event.metadata
    });
    
    await this.eventRepository.save(eventRecord);
  }
  
  async getEvents(aggregateId: UUID): Promise<DomainEvent[]> {
    const eventRecords = await this.eventRepository.findByAggregateId(aggregateId);
    
    return eventRecords.map(record => ({
      ...JSON.parse(record.eventData),
      version: record.eventVersion,
      timestamp: record.timestamp
    }));
  }
  
  async replayEvents(aggregateId: UUID, aggregate: AggregateRoot): Promise<void> {
    const events = await this.getEvents(aggregateId);
    
    for (const event of events) {
      aggregate.apply(event);
    }
  }
}
```

This comprehensive system architecture provides a robust, scalable, and secure foundation for the Direct Organization Management System, supporting all the complex requirements including scoped roles and permissions while maintaining high performance and reliability.