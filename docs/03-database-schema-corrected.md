# Direct Organization Management System - Database Schema (Corrected)

**Document Version**: 1.1  
**Created**: February 2026  
**Last Updated**: February 2026  
**Status**: Draft

## Table of Contents

1. [Database Overview](#database-overview)
2. [Schema Design Principles](#schema-design-principles)
3. [Core Tables](#core-tables)
4. [Relationship Tables](#relationship-tables)
5. [System Tables](#system-tables)
6. [Scoped Roles Implementation](#scoped-roles-implementation)
7. [Index Strategy](#index-strategy)
8. [Constraints and Application Logic](#constraints-and-application-logic)
9. [Partitioning Strategy](#partitioning-strategy)
10. [Performance Optimization](#performance-optimization)

## Database Overview

The Direct Organization Management System uses PostgreSQL as its primary database with Redis for caching. The database schema is designed to support enterprise-scale operations while maintaining data integrity, performance, and scalability.

### Database Specifications

- **Primary Database**: PostgreSQL 14+
- **Cache Layer**: Redis 6+
- **Connection Pooling**: pgBouncer
- **Monitoring**: pg_stat_statements, pgBadger
- **Backup Strategy**: WAL archiving with point-in-time recovery

### Schema Organization

The database is organized into logical schemas:

- **public**: Core business entities and relationships
- **audit**: Immutable audit trail tables
- **system**: System configuration and metadata
- **temp**: Temporary tables for batch operations

## Schema Design Principles

### Normalization Strategy

The schema follows third normal form (3NF) with strategic denormalization for performance:

- **3NF Compliance**: Eliminate transitive dependencies
- **Selective Denormalization**: Materialized paths for hierarchy queries
- **JSON Storage**: Flexible attributes in JSON columns
- **Reference Data**: Separate lookup tables for enumerated values

### Naming Conventions

```sql
-- Table naming
organizations, organization_units, users, roles, permissions, groups

-- Column naming
snake_case, id for primary keys, _id for foreign keys

-- Index naming
idx_table_column, uk_table_column for unique constraints

-- Constraint naming
fk_table_referenced_table, chk_table_column for check constraints
```

### Data Types

```sql
-- UUID for primary keys
id UUID PRIMARY KEY DEFAULT gen_random_uuid()

-- Timestamps with timezone
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP

-- JSON for flexible data
contact_info JSONB, profile_data JSONB

-- Enums for status fields
status VARCHAR(20) NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'inactive', 'deleted'))
```

## Core Tables

### organizations

The root entity representing complete organizational isolation.

```sql
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    contact_info JSONB NOT NULL,
    address JSONB,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,
    
    -- Constraints
    CONSTRAINT chk_org_name_length CHECK (length(name) >= 2),
    CONSTRAINT chk_org_contact_info CHECK (
        contact_info ? 'email' AND 
        contact_info ->> 'email' ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
    )
);

-- Indexes
CREATE INDEX idx_organizations_name ON organizations(name);
CREATE INDEX idx_organizations_status ON organizations(status);
CREATE INDEX idx_organizations_created_at ON organizations(created_at);
```

### organization_units

Hierarchical organizational structure for functional management.

```sql
CREATE TABLE organization_units (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    parent_id UUID REFERENCES organization_units(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    address JSONB,
    owner_id UUID NOT NULL,
    hierarchy_level INTEGER NOT NULL DEFAULT 0 CHECK (hierarchy_level >= 0),
    path VARCHAR(1000) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,
    
    -- Constraints
    CONSTRAINT uk_org_unit_name_parent UNIQUE (organization_id, parent_id, name),
    CONSTRAINT chk_hierarchy_level CHECK (hierarchy_level <= 10),
    CONSTRAINT chk_path_format CHECK (path ~ '^[0-9a-f-]+(\.[0-9a-f-]+)*$')
);

-- Indexes
CREATE INDEX idx_org_units_org_id ON organization_units(organization_id);
CREATE INDEX idx_org_units_parent_id ON organization_units(parent_id);
CREATE INDEX idx_org_units_path ON organization_units USING GIN(path gin_trgm_ops);
CREATE INDEX idx_org_units_owner_id ON organization_units(owner_id);
CREATE INDEX idx_org_units_hierarchy_level ON organization_units(hierarchy_level);
CREATE INDEX idx_org_units_status ON organization_units(status);
```

### users

Individual user accounts with profile information and access control.

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    organization_unit_id UUID REFERENCES organization_units(id) ON DELETE SET NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    phone VARCHAR(20),
    profile_data JSONB,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    last_login_at TIMESTAMP WITH TIME ZONE,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,
    
    -- Constraints
    CONSTRAINT chk_user_name_length CHECK (
        length(first_name) >= 2 AND length(last_name) >= 2
    ),
    CONSTRAINT chk_user_email_format CHECK (
        email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
    ),
    CONSTRAINT chk_failed_attempts CHECK (failed_login_attempts >= 0),
    CONSTRAINT chk_org_unit_belongs_to_org CHECK (
        organization_unit_id IS NULL OR 
        EXISTS (
            SELECT 1 FROM organization_units ou 
            WHERE ou.id = organization_unit_id 
            AND ou.organization_id = organization_id
        )
    )
);

-- Indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_org_id ON users(organization_id);
CREATE INDEX idx_users_org_unit_id ON users(organization_unit_id);
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_last_login ON users(last_login_at);
CREATE INDEX idx_users_failed_attempts ON users(failed_login_attempts);
```

### roles

Collections of permissions that can be assigned to users or groups.

```sql
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(20) NOT NULL DEFAULT 'custom',
    scope_type VARCHAR(50) DEFAULT 'organization',
    scope_id UUID,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,
    
    -- Constraints
    CONSTRAINT uk_role_name_org_scope UNIQUE (organization_id, name, scope_type, scope_id),
    CONSTRAINT chk_scope_consistency CHECK (
        (scope_type = 'organization' AND scope_id IS NULL) OR
        (scope_type = 'group' AND scope_id IS NOT NULL) OR
        (scope_type = 'organization_unit' AND scope_id IS NOT NULL)
    ),
    CONSTRAINT chk_scope_references CHECK (
        (scope_type = 'group' AND EXISTS (SELECT 1 FROM groups WHERE id = scope_id)) OR
        (scope_type = 'organization_unit' AND EXISTS (SELECT 1 FROM organization_units WHERE id = scope_id)) OR
        (scope_type = 'organization')
    )
);

-- Indexes
CREATE INDEX idx_roles_org_id ON roles(organization_id);
CREATE INDEX idx_roles_type ON roles(type);
CREATE INDEX idx_roles_status ON roles(status);
CREATE INDEX idx_roles_scope ON roles(scope_type, scope_id);
CREATE INDEX idx_roles_name ON roles(name);
```

### permissions

Atomic access control units that can be assigned to roles.

```sql
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    type VARCHAR(20) NOT NULL DEFAULT 'system',
    category VARCHAR(100),
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,
    
    -- Constraints
    CONSTRAINT chk_permission_type_consistency CHECK (
        (type = 'system' AND is_system_permission = true) OR
        (type = 'custom' AND is_system_permission = false)
    )
);

-- Indexes
CREATE INDEX idx_permissions_type ON permissions(type);
CREATE INDEX idx_permissions_category ON permissions(category);
CREATE INDEX idx_permissions_status ON permissions(status);
```

### groups

Collections of users for role and permission management.

```sql
CREATE TABLE groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    parent_id UUID REFERENCES groups(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(20) NOT NULL DEFAULT 'custom',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,
    
    -- Constraints
    CONSTRAINT uk_group_name_org UNIQUE (organization_id, name),
    CONSTRAINT chk_group_hierarchy CHECK (
        parent_id IS NULL OR 
        EXISTS (
            SELECT 1 FROM groups g2 
            WHERE g2.id = parent_id 
            AND g2.organization_id = organization_id
        )
    )
);

-- Indexes
CREATE INDEX idx_groups_org_id ON groups(organization_id);
CREATE INDEX idx_groups_parent_id ON groups(parent_id);
CREATE INDEX idx_groups_type ON groups(type);
CREATE INDEX idx_groups_status ON groups(status);
```

## Relationship Tables

### user_roles

Many-to-many relationship between users and roles.

```sql
CREATE TABLE user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_by UUID NOT NULL REFERENCES users(id),
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Constraints
    CONSTRAINT uk_user_role UNIQUE (user_id, role_id),
    CONSTRAINT chk_assignment_validity CHECK (
        assigned_by IS NOT NULL AND 
        EXISTS (
            SELECT 1 FROM users u2 
            WHERE u2.id = assigned_by 
            AND u2.organization_id = (
                SELECT organization_id FROM users WHERE id = user_id
            )
        )
    ),
    CONSTRAINT chk_expiration_future CHECK (
        expires_at IS NULL OR expires_at > assigned_at
    )
);

-- Indexes
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX idx_user_roles_assigned_by ON user_roles(assigned_by);
CREATE INDEX idx_user_roles_expires_at ON user_roles(expires_at);
CREATE INDEX idx_user_roles_status ON user_roles(status);
CREATE INDEX idx_user_roles_assigned_at ON user_roles(assigned_at);
```

### role_permissions

Many-to-many relationship between roles and permissions.

```sql
CREATE TABLE role_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_by UUID NOT NULL REFERENCES users(id),
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Constraints
    CONSTRAINT uk_role_permission UNIQUE (role_id, permission_id),
    CONSTRAINT chk_permission_assignment CHECK (
        granted_by IS NOT NULL AND 
        EXISTS (
            SELECT 1 FROM users u 
            WHERE u.id = granted_by AND u.status = 'active'
        )
    ),
    CONSTRAINT chk_system_permission_restriction CHECK (
        NOT (
            EXISTS (SELECT 1 FROM roles r WHERE r.id = role_id AND r.is_system_role = true) AND
            EXISTS (SELECT 1 FROM permissions p WHERE p.id = permission_id AND p.is_system_permission = false)
        )
    )
);

-- Indexes
CREATE INDEX idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission_id ON role_permissions(permission_id);
CREATE INDEX idx_role_permissions_granted_by ON role_permissions(granted_by);
CREATE INDEX idx_role_permissions_status ON role_permissions(status);
CREATE INDEX idx_role_permissions_granted_at ON role_permissions(granted_at);
```

### group_members

Many-to-many relationship between groups and users.

```sql
CREATE TABLE group_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    added_by UUID NOT NULL REFERENCES users(id),
    added_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    role_in_group VARCHAR(50) DEFAULT 'member',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Constraints
    CONSTRAINT uk_group_member UNIQUE (group_id, user_id),
    CONSTRAINT chk_member_validity CHECK (
        added_by IS NOT NULL AND 
        EXISTS (
            SELECT 1 FROM users u2 
            WHERE u2.id = added_by 
            AND u2.organization_id = (
                SELECT organization_id FROM users WHERE id = user_id
            )
        )
    ),
    CONSTRAINT chk_user_in_same_organization CHECK (
        EXISTS (
            SELECT 1 FROM users u 
            WHERE u.id = user_id AND u.organization_id = (
                SELECT organization_id FROM groups WHERE id = group_id
            )
        )
    )
);

-- Indexes
CREATE INDEX idx_group_members_group_id ON group_members(group_id);
CREATE INDEX idx_group_members_user_id ON group_members(user_id);
CREATE INDEX idx_group_members_added_by ON group_members(added_by);
CREATE INDEX idx_group_members_role_in_group ON group_members(role_in_group);
CREATE INDEX idx_group_members_status ON group_members(status);
CREATE INDEX idx_group_members_added_at ON group_members(added_at);
```

### group_roles

Many-to-many relationship between groups and roles.

```sql
CREATE TABLE group_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_by UUID NOT NULL REFERENCES users(id),
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Constraints
    CONSTRAINT uk_group_role UNIQUE (group_id, role_id),
    CONSTRAINT chk_group_role_validity CHECK (
        assigned_by IS NOT NULL AND 
        EXISTS (
            SELECT 1 FROM users u2 
            WHERE u2.id = assigned_by AND u2.status = 'active'
        )
    ),
    CONSTRAINT chk_group_role_organization CHECK (
        EXISTS (
            SELECT 1 FROM groups g, roles r 
            WHERE g.id = group_id AND r.id = role_id 
            AND g.organization_id = r.organization_id
        )
    ),
    CONSTRAINT chk_group_role_scope CHECK (
        -- For group-scoped roles assigned to groups, ensure consistency
        NOT (
            EXISTS (SELECT 1 FROM roles r WHERE r.id = role_id AND r.scope_type = 'group' AND r.scope_id != group_id)
        )
    )
);

-- Indexes
CREATE INDEX idx_group_roles_group_id ON group_roles(group_id);
CREATE INDEX idx_group_roles_role_id ON group_roles(role_id);
CREATE INDEX idx_group_roles_assigned_by ON group_roles(assigned_by);
CREATE INDEX idx_group_roles_status ON group_roles(status);
CREATE INDEX idx_group_roles_assigned_at ON group_roles(assigned_at);
```

## System Tables

### audit_logs

Immutable audit trail for all system changes.

```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,
    resource_name VARCHAR(255),
    old_values JSONB,
    new_values JSONB,
    changes JSONB,
    ip_address INET,
    user_agent TEXT,
    request_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Constraints
    CONSTRAINT chk_action_type CHECK (action IN (
        'CREATE', 'READ', 'UPDATE', 'DELETE', 'ASSIGN', 'REVOKE', 'LOGIN', 'LOGOUT'
    ))
);

-- Indexes
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_resource_type ON audit_logs(resource_type);
CREATE INDEX idx_audit_logs_resource_id ON audit_logs(resource_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_request_id ON audit_logs(request_id);

-- Partitioning by date
CREATE TABLE audit_logs_2026_q1 PARTITION OF audit_logs
FOR VALUES FROM ('2026-01-01') TO ('2026-04-01');

CREATE TABLE audit_logs_2026_q2 PARTITION OF audit_logs
FOR VALUES FROM ('2026-04-01') TO ('2026-07-01');

CREATE TABLE audit_logs_2026_q3 PARTITION OF audit_logs
FOR VALUES FROM ('2026-07-01') TO ('2026-10-01');

CREATE TABLE audit_logs_2026_q4 PARTITION OF audit_logs
FOR VALUES FROM ('2026-10-01') TO ('2027-01-01');
```

### sessions

User session management for authentication.

```sql
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    refresh_token_hash VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Constraints
    CONSTRAINT uk_session_token_hash UNIQUE (token_hash),
    CONSTRAINT chk_session_expiration CHECK (expires_at > created_at)
);

-- Indexes
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_last_activity ON sessions(last_activity_at);
CREATE INDEX idx_sessions_is_active ON sessions(is_active);
```

### invitations

User invitation management.

```sql
CREATE TABLE invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    invited_by UUID NOT NULL REFERENCES users(id),
    organization_unit_id UUID REFERENCES organization_units(id),
    role_ids UUID[],
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    accepted_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Constraints
    CONSTRAINT uk_invitation_token UNIQUE (token_hash),
    CONSTRAINT chk_invitation_validity CHECK (
        invited_by IS NOT NULL AND 
        EXISTS (
            SELECT 1 FROM users u 
            WHERE u.id = invited_by AND u.status = 'active'
        )
    ),
    CONSTRAINT chk_invitation_org_unit CHECK (
        organization_unit_id IS NULL OR 
        EXISTS (
            SELECT 1 FROM organization_units ou 
            WHERE ou.id = organization_unit_id 
            AND ou.organization_id = organization_id
        )
    )
);

-- Indexes
CREATE INDEX idx_invitations_organization_id ON invitations(organization_id);
CREATE INDEX idx_invitations_email ON invitations(email);
CREATE INDEX idx_invitations_invited_by ON invitations(invited_by);
CREATE INDEX idx_invitations_token_hash ON invitations(token_hash);
CREATE INDEX idx_invitations_expires_at ON invitations(expires_at);
CREATE INDEX idx_invitations_status ON invitations(status);
```

## Scoped Roles Implementation

### Understanding Scoped Roles

Scoped roles address the specific requirement you mentioned: `groupId:roleId` patterns where a role's permissions are limited to a specific context (group, organization unit).

#### The Role Naming Problem

You correctly identified a critical issue: the original constraint `uk_role_name_org UNIQUE (organization_id, name)` would prevent having multiple roles with the same name but different scopes. For example:

- OU_OWNER role for Organization Unit 1
- OU_OWNER role for Organization Unit 2  
- GROUP_OWNER role for Group A
- GROUP_OWNER role for Group B

#### Solution: Scope-Aware Unique Constraint

The solution is to include scope information in the unique constraint:

```sql
-- OLD (problematic) constraint
CONSTRAINT uk_role_name_org UNIQUE (organization_id, name)

-- NEW (correct) constraint  
CONSTRAINT uk_role_name_org_scope UNIQUE (organization_id, name, scope_type, scope_id)
```

This allows:
- Multiple "OU_OWNER" roles, each scoped to different organization units
- Multiple "GROUP_OWNER" roles, each scoped to different groups
- Organization-level roles with the same name as scoped roles (since scope_id is NULL)

#### Example Scenarios

```sql
-- Organization-level roles (scope_id = NULL)
INSERT INTO roles (organization_id, name, description, scope_type, scope_id) VALUES
('org-uuid', 'ADMIN', 'Organization-wide administrator', 'organization', NULL),
('org-uuid', 'USER', 'Basic organization user', 'organization', NULL);

-- Organization unit-scoped roles
INSERT INTO roles (organization_id, name, description, scope_type, scope_id) VALUES
('org-uuid', 'OU_OWNER', 'Owner of Engineering department', 'organization_unit', 'ou-engineering-uuid'),
('org-uuid', 'OU_OWNER', 'Owner of Marketing department', 'organization_unit', 'ou-marketing-uuid'),
('org-uuid', 'OU_MANAGER', 'Manager of Engineering department', 'organization_unit', 'ou-engineering-uuid');

-- Group-scoped roles
INSERT INTO roles (organization_id, name, description, scope_type, scope_id) VALUES
('org-uuid', 'GROUP_OWNER', 'Owner of Developers group', 'group', 'group-developers-uuid'),
('org-uuid', 'GROUP_OWNER', 'Owner of Designers group', 'group', 'group-designers-uuid'),
('org-uuid', 'GROUP_MANAGER', 'Manager of Developers group', 'group', 'group-developers-uuid');
```

This design allows the same role name to exist multiple times within an organization, as long as they have different scopes, which is exactly what's needed for hierarchical role management.

### Database Schema for Scoped Roles

The key is the `scope_type` and `scope_id` fields in the `roles` table:

```sql
-- Roles table with scope support
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(20) NOT NULL DEFAULT 'custom',
    scope_type VARCHAR(50) DEFAULT 'organization',  -- NEW: 'organization', 'group', 'organization_unit'
    scope_id UUID,                                  -- NEW: references group_id or organization_unit_id
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,
    
    -- Constraints
    CONSTRAINT uk_role_name_org_scope UNIQUE (organization_id, name, scope_type, scope_id),
    CONSTRAINT chk_scope_consistency CHECK (
        (scope_type = 'organization' AND scope_id IS NULL) OR
        (scope_type = 'group' AND scope_id IS NOT NULL) OR
        (scope_type = 'organization_unit' AND scope_id IS NOT NULL)
    ),
    CONSTRAINT chk_scope_references CHECK (
        (scope_type = 'group' AND EXISTS (SELECT 1 FROM groups WHERE id = scope_id)) OR
        (scope_type = 'organization_unit' AND EXISTS (SELECT 1 FROM organization_units WHERE id = scope_id)) OR
        (scope_type = 'organization')
    )
);
```

### Permission Evaluation with Scoped Roles

The critical implementation is in the permission evaluation logic:

```sql
-- Function to check if a user has a permission within a specific context
CREATE OR REPLACE FUNCTION has_permission_in_context(
    user_id UUID,
    permission_name VARCHAR(255),
    context_type VARCHAR(50),
    context_id UUID
) RETURNS BOOLEAN AS $$
DECLARE
    has_permission BOOLEAN := FALSE;
BEGIN
    -- Check organization-level permissions (no scope restrictions)
    SELECT EXISTS(
        SELECT 1
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.id
        JOIN role_permissions rp ON r.id = rp.role_id
        JOIN permissions p ON rp.permission_id = p.id
        WHERE ur.user_id = $1
        AND ur.status = 'active'
        AND r.scope_type = 'organization'
        AND p.name = $2
    ) INTO has_permission;
    
    IF has_permission THEN
        RETURN TRUE;
    END IF;
    
    -- Check scoped permissions
    CASE $3
        WHEN 'group' THEN
            -- Check group-scoped permissions
            SELECT EXISTS(
                SELECT 1
                FROM user_roles ur
                JOIN roles r ON ur.role_id = r.id
                JOIN role_permissions rp ON r.id = rp.role_id
                JOIN permissions p ON rp.permission_id = p.id
                WHERE ur.user_id = $1
                AND ur.status = 'active'
                AND r.scope_type = 'group'
                AND r.scope_id = $4
                AND p.name = $2
                AND EXISTS (
                    SELECT 1 FROM group_members gm 
                    WHERE gm.user_id = $1 
                    AND gm.group_id = $4 
                    AND gm.status = 'active'
                )
            ) INTO has_permission;
            
        WHEN 'organization_unit' THEN
            -- Check organization unit-scoped permissions
            SELECT EXISTS(
                SELECT 1
                FROM user_roles ur
                JOIN roles r ON ur.role_id = r.id
                JOIN role_permissions rp ON r.id = rp.role_id
                JOIN permissions p ON rp.permission_id = p.id
                WHERE ur.user_id = $1
                AND ur.status = 'active'
                AND r.scope_type = 'organization_unit'
                AND r.scope_id = $4
                AND p.name = $2
                AND EXISTS (
                    SELECT 1 FROM users u 
                    WHERE u.id = $1 
                    AND u.organization_unit_id = $4
                )
            ) INTO has_permission;
    END CASE;
    
    RETURN has_permission;
END;
$$ LANGUAGE plpgsql;
```

### Role Assignment with Context Validation

When assigning scoped roles, the system must validate the assigner's permissions within that context:

```sql
-- Function to validate role assignment permissions
CREATE OR REPLACE FUNCTION validate_role_assignment(
    assigner_id UUID,
    role_id UUID,
    user_id UUID,
    context_type VARCHAR(50),
    context_id UUID
) RETURNS BOOLEAN AS $$
DECLARE
    assigner_has_permission BOOLEAN := FALSE;
BEGIN
    -- Check if assigner has permission to assign roles
    SELECT EXISTS(
        SELECT 1
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.id
        JOIN role_permissions rp ON r.id = rp.role_id
        JOIN permissions p ON rp.permission_id = p.id
        WHERE ur.user_id = $1
        AND ur.status = 'active'
        AND p.name = 'assign_roles'
    ) INTO assigner_has_permission;
    
    IF NOT assigner_has_permission THEN
        RETURN FALSE;
    END IF;
    
    -- For scoped roles, check if assigner has appropriate scope permissions
    IF $3 IS NOT NULL THEN
        CASE $4
            WHEN 'group' THEN
                -- Check if assigner is group owner/manager
                SELECT EXISTS(
                    SELECT 1
                    FROM group_members gm
                    WHERE gm.user_id = $1
                    AND gm.group_id = $5
                    AND gm.role_in_group IN ('owner', 'manager')
                    AND gm.status = 'active'
                ) INTO assigner_has_permission;
                
            WHEN 'organization_unit' THEN
                -- Check if assigner is organization unit owner
                SELECT EXISTS(
                    SELECT 1
                    FROM organization_units ou
                    WHERE ou.id = $5
                    AND ou.owner_id = $1
                ) INTO assigner_has_permission;
        END CASE;
        
        IF NOT assigner_has_permission THEN
            RETURN FALSE;
        END IF;
    END IF;
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;
```

### API Support for Scoped Roles

The API supports scoped role assignment through context-aware endpoints:

```http
POST /api/v1/organizations/{orgId}/users/{userId}/roles
Content-Type: application/json

{
  "roleId": "role-uuid",
  "context": {
    "type": "group",
    "id": "group-developers-uuid"
  },
  "expiresAt": "2024-12-31T23:59:59Z"
}
```

### Database Migration for Scoped Roles

```sql
-- Migration script to add scoped roles support
ALTER TABLE roles ADD COLUMN scope_type VARCHAR(50) DEFAULT 'organization';
ALTER TABLE roles ADD COLUMN scope_id UUID;

-- Add constraints
ALTER TABLE roles ADD CONSTRAINT chk_scope_consistency CHECK (
    (scope_type = 'organization' AND scope_id IS NULL) OR
    (scope_type = 'group' AND scope_id IS NOT NULL) OR
    (scope_type = 'organization_unit' AND scope_id IS NOT NULL)
);

-- Update existing roles to be organization-scoped
UPDATE roles SET scope_type = 'organization', scope_id = NULL;

-- Create index for scoped role queries
CREATE INDEX idx_roles_scope ON roles(scope_type, scope_id);
```

This implementation directly addresses your concern about `groupId:roleId` patterns by providing a robust database schema that supports context-aware role assignment and permission evaluation, ensuring that scoped roles work correctly within their designated boundaries.

## Index Strategy

### Performance-Critical Indexes

```sql
-- Permission evaluation indexes
CREATE INDEX idx_permission_evaluation ON user_roles(user_id, role_id) 
WHERE status = 'active';

CREATE INDEX idx_group_permission_evaluation ON group_members(user_id, group_id) 
WHERE status = 'active';

-- Hierarchy query indexes
CREATE INDEX idx_org_unit_hierarchy ON organization_units(organization_id, path) 
WHERE status = 'active';

-- Search and filtering indexes
CREATE INDEX idx_users_search ON users(organization_id, status, last_login_at);

CREATE INDEX idx_audit_search ON audit_logs(user_id, action, created_at);
```

### Composite Indexes for Common Queries

```sql
-- Organization unit management
CREATE INDEX idx_org_units_management ON organization_units(
    organization_id, parent_id, status, hierarchy_level
);

-- User role management
CREATE INDEX idx_user_role_management ON user_roles(
    user_id, role_id, status, assigned_at
);

-- Group membership management
CREATE INDEX idx_group_member_management ON group_members(
    group_id, user_id, role_in_group, status
);

-- Permission checking
CREATE INDEX idx_permission_check ON role_permissions(
    role_id, permission_id, status
);
```

### Full-Text Search Indexes

```sql
-- Organization and unit search
CREATE INDEX idx_organizations_fts ON organizations 
USING GIN (to_tsvector('english', name || ' ' || contact_info->>'email'));

CREATE INDEX idx_org_units_fts ON organization_units 
USING GIN (to_tsvector('english', name || ' ' || COALESCE(description, '')));

-- User search
CREATE INDEX idx_users_fts ON users 
USING GIN (to_tsvector('english', first_name || ' ' || last_name || ' ' || email));
```

## Constraints and Application Logic

### Data Integrity Constraints

All data integrity constraints are enforced at the database level without triggers:

```sql
-- Check constraints for data validation
-- These are already defined in the table definitions above

-- Foreign key constraints for referential integrity
-- These are already defined in the table definitions above

-- Unique constraints for business rules
-- These are already defined in the table definitions above
```

### Application-Level Business Rules

All business logic and validation rules are implemented in the application layer:

#### Organization Unit Hierarchy Management

```typescript
// Application service for organization unit management
class OrganizationUnitService {
    async createOrganizationUnit(
        organizationId: UUID, 
        parentUnitId: UUID | null, 
        name: string, 
        ownerId: UUID
    ): Promise<OrganizationUnit> {
        // 1. Validate hierarchy depth
        if (parentUnitId) {
            const parentUnit = await this.getOrganizationUnit(parentUnitId);
            if (parentUnit.hierarchyLevel >= 9) {
                throw new ValidationError('Maximum hierarchy depth exceeded');
            }
        }
        
        // 2. Validate name uniqueness within parent
        const existingUnit = await this.findOrganizationUnitByNameAndParent(
            organizationId, 
            parentUnitId, 
            name
        );
        if (existingUnit) {
            throw new ValidationError('Organization unit name must be unique within parent');
        }
        
        // 3. Validate owner belongs to organization
        const owner = await this.getUser(ownerId);
        if (owner.organizationId !== organizationId) {
            throw new ValidationError('Owner must belong to the same organization');
        }
        
        // 4. Calculate hierarchy level and path
        const hierarchyLevel = parentUnitId ? 
            (await this.getOrganizationUnit(parentUnitId)).hierarchyLevel + 1 : 0;
        
        const path = parentUnitId ? 
            (await this.getOrganizationUnit(parentUnitId)).path + '.' + uuid() : uuid();
        
        // 5. Create organization unit
        const unit = new OrganizationUnit({
            organizationId,
            parentUnitId,
            name,
            ownerId,
            hierarchyLevel,
            path,
            status: 'active'
        });
        
        return await this.organizationUnitRepository.save(unit);
    }
    
    async moveOrganizationUnit(
        unitId: UUID, 
        newParentId: UUID | null
    ): Promise<void> {
        const unit = await this.getOrganizationUnit(unitId);
        const newParent = newParentId ? await this.getOrganizationUnit(newParentId) : null;
        
        // 1. Validate hierarchy depth
        if (newParent && newParent.hierarchyLevel >= 9) {
            throw new ValidationError('Maximum hierarchy depth would be exceeded');
        }
        
        // 2. Prevent circular references
        if (newParentId === unitId) {
            throw new ValidationError('Organization unit cannot be its own parent');
        }
        
        // 3. Check for circular references in hierarchy
        if (newParentId && await this.hasCircularReference(unitId, newParentId)) {
            throw new ValidationError('Circular reference detected in hierarchy');
        }
        
        // 4. Update unit with new parent
        unit.parentId = newParentId;
        unit.hierarchyLevel = newParent ? newParent.hierarchyLevel + 1 : 0;
        unit.path = this.calculatePath(newParentId, unitId);
        
        // 5. Update all child units recursively
        await this.updateChildUnitsHierarchy(unitId, unit.path);
        
        await this.organizationUnitRepository.save(unit);
    }
}
```

#### Role Assignment Validation

```typescript
class RoleAssignmentService {
    async assignRoleToUser(
        userId: UUID, 
        roleId: UUID, 
        assignedBy: UUID
    ): Promise<UserRole> {
        const user = await this.getUser(userId);
        const role = await this.getRole(roleId);
        const assigner = await this.getUser(assignedBy);
        
        // 1. Validate organization isolation
        if (user.organizationId !== role.organizationId) {
            throw new ValidationError('User and role must belong to the same organization');
        }
        
        // 2. Validate assigner has permission to assign role
        const assignerPermissions = await this.getUserPermissions(assigner.id);
        if (!assignerPermissions.includes('assign_role_to_user')) {
            throw new AuthorizationError('User does not have permission to assign roles');
        }
        
        // 3. Validate assigner has the role being assigned (for non-admin roles)
        if (!this.hasRoleHierarchyPermission(assigner, role)) {
            throw new AuthorizationError('User does not have permission to assign this role');
        }
        
        // 4. Check for existing assignment
        const existingAssignment = await this.findUserRoleAssignment(userId, roleId);
        if (existingAssignment) {
            throw new ValidationError('User already has this role');
        }
        
        // 5. Create role assignment
        const userRole = new UserRole({
            userId,
            roleId,
            assignedBy,
            status: 'active'
        });
        
        return await this.userRoleRepository.save(userRole);
    }
}
```

#### Permission Evaluation

```typescript
class PermissionService {
    async getUserPermissions(userId: UUID): Promise<string[]> {
        const user = await this.getUser(userId);
        
        // 1. Get direct role assignments
        const directRoles = await this.getUserRoles(userId, 'active');
        
        // 2. Get group memberships
        const groupMemberships = await this.getUserGroupMemberships(userId, 'active');
        
        // 3. Get roles from groups
        const groupRoles = [];
        for (const membership of groupMemberships) {
            const roles = await this.getGroupRoles(membership.groupId, 'active');
            groupRoles.push(...roles);
        }
        
        // 4. Combine and deduplicate permissions
        const allRoles = [...directRoles, ...groupRoles];
        const permissionIds = new Set<string>();
        
        for (const role of allRoles) {
            const permissions = await this.getRolePermissions(role.id);
            permissions.forEach(p => permissionIds.add(p.id));
        }
        
        return Array.from(permissionIds);
    }
    
    async hasPermission(userId: UUID, permissionName: string): Promise<boolean> {
        const userPermissions = await this.getUserPermissions(userId);
        return userPermissions.includes(permissionName);
    }
}
```

#### Optimistic Locking Implementation

```typescript
class BaseEntityService {
    async updateEntity<T extends BaseEntity>(
        id: UUID, 
        updates: Partial<T>, 
        expectedVersion?: number
    ): Promise<T> {
        const entity = await this.repository.findById(id);
        
        if (!entity) {
            throw new NotFoundError('Entity not found');
        }
        
        // 1. Check optimistic lock version
        if (expectedVersion && entity.version !== expectedVersion) {
            throw new ConcurrencyError('Entity was modified by another process');
        }
        
        // 2. Apply updates
        Object.assign(entity, updates);
        entity.updatedAt = new Date();
        entity.version = (entity.version || 0) + 1;
        
        // 3. Save entity
        return await this.repository.save(entity);
    }
}
```

#### Audit Logging

```typescript
class AuditService {
    async logAction(
        userId: UUID,
        action: string,
        resourceType: string,
        resourceId: UUID,
        resourceName: string,
        oldValues?: any,
        newValues?: any,
        ipAddress?: string,
        userAgent?: string,
        requestId?: UUID
    ): Promise<void> {
        const auditLog = new AuditLog({
            userId,
            action,
            resourceType,
            resourceId,
            resourceName,
            oldValues,
            newValues,
            changes: this.calculateChanges(oldValues, newValues),
            ipAddress,
            userAgent,
            requestId,
            createdAt: new Date()
        });
        
        await this.auditLogRepository.save(auditLog);
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

This approach ensures that all business logic is centralized in the application layer while maintaining data integrity through database constraints, without relying on database triggers or functions.

## Partitioning Strategy

### Audit Log Partitioning

```sql
-- Create partitioned table
CREATE TABLE audit_logs (
    id UUID,
    user_id UUID,
    action VARCHAR(50),
    resource_type VARCHAR(50),
    resource_id UUID,
    resource_name VARCHAR(255),
    old_values JSONB,
    new_values JSONB,
    changes JSONB,
    ip_address INET,
    user_agent TEXT,
    request_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

-- Create monthly partitions for the next year
DO $$
DECLARE
    start_date DATE := '2026-01-01';
    end_date DATE := '2027-01-01';
    partition_date DATE;
BEGIN
    partition_date := start_date;
    WHILE partition_date < end_date LOOP
        EXECUTE format('
            CREATE TABLE audit_logs_%s PARTITION OF audit_logs
            FOR VALUES FROM (%L) TO (%L)',
            to_char(partition_date, 'YYYY_MM'),
            partition_date,
            partition_date + INTERVAL '1 month'
        );
        partition_date := partition_date + INTERVAL '1 month';
    END LOOP;
END $$;

-- Create index on each partition
CREATE INDEX audit_logs_2026_01_created_at_idx ON audit_logs_2026_01(created_at);
CREATE INDEX audit_logs_2026_02_created_at_idx ON audit_logs_2026_02(created_at);
-- ... continue for all partitions
```

### User Activity Partitioning

```sql
-- Partition user activity by organization for better performance
CREATE TABLE user_activity (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    activity_type VARCHAR(50) NOT NULL,
    activity_data JSONB,
    ip_address INET,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
) PARTITION BY HASH (user_id);

-- Create hash partitions
CREATE TABLE user_activity_p0 PARTITION OF user_activity
FOR VALUES WITH (modulus 8, remainder 0);

CREATE TABLE user_activity_p1 PARTITION OF user_activity
FOR VALUES WITH (modulus 8, remainder 1);

-- ... continue for all 8 partitions
```

## Performance Optimization

### Connection Pooling Configuration

```sql
-- pgBouncer configuration for connection pooling
-- /etc/pgbouncer/pgbouncer.ini

[databases]
direct_prod = host=localhost port=5432 dbname=direct_prod

[pgbouncer]
pool_mode = transaction
max_client_conn = 1000
default_pool_size = 20
min_pool_size = 5
reserve_pool_size = 5
server_reset_query = DISCARD ALL
```

### Query Optimization

```sql
-- Common Table Expression for hierarchy queries
WITH RECURSIVE org_hierarchy AS (
    SELECT id, name, parent_id, 0 as level
    FROM organization_units 
    WHERE parent_id IS NULL AND organization_id = $1
    
    UNION ALL
    
    SELECT ou.id, ou.name, ou.parent_id, oh.level + 1
    FROM organization_units ou
    INNER JOIN org_hierarchy oh ON ou.parent_id = oh.id
    WHERE ou.organization_id = $1
)
SELECT * FROM org_hierarchy ORDER BY level, name;

-- Application-level caching for permission evaluation
-- Instead of materialized views, use application caching with Redis
-- Cache key: user:{user_id}:permissions
-- Cache TTL: 5 minutes with invalidation on role/group changes
```

### Caching Strategy

```typescript
// Application-level caching strategy using Redis
class CacheService {
    private redis: Redis;
    
    // Cache key patterns
    private readonly USER_PERMISSIONS_KEY = 'user:{userId}:permissions';
    private readonly ORG_USERS_KEY = 'org:{orgId}:users';
    private readonly ROLE_PERMISSIONS_KEY = 'role:{roleId}:permissions';
    private readonly GROUP_MEMBERS_KEY = 'group:{groupId}:members';
    private readonly ORG_UNIT_HIERARCHY_KEY = 'org_unit:{unitId}:sub_units';
    
    async getUserPermissions(userId: UUID): Promise<string[]> {
        const cacheKey = this.USER_PERMISSIONS_KEY.replace('{userId}', userId);
        
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
        const cacheKey = this.USER_PERMISSIONS_KEY.replace('{userId}', userId);
        await this.redis.del(cacheKey);
    }
    
    async invalidateRolePermissions(roleId: UUID): Promise<void> {
        const cacheKey = this.ROLE_PERMISSIONS_KEY.replace('{roleId}', roleId);
        await this.redis.del(cacheKey);
        
        // Invalidate all user permissions that might be affected
        const usersWithRole = await this.userRoleRepository.findUsersWithRole(roleId);
        for (const user of usersWithRole) {
            await this.invalidateUserPermissions(user.id);
        }
    }
    
    async invalidateGroupMembers(groupId: UUID): Promise<void> {
        const cacheKey = this.GROUP_MEMBERS_KEY.replace('{groupId}', groupId);
        await this.redis.del(cacheKey);
        
        // Invalidate permissions for all group members
        const members = await this.groupMemberRepository.findGroupMembers(groupId);
        for (const member of members) {
            await this.invalidateUserPermissions(member.userId);
        }
    }
}
```

### Cache Invalidation Service

```typescript
class CacheInvalidationService {
    private cacheService: CacheService;
    
    async invalidateOnUserRoleChange(userRoleId: UUID): Promise<void> {
        const userRole = await this.userRoleRepository.findById(userRoleId);
        
        // Invalidate user permissions
        await this.cacheService.invalidateUserPermissions(userRole.userId);
        
        // Invalidate role permissions if role was modified
        await this.cacheService.invalidateRolePermissions(userRole.roleId);
    }
    
    async invalidateOnGroupRoleChange(groupRoleId: UUID): Promise<void> {
        const groupRole = await this.groupRoleRepository.findById(groupRoleId);
        
        // Invalidate group members
        await this.cacheService.invalidateGroupMembers(groupRole.groupId);
        
        // Invalidate role permissions
        await this.cacheService.invalidateRolePermissions(groupRole.roleId);
    }
    
    async invalidateOnGroupMembershipChange(groupMemberId: UUID): Promise<void> {
        const groupMember = await this.groupMemberRepository.findById(groupMemberId);
        
        // Invalidate user permissions
        await this.cacheService.invalidateUserPermissions(groupMember.userId);
        
        // Invalidate group members
        await this.cacheService.invalidateGroupMembers(groupMember.groupId);
    }
}
```

This comprehensive database schema provides the foundation for implementing the Direct Organization Management System with proper support for scoped roles, addressing the critical issue you identified with role naming constraints.