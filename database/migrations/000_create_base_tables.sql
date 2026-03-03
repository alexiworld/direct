-- Migration: Create Base Tables for Organization Management System
-- This migration creates all the necessary tables for the scoped roles implementation

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create organizations table
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create organization_units table
CREATE TABLE IF NOT EXISTS organization_units (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    parent_id UUID REFERENCES organization_units(id),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    address JSONB,
    owner_id UUID,
    hierarchy_level INTEGER DEFAULT 0,
    path VARCHAR(1000),
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    organization_unit_id UUID REFERENCES organization_units(id),
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(50),
    status VARCHAR(50) DEFAULT 'pending',
    last_login_at TIMESTAMP WITH TIME ZONE,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Create groups table
CREATE TABLE IF NOT EXISTS groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    parent_id UUID REFERENCES groups(id),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(50) DEFAULT 'custom',
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Create group_members table
CREATE TABLE IF NOT EXISTS group_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    role_in_group VARCHAR(50) DEFAULT 'member',
    status VARCHAR(50) DEFAULT 'active',
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create roles table
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(50) DEFAULT 'custom',
    is_system_role BOOLEAN DEFAULT FALSE,
    status VARCHAR(50) DEFAULT 'active',
    scope_type VARCHAR(50) DEFAULT 'organization',
    scope_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Create permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    category VARCHAR(100),
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create role_permissions table
CREATE TABLE IF NOT EXISTS role_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create user_roles table
CREATE TABLE IF NOT EXISTS user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_by UUID NOT NULL REFERENCES users(id),
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'active',
    expires_at TIMESTAMP WITH TIME ZONE,
    reason TEXT,
    scope_context JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create audit_logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(500),
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    request_id VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_organizations_name ON organizations(name);
CREATE INDEX IF NOT EXISTS idx_organization_units_org ON organization_units(organization_id);
CREATE INDEX IF NOT EXISTS idx_organization_units_parent ON organization_units(parent_id);
CREATE INDEX IF NOT EXISTS idx_organization_units_path ON organization_units(path);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_org ON users(organization_id);
CREATE INDEX IF NOT EXISTS idx_users_ou ON users(organization_unit_id);
CREATE INDEX IF NOT EXISTS idx_groups_org ON groups(organization_id);
CREATE INDEX IF NOT EXISTS idx_groups_parent ON groups(parent_id);
CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id);
CREATE INDEX IF NOT EXISTS idx_group_members_group ON group_members(group_id);
CREATE INDEX IF NOT EXISTS idx_roles_org ON roles(organization_id);
CREATE INDEX IF NOT EXISTS idx_roles_scope ON roles(scope_type, scope_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_scope ON user_roles((scope_context->>'scopeType'), (scope_context->>'scopeId'));
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create triggers for updated_at (use CREATE OR REPLACE for idempotent migrations)
DROP TRIGGER IF EXISTS update_organizations_updated_at ON organizations;
CREATE TRIGGER update_organizations_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_organization_units_updated_at ON organization_units;
CREATE TRIGGER update_organization_units_updated_at
    BEFORE UPDATE ON organization_units
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_groups_updated_at ON groups;
CREATE TRIGGER update_groups_updated_at
    BEFORE UPDATE ON groups
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_group_members_updated_at ON group_members;
CREATE TRIGGER update_group_members_updated_at
    BEFORE UPDATE ON group_members
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_roles_updated_at ON roles;
CREATE TRIGGER update_roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_role_permissions_updated_at ON role_permissions;
CREATE TRIGGER update_role_permissions_updated_at
    BEFORE UPDATE ON role_permissions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_user_roles_updated_at ON user_roles;
CREATE TRIGGER update_user_roles_updated_at
    BEFORE UPDATE ON user_roles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Add comments for documentation
COMMENT ON TABLE organizations IS 'Organizations in the system';
COMMENT ON TABLE organization_units IS 'Organization units (departments, teams, etc.)';
COMMENT ON TABLE users IS 'Users in the system';
COMMENT ON TABLE groups IS 'Groups for organizing users';
COMMENT ON TABLE group_members IS 'Membership of users in groups';
COMMENT ON TABLE roles IS 'Roles that can be assigned to users';
COMMENT ON TABLE permissions IS 'Permissions that roles can have';
COMMENT ON TABLE role_permissions IS 'Permissions assigned to roles';
COMMENT ON TABLE user_roles IS 'Roles assigned to users';
COMMENT ON TABLE audit_logs IS 'Audit log for tracking changes';

-- Insert sample data
INSERT INTO organizations (id, name, description, status) VALUES
    ('00000000-0000-0000-0000-000000000001', 'Direct Organization', 'Main organization for testing', 'active')
ON CONFLICT (id) DO NOTHING;

INSERT INTO permissions (id, name, description, category, status) VALUES
    ('00000000-0000-0000-0000-000000000010', 'assign_roles', 'Assign roles to users', 'role_management', 'active'),
    ('00000000-0000-0000-0000-000000000011', 'revoke_roles', 'Revoke roles from users', 'role_management', 'active'),
    ('00000000-0000-0000-0000-000000000012', 'view_users', 'View user information', 'user_management', 'active'),
    ('00000000-0000-0000-0000-000000000013', 'edit_users', 'Edit user information', 'user_management', 'active'),
    ('00000000-0000-0000-0000-000000000014', 'invite_users', 'Invite new users', 'user_management', 'active'),
    ('00000000-0000-0000-0000-000000000015', 'remove_users', 'Remove users', 'user_management', 'active'),
    ('00000000-0000-0000-0000-000000000016', 'move_users', 'Move users between organization units', 'user_management', 'active'),
    ('00000000-0000-0000-0000-000000000017', 'manage_organization_units', 'Manage organization units', 'organization_management', 'active'),
    ('00000000-0000-0000-0000-000000000018', 'view_organization_units', 'View organization units', 'organization_management', 'active')
ON CONFLICT (id) DO NOTHING;

-- Insert sample organization units
INSERT INTO organization_units (id, organization_id, name, description, owner_id, hierarchy_level, path, status) VALUES
    ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001', 'Engineering', 'Engineering department', '00000000-0000-0000-0000-000000000004', 1, '00000000-0000-0000-0000-000000000002', 'active'),
    ('00000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000001', 'Marketing', 'Marketing department', '00000000-0000-0000-0000-000000000004', 1, '00000000-0000-0000-0000-000000000003', 'active')
ON CONFLICT (id) DO NOTHING;

-- Insert sample users
INSERT INTO users (id, organization_id, organization_unit_id, first_name, last_name, email, phone, status) VALUES
    ('00000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002', 'Admin', 'User', 'admin@example.com', '123-456-7890', 'active'),
    ('00000000-0000-0000-0000-000000000005', '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002', 'Test', 'User', 'user@example.com', '098-765-4321', 'active')
ON CONFLICT (id) DO NOTHING;

-- Insert sample groups
INSERT INTO groups (id, organization_id, name, description, type, status) VALUES
    ('00000000-0000-0000-0000-000000000006', '00000000-0000-0000-0000-000000000001', 'Parent Group', 'Parent group for testing', 'custom', 'active'),
    ('00000000-0000-0000-0000-000000000007', '00000000-0000-0000-0000-000000000001', 'Project Alpha', 'Alpha project team', 'custom', 'active')
ON CONFLICT (id) DO NOTHING;

-- Insert sample roles
INSERT INTO roles (id, organization_id, name, description, type, scope_type, scope_id, status) VALUES
    ('00000000-0000-0000-0000-000000000008', '00000000-0000-0000-0000-000000000001', 'Group Manager', 'Manager of a group', 'custom', 'group', '00000000-0000-0000-0000-000000000006', 'active'),
    ('00000000-0000-0000-0000-000000000009', '00000000-0000-0000-0000-000000000001', 'OU Manager', 'Manager of an organization unit', 'custom', 'organization_unit', '00000000-0000-0000-0000-000000000002', 'active')
ON CONFLICT (id) DO NOTHING;

-- Insert sample role permissions
INSERT INTO role_permissions (id, role_id, permission_id, status) VALUES
    ('00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-000000000008', '00000000-0000-0000-0000-000000000010', 'active'),
    ('00000000-0000-0000-0000-00000000000b', '00000000-0000-0000-0000-000000000008', '00000000-0000-0000-0000-000000000012', 'active'),
    ('00000000-0000-0000-0000-00000000000c', '00000000-0000-0000-0000-000000000009', '00000000-0000-0000-0000-000000000010', 'active'),
    ('00000000-0000-0000-0000-00000000000d', '00000000-0000-0000-0000-000000000009', '00000000-0000-0000-0000-000000000011', 'active')
ON CONFLICT (id) DO NOTHING;

-- Insert sample user roles
INSERT INTO user_roles (id, user_id, role_id, assigned_by, status) VALUES
    ('00000000-0000-0000-0000-00000000000e', '00000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-000000000009', '00000000-0000-0000-0000-000000000004', 'active')
ON CONFLICT (id) DO NOTHING;

-- Insert sample group memberships
INSERT INTO group_members (id, user_id, group_id, role_in_group, status) VALUES
    ('00000000-0000-0000-0000-00000000000f', '00000000-0000-0000-0000-000000000005', '00000000-0000-0000-0000-000000000007', 'member', 'active')
ON CONFLICT (id) DO NOTHING;

-- Grant permissions (adjust as needed for your security model)
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO your_app_user;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO your_app_user;