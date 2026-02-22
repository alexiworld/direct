-- Migration: Add Organization Unit Scoped Roles Support
-- This migration adds support for organization unit scoped roles and enhanced audit logging

-- Add scope validation fields to organization_units table
ALTER TABLE organization_units 
ADD COLUMN IF NOT EXISTS scope_validation_enabled BOOLEAN DEFAULT true;

ALTER TABLE organization_units 
ADD COLUMN IF NOT EXISTS last_scope_validation TIMESTAMP;

-- Add scope tracking to user_roles table
ALTER TABLE user_roles 
ADD COLUMN IF NOT EXISTS scope_validation_required BOOLEAN DEFAULT false;

ALTER TABLE user_roles 
ADD COLUMN IF NOT EXISTS scope_validation_timestamp TIMESTAMP;

-- Create table for OU-scoped operations audit logging
CREATE TABLE IF NOT EXISTS ou_scoped_operations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_unit_id UUID NOT NULL REFERENCES organization_units(id) ON DELETE CASCADE,
    operation_type VARCHAR(50) NOT NULL,
    target_resource_id UUID,
    target_user_id UUID REFERENCES users(id),
    scope_validation_passed BOOLEAN NOT NULL,
    scope_violation_details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Indexes for performance
    INDEX idx_ou_scoped_ops_user (user_id),
    INDEX idx_ou_scoped_ops_ou (organization_unit_id),
    INDEX idx_ou_scoped_ops_operation (operation_type),
    INDEX idx_ou_scoped_ops_created_at (created_at)
);

-- Create table for role scope validation history
CREATE TABLE IF NOT EXISTS role_scope_validations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_unit_id UUID REFERENCES organization_units(id),
    group_id UUID REFERENCES groups(id),
    validation_type VARCHAR(50) NOT NULL, -- 'assignment', 'access', 'operation'
    validation_result BOOLEAN NOT NULL,
    validation_details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Indexes for performance
    INDEX idx_role_scope_validations_role (role_id),
    INDEX idx_role_scope_validations_user (user_id),
    INDEX idx_role_scope_validations_ou (organization_unit_id),
    INDEX idx_role_scope_validations_group (group_id),
    INDEX idx_role_scope_validations_type (validation_type),
    INDEX idx_role_scope_validations_created_at (created_at)
);

-- Create function to validate OU scope for role assignments
CREATE OR REPLACE FUNCTION validate_ou_role_scope(
    p_user_id UUID,
    p_role_id UUID,
    p_organization_unit_id UUID
) RETURNS BOOLEAN AS $$
DECLARE
    v_role_scope_type VARCHAR(50);
    v_role_scope_id UUID;
    v_user_ou_id UUID;
    v_ou_owner_id UUID;
    v_is_manager BOOLEAN := FALSE;
    v_result BOOLEAN := FALSE;
BEGIN
    -- Get role scope information
    SELECT scope_type, scope_id INTO v_role_scope_type, v_role_scope_id
    FROM roles 
    WHERE id = p_role_id;
    
    -- If role is not OU-scoped, validation passes
    IF v_role_scope_type IS NULL OR v_role_scope_type != 'organization_unit' THEN
        RETURN TRUE;
    END IF;
    
    -- Check if role scope matches the target OU
    IF v_role_scope_id != p_organization_unit_id THEN
        RETURN FALSE;
    END IF;
    
    -- Get user's current OU
    SELECT organization_unit_id INTO v_user_ou_id
    FROM users 
    WHERE id = p_user_id;
    
    -- User must belong to the OU for OU-scoped roles
    IF v_user_ou_id != p_organization_unit_id THEN
        RETURN FALSE;
    END IF;
    
    -- For assignment validation, check if assigner has appropriate permissions
    -- This would typically be called from a role assignment context
    -- For now, we'll assume the caller handles assigner validation
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- Create function to validate user access to organization unit
CREATE OR REPLACE FUNCTION validate_user_ou_access(
    p_user_id UUID,
    p_organization_unit_id UUID,
    p_required_access_type VARCHAR(20) DEFAULT 'any'
) RETURNS JSONB AS $$
DECLARE
    v_ou_owner_id UUID;
    v_user_ou_id UUID;
    v_access_result JSONB;
BEGIN
    -- Get OU owner
    SELECT owner_id INTO v_ou_owner_id
    FROM organization_units 
    WHERE id = p_organization_unit_id;
    
    -- Get user's OU
    SELECT organization_unit_id INTO v_user_ou_id
    FROM users 
    WHERE id = p_user_id;
    
    -- Initialize result
    v_access_result := jsonb_build_object(
        'has_access', FALSE,
        'access_type', 'none',
        'user_id', p_user_id,
        'organization_unit_id', p_organization_unit_id
    );
    
    -- Check if user is owner
    IF v_ou_owner_id = p_user_id THEN
        v_access_result := v_access_result || jsonb_build_object(
            'has_access', TRUE,
            'access_type', 'owner'
        );
        RETURN v_access_result;
    END IF;
    
    -- Check if user is manager (has OU_MANAGER role for this OU)
    IF EXISTS (
        SELECT 1 FROM user_roles ur
        JOIN roles r ON ur.role_id = r.id
        WHERE ur.user_id = p_user_id 
        AND r.name = 'OU_MANAGER'
        AND r.scope_type = 'organization_unit'
        AND r.scope_id = p_organization_unit_id
        AND ur.status = 'active'
    ) THEN
        v_access_result := v_access_result || jsonb_build_object(
            'has_access', TRUE,
            'access_type', 'manager'
        );
        RETURN v_access_result;
    END IF;
    
    -- Check if user belongs to the OU (member access)
    IF v_user_ou_id = p_organization_unit_id THEN
        v_access_result := v_access_result || jsonb_build_object(
            'has_access', TRUE,
            'access_type', 'member'
        );
        RETURN v_access_result;
    END IF;
    
    -- No access found
    RETURN v_access_result;
END;
$$ LANGUAGE plpgsql;

-- Create trigger function to audit OU-scoped operations
CREATE OR REPLACE FUNCTION audit_ou_scoped_operation()
RETURNS TRIGGER AS $$
DECLARE
    v_operation_type VARCHAR(50);
    v_scope_validation_passed BOOLEAN := TRUE;
    v_scope_violation_details JSONB;
BEGIN
    -- Determine operation type
    IF TG_OP = 'INSERT' THEN
        v_operation_type := 'user_added_to_ou';
    ELSIF TG_OP = 'UPDATE' THEN
        v_operation_type := 'user_moved_in_ou';
    ELSIF TG_OP = 'DELETE' THEN
        v_operation_type := 'user_removed_from_ou';
    END IF;
    
    -- For now, we'll assume the operation passed scope validation
    -- In a real implementation, this would be determined by the calling application
    
    -- Insert audit record
    INSERT INTO ou_scoped_operations (
        user_id,
        organization_unit_id,
        operation_type,
        target_resource_id,
        target_user_id,
        scope_validation_passed,
        scope_violation_details,
        created_at
    ) VALUES (
        COALESCE(NEW.updated_by, OLD.updated_by, NEW.created_by, OLD.created_by),
        COALESCE(NEW.organization_unit_id, OLD.organization_unit_id),
        v_operation_type,
        COALESCE(NEW.id, OLD.id),
        COALESCE(NEW.user_id, OLD.user_id),
        v_scope_validation_passed,
        v_scope_violation_details,
        NOW()
    );
    
    -- Return appropriate row based on operation
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for user_organization_unit changes
-- Note: This assumes there's a table tracking user-OU relationships
-- If users have organization_unit_id directly in the users table,
-- you would create a trigger on the users table instead

-- Example trigger (commented out as table structure may vary):
/*
CREATE TRIGGER trigger_audit_user_ou_changes
    AFTER INSERT OR UPDATE OR DELETE ON user_organization_units
    FOR EACH ROW
    EXECUTE FUNCTION audit_ou_scoped_operation();
*/

-- Create indexes for better query performance on scoped operations
CREATE INDEX IF NOT EXISTS idx_ou_scoped_ops_user_created_at 
ON ou_scoped_operations(user_id, created_at);

CREATE INDEX IF NOT EXISTS idx_ou_scoped_ops_ou_created_at 
ON ou_scoped_operations(organization_unit_id, created_at);

CREATE INDEX IF NOT EXISTS idx_role_scope_validations_user_created_at 
ON role_scope_validations(user_id, created_at);

CREATE INDEX IF NOT EXISTS idx_role_scope_validations_role_created_at 
ON role_scope_validations(role_id, created_at);

-- Insert sample data for testing (optional)
-- Uncomment the following lines to add sample scoped roles

/*
-- Add sample OU-scoped roles
INSERT INTO roles (id, organization_id, name, description, type, is_system_role, scope_type, scope_id, status)
VALUES 
    (gen_random_uuid(), 'org-1', 'Department Manager', 'Manager role for specific department', 'custom', false, 'organization_unit', 'ou-dept-1', 'active'),
    (gen_random_uuid(), 'org-1', 'Team Lead', 'Team lead role for specific team', 'custom', false, 'organization_unit', 'ou-team-1', 'active');

-- Add sample role permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name IN ('Department Manager', 'Team Lead')
AND p.name IN ('view_users', 'edit_users', 'invite_users', 'move_users');
*/

-- Add comments for documentation
COMMENT ON TABLE ou_scoped_operations IS 'Audit log for organization unit scoped operations';
COMMENT ON TABLE role_scope_validations IS 'History of role scope validation checks';
COMMENT ON FUNCTION validate_ou_role_scope IS 'Validates if a user can be assigned a role based on OU scope';
COMMENT ON FUNCTION validate_user_ou_access IS 'Validates user access level to an organization unit';

-- Grant necessary permissions (adjust as needed for your security model)
-- GRANT SELECT, INSERT, UPDATE ON ou_scoped_operations TO your_app_user;
-- GRANT SELECT, INSERT, UPDATE ON role_scope_validations TO your_app_user;
-- GRANT EXECUTE ON FUNCTION validate_ou_role_scope TO your_app_user;
-- GRANT EXECUTE ON FUNCTION validate_user_ou_access TO your_app_user;