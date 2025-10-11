-- Group to Role Mapping Tables
-- For production-ready group/role management

-- Azure AD Groups Registry
CREATE TABLE IF NOT EXISTS ad_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id VARCHAR(255) UNIQUE NOT NULL, -- Azure AD group ID
    group_name VARCHAR(255) NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Application Roles
CREATE TABLE IF NOT EXISTS app_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    is_system BOOLEAN DEFAULT false, -- System roles can't be deleted
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- S3 Permissions
CREATE TABLE IF NOT EXISTS s3_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    permission_name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    resource_pattern VARCHAR(255), -- e.g., "bucket/*" or "bucket/prefix/*"
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Group to Role Mappings
CREATE TABLE IF NOT EXISTS group_role_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL REFERENCES ad_groups(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES app_roles(id) ON DELETE CASCADE,
    created_by VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(group_id, role_id)
);

-- Role to Permission Mappings
CREATE TABLE IF NOT EXISTS role_permission_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES app_roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES s3_permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(role_id, permission_id)
);

-- Bucket Access Policies
CREATE TABLE IF NOT EXISTS bucket_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES app_roles(id) ON DELETE CASCADE,
    bucket_pattern VARCHAR(255) NOT NULL, -- e.g., "dev-*", "prod-data-lake"
    access_level VARCHAR(50) NOT NULL, -- 'read', 'write', 'admin'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Audit Log for Changes
CREATE TABLE IF NOT EXISTS group_role_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action VARCHAR(50) NOT NULL, -- 'create', 'update', 'delete'
    entity_type VARCHAR(50) NOT NULL, -- 'group', 'role', 'mapping'
    entity_id UUID NOT NULL,
    old_values JSONB,
    new_values JSONB,
    changed_by VARCHAR(255) NOT NULL,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default system roles
INSERT INTO app_roles (role_name, description, is_system) VALUES
    ('admin', 'Full system administrator with all permissions', true),
    ('storage-admin', 'Storage service administrator', true),
    ('bucket-admin', 'Can create and manage buckets', true),
    ('developer', 'Read/write access to development resources', true),
    ('reader', 'Read-only access to resources', true)
ON CONFLICT (role_name) DO NOTHING;

-- Insert default S3 permissions
INSERT INTO s3_permissions (permission_name, description) VALUES
    ('s3:*', 'All S3 operations'),
    ('s3:ListAllMyBuckets', 'List all buckets'),
    ('s3:CreateBucket', 'Create new buckets'),
    ('s3:DeleteBucket', 'Delete buckets'),
    ('s3:GetObject', 'Read objects'),
    ('s3:PutObject', 'Write objects'),
    ('s3:DeleteObject', 'Delete objects'),
    ('s3:ListBucket', 'List bucket contents'),
    ('s3:GetBucketPolicy', 'Read bucket policies'),
    ('s3:PutBucketPolicy', 'Write bucket policies')
ON CONFLICT (permission_name) DO NOTHING;

-- Create indexes for performance
CREATE INDEX idx_group_mappings_group ON group_role_mappings(group_id);
CREATE INDEX idx_role_permissions_role ON role_permission_mappings(role_id);
CREATE INDEX idx_bucket_policies_role ON bucket_policies(role_id);
CREATE INDEX idx_audit_entity ON group_role_audit(entity_type, entity_id);
CREATE INDEX idx_audit_changed_by ON group_role_audit(changed_by, changed_at);

-- Create views for easy querying
CREATE OR REPLACE VIEW v_group_roles AS
SELECT 
    g.group_id AS azure_group_id,
    g.group_name,
    g.description AS group_description,
    array_agg(DISTINCT r.role_name) AS roles
FROM ad_groups g
LEFT JOIN group_role_mappings grm ON g.id = grm.group_id
LEFT JOIN app_roles r ON grm.role_id = r.id
WHERE g.is_active = true
GROUP BY g.id, g.group_id, g.group_name, g.description;

CREATE OR REPLACE VIEW v_role_permissions AS
SELECT 
    r.role_name,
    r.description AS role_description,
    array_agg(DISTINCT p.permission_name) AS permissions
FROM app_roles r
LEFT JOIN role_permission_mappings rpm ON r.id = rpm.role_id
LEFT JOIN s3_permissions p ON rpm.permission_id = p.id
GROUP BY r.id, r.role_name, r.description;