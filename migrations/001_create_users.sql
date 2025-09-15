-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    access_key VARCHAR(255) UNIQUE NOT NULL,
    secret_key VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    active BOOLEAN DEFAULT true
);

-- Create index on access_key for fast lookups
CREATE INDEX IF NOT EXISTS idx_users_access_key ON users(access_key);

-- Create index on email for user management
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Create user_permissions table
CREATE TABLE IF NOT EXISTS user_permissions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bucket_pattern VARCHAR(255) NOT NULL,
    permissions VARCHAR(50) NOT NULL, -- comma-separated: read,write,delete
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, bucket_pattern)
);

-- Create index on user_id for permission lookups
CREATE INDEX IF NOT EXISTS idx_user_permissions_user_id ON user_permissions(user_id);