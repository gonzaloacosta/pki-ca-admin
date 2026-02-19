-- Database initialization script for PKI-CA-ADMIN
-- This script runs when the PostgreSQL container starts

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create indexes for better performance
-- Additional indexes will be created by SQLAlchemy models

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE pki_ca_admin TO pki_admin;

-- Create default organization for development
-- This will be replaced by proper org creation in production
-- INSERT INTO organizations (id, name, domain, plan_type, max_cas, max_certificates)
-- VALUES (
--     gen_random_uuid(),
--     'Development Organization',
--     'dev.local',
--     'enterprise',
--     50,
--     10000
-- ) ON CONFLICT DO NOTHING;

-- Create development admin user
-- Password: 'admin123' (change in production)
-- INSERT INTO users (id, email, organization_id, hashed_password, full_name, enabled)
-- VALUES (
--     gen_random_uuid(),
--     'admin@dev.local',
--     (SELECT id FROM organizations WHERE domain = 'dev.local' LIMIT 1),
--     '$2b$12$LHvqW8H9Xt.W3YU0F9H1l.BvZjKoKEoXvZbI7QXXF9oJK9sFZpGWu', -- admin123
--     'Development Admin',
--     true
-- ) ON CONFLICT DO NOTHING;