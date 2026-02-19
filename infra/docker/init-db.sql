-- Database initialization for PKI CA Admin
-- This will be run when the PostgreSQL container starts

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create a read-only user for monitoring/backup
CREATE USER pki_readonly WITH PASSWORD 'readonly_pass';
GRANT CONNECT ON DATABASE pki_ca_admin TO pki_readonly;
GRANT USAGE ON SCHEMA public TO pki_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO pki_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO pki_readonly;