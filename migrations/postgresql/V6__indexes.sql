-- V6__indexes.sql
-- Performance indexes for production workloads.

-- Users
CREATE INDEX IF NOT EXISTS idx_users_realm_email ON users(realm_id, email) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);

-- Sessions
CREATE INDEX IF NOT EXISTS idx_sessions_access_hash ON sessions(access_token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_hash ON sessions(refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at) WHERE NOT revoked;

-- API Keys
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_realm ON api_keys(realm_id) WHERE NOT revoked;

-- Audit Events
CREATE INDEX IF NOT EXISTS idx_audit_realm_time ON audit_events(realm_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events(actor_id, created_at);

-- MLS
CREATE INDEX IF NOT EXISTS idx_mls_groups_realm ON mls_groups(realm_id);
CREATE INDEX IF NOT EXISTS idx_kp_user ON mls_key_packages(user_id) WHERE NOT used;
