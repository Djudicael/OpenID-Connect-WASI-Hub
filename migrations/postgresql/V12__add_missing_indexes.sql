-- Add missing indexes for common query patterns

CREATE INDEX IF NOT EXISTS idx_sessions_realm_id ON sessions(realm_id);
CREATE INDEX IF NOT EXISTS idx_signing_keys_realm_id ON signing_keys(realm_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_created_by ON api_keys(created_by);
CREATE INDEX IF NOT EXISTS idx_audit_events_realm_id ON audit_events(realm_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(created_at);
