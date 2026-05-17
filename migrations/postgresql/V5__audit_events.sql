-- V5__audit_events.sql
-- Finalized audit trail schema.

CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID REFERENCES realms(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    actor_id UUID,
    actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'api_key', 'system')),
    target_type TEXT,
    target_id UUID,
    details JSONB NOT NULL DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_realm_time ON audit_events(realm_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events(actor_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at);
