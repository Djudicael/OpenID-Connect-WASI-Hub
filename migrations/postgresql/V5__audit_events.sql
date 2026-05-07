-- V5__audit_events.sql
-- Comprehensive audit trail for compliance and security.

CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID REFERENCES realms(id),
    event_type TEXT NOT NULL,
    actor_id UUID REFERENCES users(id),
    actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'api_key', 'system')),
    target_type TEXT,
    target_id UUID,
    details JSONB NOT NULL DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
