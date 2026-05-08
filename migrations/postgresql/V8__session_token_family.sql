-- V8__session_token_family.sql
-- Add token family tracking for refresh token rotation and theft detection.

-- Add token family columns to sessions
ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS token_family_id UUID,
    ADD COLUMN IF NOT EXISTS previous_session_id UUID,
    ADD COLUMN IF NOT EXISTS rotated_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS reused_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS family_revoked BOOLEAN NOT NULL DEFAULT FALSE;

-- Index for token family lookups
CREATE INDEX IF NOT EXISTS idx_sessions_token_family ON sessions(token_family_id);
CREATE INDEX IF NOT EXISTS idx_sessions_previous ON sessions(previous_session_id);
