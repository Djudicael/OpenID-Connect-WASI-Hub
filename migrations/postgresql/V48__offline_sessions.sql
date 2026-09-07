ALTER TABLE sessions
    ADD COLUMN offline_session BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN offline_max_expires_at TIMESTAMPTZ;

ALTER TABLE sessions
    ADD CONSTRAINT sessions_offline_max_expiry
    CHECK (NOT offline_session OR offline_max_expires_at IS NOT NULL);

CREATE INDEX idx_sessions_active_offline_user
    ON sessions(user_id, offline_max_expires_at)
    WHERE offline_session AND NOT revoked AND rotated_at IS NULL;
