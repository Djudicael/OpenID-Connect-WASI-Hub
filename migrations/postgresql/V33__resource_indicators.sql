-- RFC 8707 Resource Indicators
ALTER TABLE authorization_codes ADD COLUMN resource JSONB NOT NULL DEFAULT '[]';
ALTER TABLE sessions ADD COLUMN resource JSONB NOT NULL DEFAULT '[]';
