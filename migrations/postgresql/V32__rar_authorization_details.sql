-- RFC 9396 Rich Authorization Requests
ALTER TABLE authorization_codes ADD COLUMN authorization_details JSONB;
ALTER TABLE sessions ADD COLUMN authorization_details JSONB;
