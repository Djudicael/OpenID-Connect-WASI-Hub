-- RFC 9101 JARM (JWT-Secured Authorization Response Mode)
ALTER TABLE authorization_codes ADD COLUMN response_mode VARCHAR(20);
ALTER TABLE clients ADD COLUMN response_modes JSONB NOT NULL DEFAULT '["query", "fragment"]';
