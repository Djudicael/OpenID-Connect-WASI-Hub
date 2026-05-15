-- V39: Add request object encryption fields and client_secret_jwt support

-- Request object encryption fields
ALTER TABLE clients ADD COLUMN IF NOT EXISTS request_object_encryption_alg TEXT;
ALTER TABLE clients ADD COLUMN IF NOT EXISTS request_object_encryption_enc TEXT DEFAULT 'A256GCM';
ALTER TABLE clients ADD COLUMN IF NOT EXISTS request_object_encryption_key_encrypted TEXT;
ALTER TABLE clients ADD COLUMN IF NOT EXISTS request_object_encryption_key_pem TEXT;

-- Ensure client_secret_encrypted column exists (placeholder from earlier, may not have been added)
ALTER TABLE clients ADD COLUMN IF NOT EXISTS client_secret_encrypted TEXT;

-- Add comment
COMMENT ON COLUMN clients.request_object_encryption_alg IS 'JWE key encryption algorithm for request objects: dir or RSA-OAEP-256';
COMMENT ON COLUMN clients.request_object_encryption_enc IS 'JWE content encryption algorithm for request objects: A256GCM';
COMMENT ON COLUMN clients.request_object_encryption_key_encrypted IS 'Symmetric key for JWE dir encryption of request objects, encrypted at rest with server key';
COMMENT ON COLUMN clients.request_object_encryption_key_pem IS 'Client RSA public key PEM for JWE RSA-OAEP-256 encryption of request objects';
COMMENT ON COLUMN clients.client_secret_encrypted IS 'AES-256-GCM encrypted client secret for client_secret_jwt authentication';
