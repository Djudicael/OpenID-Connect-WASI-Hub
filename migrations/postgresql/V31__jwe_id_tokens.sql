-- JWE Encrypted ID Tokens
-- Add fields for JWE encryption configuration on clients.
-- - id_token_encrypted_response_alg: JWE key encryption algorithm (dir, RSA-OAEP-256)
-- - id_token_encrypted_response_enc: JWE content encryption algorithm (A256GCM)
-- - id_token_encryption_key_encrypted: Symmetric key for "dir" algorithm, encrypted at rest
-- - id_token_encryption_key_pem: RSA public key for "RSA-OAEP-256" algorithm (PEM format)

ALTER TABLE clients ADD COLUMN IF NOT EXISTS id_token_encrypted_response_alg VARCHAR(20);
ALTER TABLE clients ADD COLUMN IF NOT EXISTS id_token_encrypted_response_enc VARCHAR(10);
ALTER TABLE clients ADD COLUMN IF NOT EXISTS id_token_encryption_key_encrypted TEXT;
ALTER TABLE clients ADD COLUMN IF NOT EXISTS id_token_encryption_key_pem TEXT;
