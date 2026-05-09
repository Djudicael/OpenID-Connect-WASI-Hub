-- Add ON DELETE CASCADE for foreign keys that should cascade

-- Sessions should be deleted when their user, client, or realm is deleted
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_user_id_fkey;
ALTER TABLE sessions ADD CONSTRAINT sessions_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_client_id_fkey;
ALTER TABLE sessions ADD CONSTRAINT sessions_client_id_fkey
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE;

ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_realm_id_fkey;
ALTER TABLE sessions ADD CONSTRAINT sessions_realm_id_fkey
    FOREIGN KEY (realm_id) REFERENCES realms(id) ON DELETE CASCADE;

-- Authorization codes should cascade on delete
ALTER TABLE authorization_codes DROP CONSTRAINT IF EXISTS authorization_codes_user_id_fkey;
ALTER TABLE authorization_codes ADD CONSTRAINT authorization_codes_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE authorization_codes DROP CONSTRAINT IF EXISTS authorization_codes_client_id_fkey;
ALTER TABLE authorization_codes ADD CONSTRAINT authorization_codes_client_id_fkey
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE;

ALTER TABLE authorization_codes DROP CONSTRAINT IF EXISTS authorization_codes_realm_id_fkey;
ALTER TABLE authorization_codes ADD CONSTRAINT authorization_codes_realm_id_fkey
    FOREIGN KEY (realm_id) REFERENCES realms(id) ON DELETE CASCADE;

-- API keys should cascade when creator or realm is deleted
ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_created_by_fkey;
ALTER TABLE api_keys ADD CONSTRAINT api_keys_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_realm_id_fkey;
ALTER TABLE api_keys ADD CONSTRAINT api_keys_realm_id_fkey
    FOREIGN KEY (realm_id) REFERENCES realms(id) ON DELETE CASCADE;

-- Signing keys should cascade when realm is deleted
ALTER TABLE signing_keys DROP CONSTRAINT IF EXISTS signing_keys_realm_id_fkey;
ALTER TABLE signing_keys ADD CONSTRAINT signing_keys_realm_id_fkey
    FOREIGN KEY (realm_id) REFERENCES realms(id) ON DELETE CASCADE;

-- Audit events: keep but set actor_id to NULL when user is deleted
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_actor_id_fkey;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_actor_id_fkey
    FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_realm_id_fkey;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_realm_id_fkey
    FOREIGN KEY (realm_id) REFERENCES realms(id) ON DELETE CASCADE;
