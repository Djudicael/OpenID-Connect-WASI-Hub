//! Fixture functions and constants for integration tests.
//!
//! Provides deterministic test data (realms, users, clients, API keys)
//! with sensible defaults so individual tests don't have to construct
//! boilerplate entities from scratch.

use oidc_core::models::{Client, ClientType, Realm, User};
use oidc_core::traits::Hasher;
use oidc_core::traits::hasher::Argon2idHasher;
use uuid::Uuid;

// ===================================================================
// Constants
// ===================================================================

/// Deterministic 64-char hex encryption key (32 bytes) for tests.
pub const TEST_ENCRYPTION_KEY: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Default test admin user email.
pub const TEST_USER_EMAIL: &str = "testadmin@localhost";

/// Default test admin user password.
pub const TEST_USER_PASSWORD: &str = "TestPass123!";

/// Default test client ID (admin UI).
pub const TEST_CLIENT_ID: &str = "admin-ui";

// ===================================================================
// Fixture builders
// ===================================================================

/// Create a `Realm` with sensible defaults for testing.
///
/// The realm is enabled, has an empty JSON config, and no soft-delete.
pub fn test_realm(name: &str) -> Realm {
    Realm {
        id: Uuid::new_v4(),
        name: name.to_string(),
        display_name: name.to_string(),
        enabled: true,
        config: serde_json::Value::Object(serde_json::Map::new()),
        deleted_at: None,
    }
}

/// Create a `User` with a hashed password for testing.
///
/// The user is enabled, email-verified, and has no soft-delete.
/// The password is hashed using `Argon2idHasher`.
pub fn test_user(realm_id: Uuid, email: &str, password: &str) -> User {
    let hasher = Argon2idHasher::new();
    let password_hash = hasher
        .hash(password)
        .expect("failed to hash test user password");

    User {
        id: Uuid::new_v4(),
        realm_id,
        email: email.to_string(),
        email_verified: true,
        username: None,
        password_hash: Some(password_hash),
        given_name: None,
        family_name: None,
        phone_number: None,
        locale: None,
        attributes: serde_json::Value::Object(serde_json::Map::new()),
        enabled: true,
        deleted_at: None,
    }
}

/// Create a `Client` with sensible defaults for testing.
///
/// Defaults:
/// - **Confidential** client type
/// - PKCE required
/// - Allowed scopes: `openid`, `profile`, `email`
/// - Allowed grant types: `authorization_code`, `refresh_token`
/// - Enabled
pub fn test_client(realm_id: Uuid, client_id: &str, redirect_uris: Vec<String>) -> Client {
    Client {
        id: Uuid::new_v4(),
        realm_id,
        client_id: client_id.to_string(),
        client_type: ClientType::Confidential,
        client_secret_hash: None,
        name: client_id.to_string(),
        redirect_uris,
        allowed_scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ],
        allowed_grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        pkce_required: true,
        enabled: true,
        deleted_at: None,
    }
}
