//! Property-based tests using `proptest`.

use crate::OidcError;
use crate::models::client::{Client, ClientType};
use crate::models::realm::Realm;
use crate::models::user::User;
use crate::utils::pkce::{s256_challenge, verify_s256};
use crate::utils::token::{compute_at_hash, compute_c_hash, sha2_256_hex};
use proptest::prelude::*;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// PKCE property tests
// ---------------------------------------------------------------------------

proptest! {
    /// `s256_challenge` always produces a 43-character base64url string
    /// for any non-empty input.
    #[test]
    fn proptest_s256_challenge_length(verifier in ".{1,200}") {
        let challenge = s256_challenge(&verifier);
        prop_assert_eq!(challenge.len(), 43, "S256 challenge must be 43 base64url chars");
        // All characters must be valid base64url (A-Z, a-z, 0-9, -, _)
        for ch in challenge.chars() {
            prop_assert!(
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
                "Invalid base64url char: {}",
                ch
            );
        }
    }

    /// `verify_s256` roundtrips for any random verifier string.
    #[test]
    fn proptest_s256_roundtrip(verifier in ".{1,200}") {
        let challenge = s256_challenge(&verifier);
        prop_assert!(verify_s256(&verifier, &challenge));
        // A different verifier should not match
        let wrong = format!("{}x", &verifier);
        if wrong != verifier {
            prop_assert!(!verify_s256(&wrong, &challenge));
        }
    }
}

// ---------------------------------------------------------------------------
// Token utility property tests
// ---------------------------------------------------------------------------

proptest! {
    /// `sha2_256_hex` always returns a 64-character hex string for any input.
    #[test]
    fn proptest_sha2_256_hex_length(input in ".*") {
        let hash = sha2_256_hex(&input);
        prop_assert_eq!(hash.len(), 64, "SHA-256 hex must be 64 chars");
        for ch in hash.chars() {
            prop_assert!(
                ch.is_ascii_hexdigit(),
                "Invalid hex char: {}",
                ch
            );
        }
    }

    /// `sha2_256_hex` is deterministic: same input always produces same output.
    #[test]
    fn proptest_sha2_256_hex_deterministic(input in ".*") {
        let h1 = sha2_256_hex(&input);
        let h2 = sha2_256_hex(&input);
        prop_assert_eq!(h1, h2);
    }

    /// `compute_at_hash` always returns a non-empty string for any input.
    #[test]
    fn proptest_at_hash_nonempty(token in ".{1,200}") {
        let hash = compute_at_hash(&token);
        prop_assert!(!hash.is_empty(), "at_hash must not be empty");
    }

    /// `compute_at_hash` is deterministic.
    #[test]
    fn proptest_at_hash_deterministic(token in ".{1,200}") {
        let h1 = compute_at_hash(&token);
        let h2 = compute_at_hash(&token);
        prop_assert_eq!(h1, h2);
    }

    /// `compute_c_hash` always returns a non-empty string for any input.
    #[test]
    fn proptest_c_hash_nonempty(code in ".{1,200}") {
        let hash = compute_c_hash(&code);
        prop_assert!(!hash.is_empty(), "c_hash must not be empty");
    }

    /// `compute_c_hash` is deterministic.
    #[test]
    fn proptest_c_hash_deterministic(code in ".{1,200}") {
        let h1 = compute_c_hash(&code);
        let h2 = compute_c_hash(&code);
        prop_assert_eq!(h1, h2);
    }
}

// ---------------------------------------------------------------------------
// Model validation property tests
// ---------------------------------------------------------------------------

/// Helper to build a valid User with a given email.
fn make_user_with_email(email: String) -> User {
    User {
        id: Uuid::now_v7(),
        realm_id: Uuid::now_v7(),
        email,
        email_verified: false,
        username: None,
        password_hash: None,
        given_name: None,
        family_name: None,
        middle_name: None,
        nickname: None,
        preferred_username: None,
        profile: None,
        picture: None,
        website: None,
        gender: None,
        birthdate: None,
        zoneinfo: None,
        phone_number: None,
        phone_number_verified: None,
        locale: "en".into(),
        attributes: serde_json::Value::Object(serde_json::Map::new()),
        enabled: true,
        deleted_at: None,
        updated_at: chrono::Utc::now(),
    }
}

/// Helper to build a valid Realm with a given name.
fn make_realm_with_name(name: String) -> Realm {
    Realm {
        id: Uuid::now_v7(),
        name,
        display_name: "Test".into(),
        enabled: true,
        config: serde_json::Value::Object(serde_json::Map::new()),
        deleted_at: None,
    }
}

/// Helper to build a valid Client with a given client_id.
fn make_client_with_client_id(client_id: String) -> Client {
    Client {
        id: Uuid::now_v7(),
        realm_id: Uuid::now_v7(),
        client_id,
        client_type: ClientType::Confidential,
        client_secret_hash: None,
        name: "Test".into(),
        redirect_uris: vec!["https://example.com/callback".into()],
        allowed_scopes: vec!["openid".into()],
        allowed_grant_types: vec!["authorization_code".into()],
        pkce_required: true,
        enabled: true,
        deleted_at: None,
        token_endpoint_auth_method: "client_secret_basic".into(),
        jwks_uri: None,
        jwks: None,
        request_uris: vec![],
        client_secret_encrypted: None,
    }
}

proptest! {
    /// `User::validate` rejects empty emails.
    #[test]
    fn proptest_user_validate_rejects_empty_email(email in "") {
        let user = make_user_with_email(email);
        let result = user.validate();
        prop_assert!(matches!(result, Err(OidcError::InvalidInput(ref s)) if s.contains("empty")));
    }

    /// `User::validate` rejects emails without '@'.
    #[test]
    fn proptest_user_validate_rejects_no_at(email in "[^@]{1,50}") {
        let user = make_user_with_email(email.clone());
        let result = user.validate();
        prop_assert!(result.is_err(), "Email without @ should be rejected: {}", email);
    }

    /// `User::validate` rejects emails without '.' after '@'.
    #[test]
    fn proptest_user_validate_rejects_no_dot_after_at(email in "[a-z]+@[a-z]+") {
        // Only accept if there's no dot after the @
        if !email.split('@').nth(1).unwrap_or("").contains('.') {
            let user = make_user_with_email(email.clone());
            let result = user.validate();
            prop_assert!(result.is_err(), "Email without dot after @ should be rejected: {}", email);
        }
    }

    /// `User::validate` accepts valid emails.
    #[test]
    fn proptest_user_validate_accepts_valid_email(local in "[a-z]{1,10}", domain in "[a-z]{1,10}", tld in "[a-z]{2,5}") {
        let email = format!("{}@{}.{}", local, domain, tld);
        let user = make_user_with_email(email);
        let result = user.validate();
        prop_assert!(result.is_ok(), "Valid email should pass: {}@{}.{}", local, domain, tld);
    }

    /// `Realm::validate` rejects empty names.
    #[test]
    fn proptest_realm_validate_rejects_empty_name(name in "") {
        let realm = make_realm_with_name(name);
        let result = realm.validate();
        prop_assert!(matches!(result, Err(OidcError::InvalidInput(ref s)) if s.contains("empty")));
    }

    /// `Realm::validate` rejects names with special characters.
    #[test]
    fn proptest_realm_validate_rejects_special_chars(name in "[^a-zA-Z0-9_-]{1,20}") {
        // Skip if the name is empty (already tested) or only contains valid chars
        if !name.is_empty() && !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            let realm = make_realm_with_name(name.clone());
            let result = realm.validate();
            prop_assert!(result.is_err(), "Name with special chars should be rejected: {}", name);
        }
    }

    /// `Realm::validate` accepts valid names (alphanumeric, dashes, underscores).
    #[test]
    fn proptest_realm_validate_accepts_valid_name(name in "[a-zA-Z0-9_-]{1,30}") {
        if !name.is_empty() {
            let realm = make_realm_with_name(name.clone());
            let result = realm.validate();
            prop_assert!(result.is_ok(), "Valid name should pass: {}", name);
        }
    }

    /// `Client::validate` rejects empty client_ids.
    #[test]
    fn proptest_client_validate_rejects_empty_client_id(client_id in "") {
        let client = make_client_with_client_id(client_id);
        let result = client.validate();
        prop_assert!(matches!(result, Err(OidcError::InvalidInput(ref s)) if s.contains("client_id")));
    }

    /// `Client::validate` accepts non-empty client_ids.
    #[test]
    fn proptest_client_validate_accepts_nonempty_client_id(client_id in "[a-zA-Z0-9_-]{1,50}") {
        let client = make_client_with_client_id(client_id.clone());
        let result = client.validate();
        prop_assert!(result.is_ok(), "Non-empty client_id should pass: {}", client_id);
    }
}
