//! Database integration tests using a real PostgreSQL instance.
//!
//! The test harness (see `crate::harness`) spawns a single `podman`
//! container before the first test and reuses it for the entire run.

use chrono::Utc;
use oidc_core::models::audit_event::{ActorType, AuditEvent};
use oidc_core::models::auth_code::CodeChallengeMethod;
use oidc_core::models::signing_key::{Algorithm, SigningKey};
use oidc_core::models::{ApiKey, AuthCode, Client, ClientType, Realm, ResponseType, Session, User};
use oidc_repository::repositories::{
    api_key_repo::ApiKeyRepo, audit_event_repo::AuditEventRepo, auth_code_repo::AuthCodeRepo,
    client_repo::ClientRepo, realm_repo::RealmRepo, session_repo::SessionRepo,
    signing_key_repo::SigningKeyRepo, user_repo::UserRepo,
};
use std::net::IpAddr;
use std::str::FromStr;
use uuid::Uuid;

use crate::harness::{clean_database, test_conn};

/// Helper to create a test realm with default config.
fn test_realm(name: &str, display_name: &str) -> Realm {
    Realm {
        id: Uuid::new_v4(),
        name: name.to_string(),
        display_name: display_name.to_string(),
        enabled: true,
        config: serde_json::Value::Object(serde_json::Map::new()),
        deleted_at: None,
    }
}

/// Helper to create a test user with default fields.
fn test_user(realm_id: Uuid, email: &str) -> User {
    User {
        id: Uuid::new_v4(),
        realm_id,
        email: email.to_string(),
        email_verified: true,
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

/// Helper to create a test client with default fields.
fn test_client(realm_id: Uuid, client_id: &str, name: &str) -> Client {
    Client {
        id: Uuid::new_v4(),
        realm_id,
        client_id: client_id.to_string(),
        client_type: ClientType::Public,
        client_secret_hash: None,
        name: name.to_string(),
        redirect_uris: vec![],
        allowed_scopes: vec!["openid".to_string()],
        allowed_grant_types: vec!["authorization_code".to_string()],
        pkce_required: true,
        enabled: true,
        deleted_at: None,
    }
}

// ===================================================================
// Realm Repository Tests
// ===================================================================
#[tokio::test]
async fn test_realm_crud() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let repo = RealmRepo;
    let realm = test_realm("test-realm", "Test Realm");

    repo.create(&mut conn, &realm).await.unwrap();

    let found = repo.find_by_id(&mut conn, realm.id).await.unwrap();
    assert!(found.is_some());
    let found = found.unwrap();
    assert_eq!(found.name, "test-realm");
    assert_eq!(found.display_name, "Test Realm");
    assert!(found.enabled);

    let by_name = repo.find_by_name(&mut conn, "test-realm").await.unwrap();
    assert!(by_name.is_some());
    assert_eq!(by_name.unwrap().id, realm.id);

    let mut updated = realm.clone();
    updated.display_name = "Updated Realm".to_string();
    updated.enabled = false;
    repo.update(&mut conn, &updated).await.unwrap();

    let found = repo.find_by_id(&mut conn, realm.id).await.unwrap().unwrap();
    assert_eq!(found.display_name, "Updated Realm");
    assert!(!found.enabled);

    repo.delete(&mut conn, realm.id).await.unwrap();
    let deleted = repo.find_by_id(&mut conn, realm.id).await.unwrap();
    assert!(deleted.is_none());
}

// ===================================================================
// User Repository Tests (with soft delete)
// ===================================================================
#[tokio::test]
async fn test_user_crud_and_soft_delete() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm_repo = RealmRepo;
    let realm = test_realm("user-test-realm", "User Test Realm");
    realm_repo.create(&mut conn, &realm).await.unwrap();

    let repo = UserRepo;
    let user = User {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        email: "test@example.com".to_string(),
        email_verified: false,
        username: Some("testuser".to_string()),
        password_hash: Some("$argon2id$...".to_string()),
        given_name: Some("Test".to_string()),
        family_name: Some("User".to_string()),
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
    };

    repo.create(&mut conn, &user).await.unwrap();

    let found = repo.find_by_id(&mut conn, user.id).await.unwrap();
    assert!(found.is_some());
    let found = found.unwrap();
    assert_eq!(found.email, "test@example.com");
    assert_eq!(found.username, Some("testuser".to_string()));

    let by_email = repo
        .find_by_email(&mut conn, realm.id, "test@example.com")
        .await
        .unwrap();
    assert!(by_email.is_some());

    repo.delete(&mut conn, user.id).await.unwrap();
    let deleted = repo.find_by_id(&mut conn, user.id).await.unwrap();
    assert!(deleted.is_none(), "Soft-deleted user should not be found");

    let raw = conn
        .query_params("SELECT deleted_at FROM users WHERE id = $1", &[&user.id])
        .await
        .unwrap();
    assert_eq!(raw.len(), 1);
}

// ===================================================================
// Client Repository Tests
// ===================================================================
#[tokio::test]
async fn test_client_crud() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm_repo = RealmRepo;
    let realm = test_realm("client-test-realm", "Client Test");
    realm_repo.create(&mut conn, &realm).await.unwrap();

    let repo = ClientRepo;
    let client = Client {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        client_id: "my-client".to_string(),
        client_type: ClientType::Confidential,
        client_secret_hash: Some("secret_hash".to_string()),
        name: "My Client".to_string(),
        redirect_uris: vec!["https://app.example.com/callback".to_string()],
        allowed_scopes: vec!["openid".to_string(), "profile".to_string()],
        allowed_grant_types: vec!["authorization_code".to_string()],
        pkce_required: true,
        enabled: true,
        deleted_at: None,
    };

    repo.create(&mut conn, &client).await.unwrap();

    let found = repo.find_by_id(&mut conn, client.id).await.unwrap();
    assert!(found.is_some());
    let found = found.unwrap();
    assert_eq!(found.client_id, "my-client");
    assert_eq!(found.client_type, ClientType::Confidential);
    assert!(found.pkce_required);

    let by_client_id = repo
        .find_by_client_id(&mut conn, "my-client")
        .await
        .unwrap();
    assert!(by_client_id.is_some());

    let mut updated = client.clone();
    updated.name = "Updated Client".to_string();
    updated.enabled = false;
    repo.update(&mut conn, &updated).await.unwrap();

    let found = repo
        .find_by_id(&mut conn, client.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.name, "Updated Client");
    assert!(!found.enabled);

    repo.delete(&mut conn, client.id).await.unwrap();
    assert!(
        repo.find_by_id(&mut conn, client.id)
            .await
            .unwrap()
            .is_none()
    );
}

// ===================================================================
// Session Repository Tests
// ===================================================================
#[tokio::test]
async fn test_session_crud() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm_repo = RealmRepo;
    let realm = test_realm("session-test-realm", "Session Test");
    realm_repo.create(&mut conn, &realm).await.unwrap();

    let user_repo = UserRepo;
    let user = test_user(realm.id, "session@example.com");
    user_repo.create(&mut conn, &user).await.unwrap();

    let client_repo = ClientRepo;
    let client = test_client(realm.id, "session-client", "Session Client");
    client_repo.create(&mut conn, &client).await.unwrap();

    let now = chrono::Utc::now();
    let repo = SessionRepo;
    let session = Session {
        id: Uuid::new_v4(),
        user_id: Some(user.id),
        realm_id: realm.id,
        client_id: client.id,
        grant_type: "authorization_code".to_string(),
        access_token_hash: "hash123".to_string(),
        refresh_token_hash: Some("refresh_hash".to_string()),
        id_token_jti: Some("jti123".to_string()),
        scope: vec!["openid".to_string(), "profile".to_string()],
        revoked: false,
        expires_at: now + chrono::Duration::hours(1),
        refresh_expires_at: Some(now + chrono::Duration::days(30)),
        created_at: now,
        last_used_at: None,
        token_family_id: Some(Uuid::new_v4()),
        previous_session_id: None,
        rotated_at: None,
        reused_at: None,
        family_revoked: false,
    };

    repo.create(&mut conn, &session).await.unwrap();

    // ---- find_by_id ----
    let found = repo.find_by_id(&mut conn, session.id).await.unwrap();
    assert!(found.is_some());
    let found = found.unwrap();
    assert_eq!(found.access_token_hash, "hash123");

    let by_access = repo
        .find_by_access_token_hash(&mut conn, "hash123")
        .await
        .unwrap();
    assert!(by_access.is_some());

    let by_refresh = repo
        .find_by_refresh_token_hash(&mut conn, "refresh_hash")
        .await
        .unwrap();
    assert!(by_refresh.is_some());

    repo.revoke(&mut conn, session.id).await.unwrap();
    let revoked = repo
        .find_by_access_token_hash(&mut conn, "hash123")
        .await
        .unwrap();
    assert!(
        revoked.is_none(),
        "Revoked session should not be found by access token"
    );
}

// ===================================================================
// API Key Repository Tests
// ===================================================================
#[tokio::test]
async fn test_api_key_crud() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm_repo = RealmRepo;
    let realm = test_realm("apikey-test-realm", "API Key Test");
    realm_repo.create(&mut conn, &realm).await.unwrap();

    let repo = ApiKeyRepo;
    let key = ApiKey {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        name: "test-key".to_string(),
        prefix: "tk_".to_string(),
        hashed_secret: "argon2id_hash".to_string(),
        scopes: vec!["read".to_string(), "write".to_string()],
        revoked: false,
        request_count: 0,
        expires_at: None,
        last_used_at: None,
        created_at: chrono::Utc::now(),
        created_by: None,
        rotated_at: None,
    };

    repo.create(&mut conn, &key).await.unwrap();

    let found = repo.find_by_id(&mut conn, key.id).await.unwrap();
    assert!(found.is_some());
    let found = found.unwrap();
    assert_eq!(found.prefix, "tk_");
    assert_eq!(found.scopes, vec!["read", "write"]);

    let by_prefix = repo.find_by_prefix(&mut conn, "tk_").await.unwrap();
    assert!(by_prefix.is_some());

    repo.increment_count(&mut conn, key.id).await.unwrap();
    let updated = repo.find_by_id(&mut conn, key.id).await.unwrap().unwrap();
    assert_eq!(updated.request_count, 1);

    repo.revoke(&mut conn, key.id).await.unwrap();
    let revoked = repo.find_by_prefix(&mut conn, "tk_").await.unwrap();
    assert!(revoked.is_none());
}

// ===================================================================
// Auth Code Repository Tests
// ===================================================================
#[tokio::test]
async fn test_auth_code_crud() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm_repo = RealmRepo;
    let realm = test_realm("authcode-test-realm", "AuthCode Test");
    realm_repo.create(&mut conn, &realm).await.unwrap();

    let user_repo = UserRepo;
    let user = test_user(realm.id, "auth@example.com");
    user_repo.create(&mut conn, &user).await.unwrap();

    let client_repo = ClientRepo;
    let client = Client {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        client_id: "auth-client".to_string(),
        client_type: ClientType::Public,
        client_secret_hash: None,
        name: "Auth Client".to_string(),
        redirect_uris: vec!["https://app.example.com/callback".to_string()],
        allowed_scopes: vec!["openid".to_string()],
        allowed_grant_types: vec!["authorization_code".to_string()],
        pkce_required: true,
        enabled: true,
        deleted_at: None,
    };
    client_repo.create(&mut conn, &client).await.unwrap();

    let repo = AuthCodeRepo;
    let code = AuthCode {
        id: Uuid::new_v4(),
        code: "abc123".to_string(),
        client_id: client.id,
        user_id: user.id,
        realm_id: realm.id,
        redirect_uri: "https://app.example.com/callback".to_string(),
        scope: vec!["openid".to_string()],
        code_challenge: "challenge123".to_string(),
        code_challenge_method: CodeChallengeMethod::S256,
        nonce: Some("test-nonce".to_string()),
        used: false,
        claims_request: None,
        display: None,
        response_type: ResponseType::CODE,
        expires_at: Utc::now() + chrono::Duration::minutes(10),
    };

    repo.create(&mut conn, &code).await.unwrap();

    let found = repo.find_by_code(&mut conn, "abc123").await.unwrap();
    assert!(found.is_some());
    let found = found.unwrap();
    // AuthCodeRepo stores the SHA-256 hash of the code, not the plaintext
    let expected_hash = oidc_core::utils::sha2_256_hex("abc123");
    assert_eq!(found.code, expected_hash);
    assert!(!found.used);

    repo.mark_used(&mut conn, code.id).await.unwrap();
    let used = repo.find_by_code(&mut conn, "abc123").await.unwrap();
    assert!(used.is_none(), "Used code should not be found");
}

// ===================================================================
// Signing Key Repository Tests
// ===================================================================
#[tokio::test]
async fn test_signing_key_crud() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm_repo = RealmRepo;
    let realm = test_realm("signing-test-realm", "Signing Key Test");
    realm_repo.create(&mut conn, &realm).await.unwrap();

    let repo = SigningKeyRepo;
    let key = SigningKey {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        kid: "key-2024-01".to_string(),
        algorithm: Algorithm::Rs256,
        public_key_pem: "-----BEGIN PUBLIC KEY-----\n...".to_string(),
        private_key_pem_encrypted: Some("encrypted_pem".to_string()),
        active: true,
        created_at: Utc::now(),
        expires_at: None,
        retired_at: None,
    };

    repo.create(&mut conn, &key).await.unwrap();

    let found = repo.find_by_id(&mut conn, key.id).await.unwrap();
    assert!(found.is_some());
    let found = found.unwrap();
    assert_eq!(found.kid, "key-2024-01");
    assert_eq!(found.algorithm, Algorithm::Rs256);
    assert!(found.active);

    let by_kid = repo.find_by_kid(&mut conn, "key-2024-01").await.unwrap();
    assert!(by_kid.is_some());

    let active = repo
        .find_active_by_realm(&mut conn, realm.id)
        .await
        .unwrap();
    assert_eq!(active.len(), 1);

    repo.retire(&mut conn, key.id).await.unwrap();
    let active = repo
        .find_active_by_realm(&mut conn, realm.id)
        .await
        .unwrap();
    assert!(active.is_empty());
}

// ===================================================================
// Audit Event Repository Tests
// ===================================================================
#[tokio::test]
async fn test_audit_event_crud() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm_repo = RealmRepo;
    let realm = test_realm("audit-test-realm", "Audit Test");
    realm_repo.create(&mut conn, &realm).await.unwrap();

    let user_repo = UserRepo;
    let user = test_user(realm.id, "audit@example.com");
    user_repo.create(&mut conn, &user).await.unwrap();

    let repo = AuditEventRepo;
    let event = AuditEvent {
        id: Uuid::new_v4(),
        realm_id: Some(realm.id),
        event_type: "user.login".to_string(),
        actor_id: Some(user.id),
        actor_type: ActorType::User,
        target_type: Some("user".to_string()),
        target_id: Some(user.id),
        details: serde_json::json!({"ip": "192.168.1.1", "method": "password"}),
        ip_address: Some(IpAddr::from_str("192.168.1.1").unwrap()),
        user_agent: Some("Mozilla/5.0".to_string()),
        created_at: Utc::now(),
    };

    repo.create(&mut conn, &event).await.unwrap();

    let found = repo.find_by_id(&mut conn, event.id).await.unwrap();
    assert!(found.is_some());
    let found = found.unwrap();
    assert_eq!(found.event_type, "user.login");
    assert_eq!(found.actor_type, ActorType::User);

    let by_realm = repo
        .find_by_realm(&mut conn, realm.id, 10, 0, None, None, None)
        .await
        .unwrap();
    assert_eq!(by_realm.len(), 1);

    let by_actor = repo.find_by_actor(&mut conn, user.id, 10, 0).await.unwrap();
    assert_eq!(by_actor.len(), 1);
}

// ===================================================================
// Performance & Index Verification Tests
// ===================================================================
#[tokio::test]
async fn test_user_email_index_performance() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm_repo = RealmRepo;
    let realm = test_realm("perf-test-realm", "Perf Test");
    realm_repo.create(&mut conn, &realm).await.unwrap();

    let user_repo = UserRepo;

    for i in 0..1000 {
        let user = User {
            id: Uuid::new_v4(),
            realm_id: realm.id,
            email: format!("user{}@example.com", i),
            email_verified: true,
            username: Some(format!("user{}", i)),
            password_hash: Some("hash".to_string()),
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
        };
        user_repo.create(&mut conn, &user).await.unwrap();
    }

    let explain = conn.query_params(
        "EXPLAIN (FORMAT TEXT) SELECT id FROM users WHERE realm_id = $1 AND email = 'user500@example.com' AND deleted_at IS NULL",
        &[&realm.id],
    ).await.unwrap();
    let plan: String = explain
        .iter()
        .map(|r| r.get::<String>(0).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        plan.contains("Index Scan") || plan.contains("idx_users_realm_email"),
        "Expected index scan, got:\n{}",
        plan
    );

    let start = std::time::Instant::now();
    let found = user_repo
        .find_by_email(&mut conn, realm.id, "user500@example.com")
        .await
        .unwrap();
    let elapsed = start.elapsed();
    assert!(found.is_some());
    assert!(
        elapsed < std::time::Duration::from_millis(100),
        "Lookup took {:?}, expected < 100ms",
        elapsed
    );
}

#[tokio::test]
async fn test_session_token_hash_index_performance() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm_repo = RealmRepo;
    let realm = test_realm("session-perf-realm", "Session Perf");
    realm_repo.create(&mut conn, &realm).await.unwrap();

    let user_repo = UserRepo;
    let user = test_user(realm.id, "session@example.com");
    user_repo.create(&mut conn, &user).await.unwrap();

    let client_repo = ClientRepo;
    let client = test_client(realm.id, "perf-client", "Perf Client");
    client_repo.create(&mut conn, &client).await.unwrap();

    let session_repo = SessionRepo;

    for i in 0..1000 {
        let now = chrono::Utc::now();
        let session = Session {
            id: Uuid::new_v4(),
            user_id: Some(user.id),
            realm_id: realm.id,
            client_id: client.id,
            grant_type: "authorization_code".to_string(),
            access_token_hash: format!("hash_{:04}", i),
            refresh_token_hash: Some(format!("refresh_{:04}", i)),
            id_token_jti: None,
            scope: vec!["openid".to_string()],
            revoked: false,
            expires_at: now + chrono::Duration::hours(1),
            refresh_expires_at: Some(now + chrono::Duration::days(7)),
            created_at: now,
            last_used_at: None,
            token_family_id: None,
            previous_session_id: None,
            rotated_at: None,
            reused_at: None,
            family_revoked: false,
        };
        session_repo.create(&mut conn, &session).await.unwrap();
    }

    let explain = conn.query(
        "EXPLAIN (FORMAT TEXT) SELECT id FROM sessions WHERE access_token_hash = 'hash_0500' AND NOT revoked",
    ).await.unwrap();
    let plan: String = explain
        .iter()
        .map(|r| r.get::<String>(0).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        plan.contains("Index Scan") || plan.contains("idx_sessions_access_hash"),
        "Expected index scan, got:\n{}",
        plan
    );

    let start = std::time::Instant::now();
    let found = session_repo
        .find_by_access_token_hash(&mut conn, "hash_0500")
        .await
        .unwrap();
    let elapsed = start.elapsed();
    assert!(found.is_some());
    assert!(
        elapsed < std::time::Duration::from_millis(100),
        "Lookup took {:?}, expected < 100ms",
        elapsed
    );
}

#[tokio::test]
async fn test_api_key_prefix_index_performance() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm_repo = RealmRepo;
    let realm = test_realm("apikey-perf-realm", "API Key Perf");
    realm_repo.create(&mut conn, &realm).await.unwrap();

    let repo = ApiKeyRepo;

    for i in 0..1000 {
        let key = ApiKey {
            id: Uuid::new_v4(),
            realm_id: realm.id,
            name: format!("key-{}", i),
            prefix: format!("tk_{:04}", i),
            hashed_secret: "secret".to_string(),
            scopes: vec!["read".to_string()],
            revoked: false,
            request_count: 0,
            expires_at: None,
            last_used_at: None,
            created_at: chrono::Utc::now(),
            created_by: None,
            rotated_at: None,
        };
        repo.create(&mut conn, &key).await.unwrap();
    }

    let explain = conn.query(
        "EXPLAIN (FORMAT TEXT) SELECT id FROM api_keys WHERE prefix = 'tk_0500' AND NOT revoked",
    ).await.unwrap();
    let plan: String = explain
        .iter()
        .map(|r| r.get::<String>(0).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        plan.contains("Index Scan") || plan.contains("idx_api_keys_prefix"),
        "Expected index scan, got:\n{}",
        plan
    );

    let start = std::time::Instant::now();
    let found = repo.find_by_prefix(&mut conn, "tk_0500").await.unwrap();
    let elapsed = start.elapsed();
    assert!(found.is_some());
    assert!(
        elapsed < std::time::Duration::from_millis(100),
        "Lookup took {:?}, expected < 100ms",
        elapsed
    );
}

#[tokio::test]
async fn test_audit_event_insertion_performance() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm_repo = RealmRepo;
    let realm = test_realm("audit-perf-realm", "Audit Perf");
    realm_repo.create(&mut conn, &realm).await.unwrap();

    let repo = AuditEventRepo;

    let mut max_elapsed = std::time::Duration::ZERO;
    for i in 0..100 {
        let event = AuditEvent {
            id: Uuid::new_v4(),
            realm_id: Some(realm.id),
            event_type: "user.login".to_string(),
            actor_id: None,
            actor_type: ActorType::System,
            target_type: None,
            target_id: None,
            details: serde_json::json!({"index": i}),
            ip_address: None,
            user_agent: None,
            created_at: Utc::now(),
        };

        let start = std::time::Instant::now();
        repo.create(&mut conn, &event).await.unwrap();
        let elapsed = start.elapsed();
        if elapsed > max_elapsed {
            max_elapsed = elapsed;
        }
    }

    assert!(
        max_elapsed < std::time::Duration::from_millis(10),
        "Audit event insertion p99-like latency was {:?}, expected < 10ms",
        max_elapsed
    );
}

// ===================================================================
// Migration Rollback Verification
// ===================================================================
#[tokio::test]
async fn test_migration_idempotency() {
    let mut conn = test_conn().await;

    let result = conn
        .query(
            r#"
        CREATE TABLE IF NOT EXISTS realms (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid()
        );
    "#,
        )
        .await;
    assert!(
        result.is_ok(),
        "Re-running idempotent migration should not fail"
    );

    let tables = conn.query(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name"
    ).await.unwrap();
    let table_names: Vec<String> = tables.iter().map(|r| r.get::<String>(0).unwrap()).collect();

    assert!(table_names.contains(&"realms".to_string()));
    assert!(table_names.contains(&"users".to_string()));
    assert!(table_names.contains(&"clients".to_string()));
    assert!(table_names.contains(&"sessions".to_string()));
    assert!(table_names.contains(&"api_keys".to_string()));
    assert!(table_names.contains(&"signing_keys".to_string()));
    assert!(table_names.contains(&"audit_events".to_string()));
    assert!(table_names.contains(&"authorization_codes".to_string()));
    assert!(table_names.contains(&"_migrations".to_string()));
}

// ===================================================================
// ON DELETE Cascade Tests
// ===================================================================

#[tokio::test]
async fn test_cascade_delete_sessions_on_user_delete() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm_repo = RealmRepo;
    let realm = test_realm("cascade-test-realm", "Cascade Test");
    realm_repo.create(&mut conn, &realm).await.unwrap();

    let user_repo = UserRepo;
    let user = test_user(realm.id, "cascade@example.com");
    user_repo.create(&mut conn, &user).await.unwrap();

    let client_repo = ClientRepo;
    let client = test_client(realm.id, "cascade-client", "Cascade Client");
    client_repo.create(&mut conn, &client).await.unwrap();

    let now = chrono::Utc::now();
    let session_repo = SessionRepo;
    let session = Session {
        id: Uuid::new_v4(),
        user_id: Some(user.id),
        realm_id: realm.id,
        client_id: client.id,
        grant_type: "authorization_code".to_string(),
        access_token_hash: "cascade_hash".to_string(),
        refresh_token_hash: Some("cascade_refresh_hash".to_string()),
        id_token_jti: None,
        scope: vec!["openid".to_string()],
        revoked: false,
        expires_at: now + chrono::Duration::minutes(15),
        refresh_expires_at: Some(now + chrono::Duration::days(7)),
        created_at: now,
        last_used_at: None,
        token_family_id: None,
        previous_session_id: None,
        rotated_at: None,
        reused_at: None,
        family_revoked: false,
    };
    session_repo.create(&mut conn, &session).await.unwrap();

    // Verify the session exists
    let found = session_repo
        .find_by_id(&mut conn, session.id)
        .await
        .unwrap();
    assert!(found.is_some(), "session should exist before user deletion");

    // Delete the user (hard delete — bypass soft-delete to trigger cascade)
    conn.execute_params("DELETE FROM users WHERE id = $1", &[&user.id])
        .await
        .expect("failed to delete user");

    // Verify the session is also deleted (or revoked)
    // With ON DELETE CASCADE, the session row should be gone entirely
    let found_after = session_repo
        .find_by_id(&mut conn, session.id)
        .await
        .unwrap();
    assert!(
        found_after.is_none(),
        "session should be deleted (cascade) after user is deleted"
    );
}

// ===================================================================
// Unique Constraint Violation
// ===================================================================

#[tokio::test]
async fn test_unique_constraint_violation_surface() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm_repo = RealmRepo;
    let realm1 = test_realm("test-realm", "Test Realm");
    realm_repo.create(&mut conn, &realm1).await.unwrap();

    // Try to create another realm with the same name
    let realm2 = test_realm("test-realm", "Another Test Realm");
    let result = realm_repo.create(&mut conn, &realm2).await;

    // The error should be OidcError::Conflict (not OidcError::Internal)
    let err = result.expect_err("creating a realm with a duplicate name should fail");
    assert!(
        matches!(err, oidc_core::OidcError::Conflict(_)),
        "unique constraint violation should surface as OidcError::Conflict, got: {err:?}"
    );
}

// ===================================================================
// Expired Session Cleanup
// ===================================================================

#[tokio::test]
async fn test_expired_session_cleanup() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm_repo = RealmRepo;
    let realm = test_realm("session-cleanup-realm", "Session Cleanup");
    realm_repo.create(&mut conn, &realm).await.unwrap();

    let user_repo = UserRepo;
    let user = test_user(realm.id, "cleanup-session@example.com");
    user_repo.create(&mut conn, &user).await.unwrap();

    let client_repo = ClientRepo;
    let client = test_client(realm.id, "session-cleanup-client", "Session Cleanup Client");
    client_repo.create(&mut conn, &client).await.unwrap();

    let now = chrono::Utc::now();
    let session_repo = SessionRepo;

    // Create a session with expires_at in the past
    let expired_session = Session {
        id: Uuid::new_v4(),
        user_id: Some(user.id),
        realm_id: realm.id,
        client_id: client.id,
        grant_type: "authorization_code".to_string(),
        access_token_hash: "expired_session_hash".to_string(),
        refresh_token_hash: Some("expired_refresh_hash".to_string()),
        id_token_jti: None,
        scope: vec!["openid".to_string()],
        revoked: false,
        expires_at: now - chrono::Duration::minutes(5), // expired 5 minutes ago
        refresh_expires_at: Some(now - chrono::Duration::hours(1)),
        created_at: now - chrono::Duration::hours(1),
        last_used_at: None,
        token_family_id: None,
        previous_session_id: None,
        rotated_at: None,
        reused_at: None,
        family_revoked: false,
    };
    session_repo
        .create(&mut conn, &expired_session)
        .await
        .unwrap();

    // Verify the expired session exists
    let found = session_repo
        .find_by_id(&mut conn, expired_session.id)
        .await
        .unwrap();
    assert!(
        found.is_some(),
        "expired session should exist before cleanup"
    );

    // Call cleanup_expired
    let deleted = session_repo.cleanup_expired(&mut conn).await.unwrap();
    assert!(
        deleted > 0,
        "cleanup_expired should delete at least one session"
    );

    // Verify the expired session is deleted
    let found_after = session_repo
        .find_by_id(&mut conn, expired_session.id)
        .await
        .unwrap();
    assert!(
        found_after.is_none(),
        "expired session should be deleted after cleanup"
    );
}

// ===================================================================
// Auth Code Cleanup
// ===================================================================

#[tokio::test]
async fn test_expired_auth_code_cleanup() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm_repo = RealmRepo;
    let realm = test_realm("authcode-cleanup-realm", "AuthCode Cleanup");
    realm_repo.create(&mut conn, &realm).await.unwrap();

    let user_repo = UserRepo;
    let user = test_user(realm.id, "authcode-cleanup@example.com");
    user_repo.create(&mut conn, &user).await.unwrap();

    let client_repo = ClientRepo;
    let client = test_client(
        realm.id,
        "authcode-cleanup-client",
        "AuthCode Cleanup Client",
    );
    client_repo.create(&mut conn, &client).await.unwrap();

    let auth_code_repo = AuthCodeRepo;

    // Create an auth code with expires_at in the past
    // Note: The code is hashed on insert, so we need to use the raw code for lookup
    let raw_code = "expired_auth_code_123";
    let expired_code = AuthCode {
        id: Uuid::new_v4(),
        code: raw_code.to_string(),
        client_id: client.id,
        user_id: user.id,
        realm_id: realm.id,
        redirect_uri: "https://app.example.com/callback".to_string(),
        scope: vec!["openid".to_string()],
        code_challenge: "challenge".to_string(),
        code_challenge_method: CodeChallengeMethod::S256,
        nonce: None,
        used: false,
        claims_request: None,
        display: None,
        response_type: ResponseType::CODE,
        expires_at: Utc::now() - chrono::Duration::minutes(5), // expired 5 minutes ago
    };
    auth_code_repo
        .create(&mut conn, &expired_code)
        .await
        .unwrap();

    // Verify the expired auth code exists (it won't be found by find_by_code because it's expired)
    // but we can check directly in the database
    let raw = conn
        .query_params(
            "SELECT id FROM authorization_codes WHERE id = $1",
            &[&expired_code.id],
        )
        .await
        .unwrap();
    assert_eq!(
        raw.len(),
        1,
        "expired auth code should exist before cleanup"
    );

    // Call cleanup_expired
    let deleted = auth_code_repo.cleanup_expired(&mut conn).await.unwrap();
    assert!(
        deleted > 0,
        "cleanup_expired should delete at least one auth code"
    );

    // Verify the expired auth code is deleted
    let raw_after = conn
        .query_params(
            "SELECT id FROM authorization_codes WHERE id = $1",
            &[&expired_code.id],
        )
        .await
        .unwrap();
    assert_eq!(
        raw_after.len(),
        0,
        "expired auth code should be deleted after cleanup"
    );
}
