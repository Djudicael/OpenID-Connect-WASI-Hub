//! Database integration tests using a real PostgreSQL instance.
//!
//! Run with:
//! ```bash
//! podman run --rm -d -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=oidc_hub_test \
//!   -p 5433:5432 --name oidc_test_pg postgres:16-alpine
//! OIDC_DATABASE_URL=postgresql://postgres:postgres@localhost:5433/oidc_hub_test \
//!   cargo run -p oidc-migrate
//! TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:5433/oidc_hub_test \
//!   cargo test -p integration-tests -- --test-threads=1
//! ```

use chrono::Utc;
use oidc_core::OidcError;
use oidc_core::models::audit_event::{ActorType, AuditEvent};
use oidc_core::models::mls::{KeyPackageEntry, MlsGroup, MlsMember};
use oidc_core::models::signing_key::{Algorithm, SigningKey};
use oidc_core::models::{ApiKey, AuthCode, Client, ClientType, Realm, Session, User};
use oidc_repository::connection::Connection;
use oidc_repository::repositories::{
    api_key_repo::ApiKeyRepo, audit_event_repo::AuditEventRepo, auth_code_repo::AuthCodeRepo,
    client_repo::ClientRepo, mls_group_repo::MlsGroupRepo, mls_key_package_repo::MlsKeyPackageRepo,
    mls_member_repo::MlsMemberRepo, realm_repo::RealmRepo, session_repo::SessionRepo,
    signing_key_repo::SigningKeyRepo, user_repo::UserRepo,
};
use std::net::IpAddr;
use std::str::FromStr;
use uuid::Uuid;

/// Get a database connection for tests.
async fn test_conn() -> Connection {
    let url = std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
        "postgresql://postgres:postgres@localhost:5433/oidc_hub_test".to_string()
    });
    let config = wasi_pg_client::Config::from_uri(&url).expect("invalid TEST_DATABASE_URL");
    let pg_conn = wasi_pg_client::Connection::connect(&config)
        .await
        .expect("failed to connect");
    Connection::from_pg_client(pg_conn)
}

/// Clean all data tables (keep _migrations).
async fn clean_database(conn: &mut Connection) -> Result<(), OidcError> {
    let tables = [
        "audit_events",
        "mls_commits",
        "mls_members",
        "mls_key_packages",
        "mls_groups",
        "authorization_codes",
        "sessions",
        "api_keys",
        "signing_keys",
        "clients",
        "users",
        "realms",
    ];
    for table in &tables {
        conn.execute(&format!("DELETE FROM {}", table))
            .await
            .map_err(|e| oidc_core::OidcError::Internal(e.to_string()))?;
    }
    Ok(())
}

// ===================================================================
// Realm Repository Tests
// ===================================================================
#[tokio::test]
async fn test_realm_crud() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let repo = RealmRepo;
    let realm = Realm {
        id: Uuid::new_v4(),
        name: "test-realm".to_string(),
        display_name: "Test Realm".to_string(),
        enabled: true,
    };

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
    let realm = Realm {
        id: Uuid::new_v4(),
        name: "user-test-realm".to_string(),
        display_name: "User Test Realm".to_string(),
        enabled: true,
    };
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
        enabled: true,
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
    let realm = Realm {
        id: Uuid::new_v4(),
        name: "client-test-realm".to_string(),
        display_name: "Client Test".to_string(),
        enabled: true,
    };
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
    let realm = Realm {
        id: Uuid::new_v4(),
        name: "session-test-realm".to_string(),
        display_name: "Session Test".to_string(),
        enabled: true,
    };
    realm_repo.create(&mut conn, &realm).await.unwrap();

    let user_repo = UserRepo;
    let user = User {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        email: "session@example.com".to_string(),
        email_verified: true,
        username: None,
        password_hash: None,
        given_name: None,
        family_name: None,
        enabled: true,
    };
    user_repo.create(&mut conn, &user).await.unwrap();

    let client_repo = ClientRepo;
    let client = Client {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        client_id: "session-client".to_string(),
        client_type: ClientType::Public,
        client_secret_hash: None,
        name: "Session Client".to_string(),
        redirect_uris: vec![],
        allowed_scopes: vec!["openid".to_string()],
        allowed_grant_types: vec!["authorization_code".to_string()],
        pkce_required: true,
        enabled: true,
    };
    client_repo.create(&mut conn, &client).await.unwrap();

    let repo = SessionRepo;
    let session = Session {
        id: Uuid::new_v4(),
        user_id: user.id,
        realm_id: realm.id,
        client_id: client.id,
        grant_type: "authorization_code".to_string(),
        access_token_hash: "hash123".to_string(),
        refresh_token_hash: Some("refresh_hash".to_string()),
        id_token_jti: Some("jti123".to_string()),
        scope: vec!["openid".to_string(), "profile".to_string()],
        revoked: false,
    };

    repo.create(&mut conn, &session).await.unwrap();

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
    let realm = Realm {
        id: Uuid::new_v4(),
        name: "apikey-test-realm".to_string(),
        display_name: "API Key Test".to_string(),
        enabled: true,
    };
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
    let realm = Realm {
        id: Uuid::new_v4(),
        name: "authcode-test-realm".to_string(),
        display_name: "AuthCode Test".to_string(),
        enabled: true,
    };
    realm_repo.create(&mut conn, &realm).await.unwrap();

    let user_repo = UserRepo;
    let user = User {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        email: "auth@example.com".to_string(),
        email_verified: true,
        username: None,
        password_hash: None,
        given_name: None,
        family_name: None,
        enabled: true,
    };
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
        code_challenge_method: "S256".to_string(),
        used: false,
        expires_at: (Utc::now() + chrono::Duration::minutes(10)).timestamp(),
    };

    repo.create(&mut conn, &code).await.unwrap();

    let found = repo.find_by_code(&mut conn, "abc123").await.unwrap();
    assert!(found.is_some());
    let found = found.unwrap();
    assert_eq!(found.code, "abc123");
    assert!(!found.used);

    repo.mark_used(&mut conn, code.id).await.unwrap();
    let used = repo.find_by_code(&mut conn, "abc123").await.unwrap();
    assert!(used.is_none(), "Used code should not be found");
}

// ===================================================================
// MLS Group Repository Tests
// ===================================================================
#[tokio::test]
async fn test_mls_group_crud() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm_repo = RealmRepo;
    let realm = Realm {
        id: Uuid::new_v4(),
        name: "mls-test-realm".to_string(),
        display_name: "MLS Test".to_string(),
        enabled: true,
    };
    realm_repo.create(&mut conn, &realm).await.unwrap();

    let repo = MlsGroupRepo;
    let group = MlsGroup {
        id: Uuid::new_v4(),
        group_id: vec![1, 2, 3, 4],
        realm_id: realm.id,
        epoch: 0,
        roster_hash: None,
        group_state_encrypted: vec![5, 6, 7, 8],
        welcome_message: None,
    };

    repo.create(&mut conn, &group).await.unwrap();

    let found = repo.find_by_id(&mut conn, group.id).await.unwrap();
    assert!(found.is_some());
    let found = found.unwrap();
    assert_eq!(found.group_id, vec![1, 2, 3, 4]);
    assert_eq!(found.epoch, 0);

    let by_group_id = repo
        .find_by_group_id(&mut conn, &[1, 2, 3, 4])
        .await
        .unwrap();
    assert!(by_group_id.is_some());

    let mut updated = group.clone();
    updated.epoch = 5;
    updated.roster_hash = Some(vec![9, 10]);
    repo.update(&mut conn, &updated).await.unwrap();

    let found = repo.find_by_id(&mut conn, group.id).await.unwrap().unwrap();
    assert_eq!(found.epoch, 5);
    assert_eq!(found.roster_hash, Some(vec![9, 10]));

    repo.delete(&mut conn, group.id).await.unwrap();
    assert!(
        repo.find_by_id(&mut conn, group.id)
            .await
            .unwrap()
            .is_none()
    );
}

// ===================================================================
// MLS Member Repository Tests
// ===================================================================
#[tokio::test]
async fn test_mls_member_crud() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm_repo = RealmRepo;
    let realm = Realm {
        id: Uuid::new_v4(),
        name: "mls-member-test-realm".to_string(),
        display_name: "MLS Member Test".to_string(),
        enabled: true,
    };
    realm_repo.create(&mut conn, &realm).await.unwrap();

    let user_repo = UserRepo;
    let user = User {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        email: "mls@example.com".to_string(),
        email_verified: true,
        username: None,
        password_hash: None,
        given_name: None,
        family_name: None,
        enabled: true,
    };
    user_repo.create(&mut conn, &user).await.unwrap();

    let group_repo = MlsGroupRepo;
    let group = MlsGroup {
        id: Uuid::new_v4(),
        group_id: vec![1, 2, 3],
        realm_id: realm.id,
        epoch: 0,
        roster_hash: None,
        group_state_encrypted: vec![4, 5, 6],
        welcome_message: None,
    };
    group_repo.create(&mut conn, &group).await.unwrap();

    let repo = MlsMemberRepo;
    let member = MlsMember {
        id: Uuid::new_v4(),
        group_id: group.id,
        user_id: user.id,
        credential: vec![7, 8, 9],
        leaf_index: 0,
        added_at: Utc::now(),
        removed_at: None,
    };

    repo.create(&mut conn, &member).await.unwrap();

    let found = repo.find_by_id(&mut conn, member.id).await.unwrap();
    assert!(found.is_some());

    let active = repo
        .find_active_by_group(&mut conn, group.id)
        .await
        .unwrap();
    assert_eq!(active.len(), 1);

    let by_gu = repo
        .find_by_group_and_user(&mut conn, group.id, user.id)
        .await
        .unwrap();
    assert!(by_gu.is_some());

    repo.remove_member(&mut conn, group.id, user.id)
        .await
        .unwrap();
    let active = repo
        .find_active_by_group(&mut conn, group.id)
        .await
        .unwrap();
    assert!(active.is_empty());
}

// ===================================================================
// MLS KeyPackage Repository Tests
// ===================================================================
#[tokio::test]
async fn test_mls_key_package_crud() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm_repo = RealmRepo;
    let realm = Realm {
        id: Uuid::new_v4(),
        name: "mls-kp-test-realm".to_string(),
        display_name: "MLS KP Test".to_string(),
        enabled: true,
    };
    realm_repo.create(&mut conn, &realm).await.unwrap();

    let user_repo = UserRepo;
    let user = User {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        email: "kp@example.com".to_string(),
        email_verified: true,
        username: None,
        password_hash: None,
        given_name: None,
        family_name: None,
        enabled: true,
    };
    user_repo.create(&mut conn, &user).await.unwrap();

    let repo = MlsKeyPackageRepo;
    let kp = KeyPackageEntry {
        id: Uuid::new_v4(),
        user_id: user.id,
        key_package_ref: vec![1, 2, 3],
        key_package_encrypted: vec![4, 5, 6],
        used: false,
        created_at: Utc::now(),
        expires_at: None,
    };

    repo.create(&mut conn, &kp).await.unwrap();

    let found = repo.find_by_id(&mut conn, kp.id).await.unwrap();
    assert!(found.is_some());

    let by_ref = repo.find_by_ref(&mut conn, &[1, 2, 3]).await.unwrap();
    assert!(by_ref.is_some());

    let unused = repo.find_unused_by_user(&mut conn, user.id).await.unwrap();
    assert_eq!(unused.len(), 1);

    repo.mark_used(&mut conn, kp.id).await.unwrap();
    let unused = repo.find_unused_by_user(&mut conn, user.id).await.unwrap();
    assert!(unused.is_empty());
}

// ===================================================================
// Signing Key Repository Tests
// ===================================================================
#[tokio::test]
async fn test_signing_key_crud() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm_repo = RealmRepo;
    let realm = Realm {
        id: Uuid::new_v4(),
        name: "signing-test-realm".to_string(),
        display_name: "Signing Key Test".to_string(),
        enabled: true,
    };
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
    let realm = Realm {
        id: Uuid::new_v4(),
        name: "audit-test-realm".to_string(),
        display_name: "Audit Test".to_string(),
        enabled: true,
    };
    realm_repo.create(&mut conn, &realm).await.unwrap();

    let user_repo = UserRepo;
    let user = User {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        email: "audit@example.com".to_string(),
        email_verified: true,
        username: None,
        password_hash: None,
        given_name: None,
        family_name: None,
        enabled: true,
    };
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

    let by_realm = repo.find_by_realm(&mut conn, realm.id, 10).await.unwrap();
    assert_eq!(by_realm.len(), 1);

    let by_actor = repo.find_by_actor(&mut conn, user.id, 10).await.unwrap();
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
    let realm = Realm {
        id: Uuid::new_v4(),
        name: "perf-test-realm".to_string(),
        display_name: "Perf Test".to_string(),
        enabled: true,
    };
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
            enabled: true,
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
    let realm = Realm {
        id: Uuid::new_v4(),
        name: "session-perf-realm".to_string(),
        display_name: "Session Perf".to_string(),
        enabled: true,
    };
    realm_repo.create(&mut conn, &realm).await.unwrap();

    let user_repo = UserRepo;
    let user = User {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        email: "session@example.com".to_string(),
        email_verified: true,
        username: None,
        password_hash: None,
        given_name: None,
        family_name: None,
        enabled: true,
    };
    user_repo.create(&mut conn, &user).await.unwrap();

    let client_repo = ClientRepo;
    let client = Client {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        client_id: "perf-client".to_string(),
        client_type: ClientType::Public,
        client_secret_hash: None,
        name: "Perf Client".to_string(),
        redirect_uris: vec![],
        allowed_scopes: vec!["openid".to_string()],
        allowed_grant_types: vec!["authorization_code".to_string()],
        pkce_required: true,
        enabled: true,
    };
    client_repo.create(&mut conn, &client).await.unwrap();

    let session_repo = SessionRepo;

    for i in 0..1000 {
        let session = Session {
            id: Uuid::new_v4(),
            user_id: user.id,
            realm_id: realm.id,
            client_id: client.id,
            grant_type: "authorization_code".to_string(),
            access_token_hash: format!("hash_{:04}", i),
            refresh_token_hash: Some(format!("refresh_{:04}", i)),
            id_token_jti: None,
            scope: vec!["openid".to_string()],
            revoked: false,
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
    let realm = Realm {
        id: Uuid::new_v4(),
        name: "apikey-perf-realm".to_string(),
        display_name: "API Key Perf".to_string(),
        enabled: true,
    };
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
    let realm = Realm {
        id: Uuid::new_v4(),
        name: "audit-perf-realm".to_string(),
        display_name: "Audit Perf".to_string(),
        enabled: true,
    };
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
    assert!(table_names.contains(&"mls_groups".to_string()));
    assert!(table_names.contains(&"mls_members".to_string()));
    assert!(table_names.contains(&"mls_key_packages".to_string()));
    assert!(table_names.contains(&"audit_events".to_string()));
    assert!(table_names.contains(&"authorization_codes".to_string()));
    assert!(table_names.contains(&"_migrations".to_string()));
}
