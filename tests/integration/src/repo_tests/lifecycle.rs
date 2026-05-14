//! Full lifecycle tests for each repository.
//!
//! These tests exercise complete create → read → update → delete flows,
//! plus edge cases like empty results, null optional fields, and
//! multi-step operations on a single connection.

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

// ===================================================================
// Helpers
// ===================================================================

fn make_realm(name: &str) -> Realm {
    Realm {
        id: Uuid::new_v4(),
        name: name.to_string(),
        display_name: name.to_string(),
        enabled: true,
        config: serde_json::Value::Object(serde_json::Map::new()),
        deleted_at: None,
    }
}

fn make_user(realm_id: Uuid, email: &str) -> User {
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

fn make_client(realm_id: Uuid, client_id: &str) -> Client {
    Client {
        id: Uuid::new_v4(),
        realm_id,
        client_id: client_id.to_string(),
        client_type: ClientType::Public,
        client_secret_hash: None,
        name: client_id.to_string(),
        redirect_uris: vec![],
        allowed_scopes: vec!["openid".to_string()],
        allowed_grant_types: vec!["authorization_code".to_string()],
        pkce_required: true,
        enabled: true,
        deleted_at: None,
    }
}

fn make_session(user_id: Uuid, realm_id: Uuid, client_id: Uuid, hash: &str) -> Session {
    let now = chrono::Utc::now();
    Session {
        id: Uuid::new_v4(),
        user_id: Some(user_id),
        realm_id,
        client_id,
        grant_type: "authorization_code".to_string(),
        access_token_hash: hash.to_string(),
        refresh_token_hash: None,
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
    }
}

fn make_api_key(realm_id: Uuid, name: &str) -> ApiKey {
    ApiKey {
        id: Uuid::new_v4(),
        realm_id,
        name: name.to_string(),
        prefix: format!(
            "{}_{}",
            name.chars().take(3).collect::<String>(),
            Uuid::new_v4()
                .as_simple()
                .to_string()
                .chars()
                .take(5)
                .collect::<String>()
        ),
        hashed_secret: "argon2id_test_hash".to_string(),
        scopes: vec!["admin".to_string()],
        revoked: false,
        request_count: 0,
        expires_at: None,
        last_used_at: None,
        created_at: chrono::Utc::now(),
        created_by: None,
        rotated_at: None,
    }
}

fn make_signing_key(realm_id: Uuid, kid: &str) -> SigningKey {
    SigningKey {
        id: Uuid::new_v4(),
        realm_id,
        kid: kid.to_string(),
        algorithm: Algorithm::Rs256,
        public_key_pem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----".to_string(),
        private_key_pem_encrypted: Some("encrypted_pem".to_string()),
        active: true,
        created_at: chrono::Utc::now(),
        expires_at: None,
        retired_at: None,
    }
}

fn make_auth_code(client_id: Uuid, user_id: Uuid, realm_id: Uuid, code: &str) -> AuthCode {
    AuthCode {
        id: Uuid::new_v4(),
        code: code.to_string(),
        client_id,
        user_id,
        realm_id,
        redirect_uri: "https://app.example.com/callback".to_string(),
        scope: vec!["openid".to_string()],
        code_challenge: "test_challenge".to_string(),
        code_challenge_method: CodeChallengeMethod::S256,
        nonce: None,
        used: false,
        claims_request: None,
        display: None,
        response_type: ResponseType::CODE,
        expires_at: Utc::now() + chrono::Duration::minutes(10),
    }
}

fn make_audit_event(realm_id: Uuid, event_type: &str, actor_id: Option<Uuid>) -> AuditEvent {
    AuditEvent {
        id: Uuid::new_v4(),
        realm_id: Some(realm_id),
        event_type: event_type.to_string(),
        actor_id,
        actor_type: ActorType::User,
        target_type: Some("user".to_string()),
        target_id: actor_id,
        details: serde_json::json!({"test": true}),
        ip_address: Some(IpAddr::from_str("127.0.0.1").unwrap()),
        user_agent: Some("test-agent".to_string()),
        created_at: Utc::now(),
    }
}

/// Seed a realm + user + client for tests that need all three.
async fn seed_realm_user_client() -> (Realm, User, Client) {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm = make_realm("lifecycle-realm");
    RealmRepo
        .create(&mut conn, &realm)
        .await
        .expect("realm create");

    let user = make_user(realm.id, "lifecycle@example.com");
    UserRepo
        .create(&mut conn, &user)
        .await
        .expect("user create");

    let client = make_client(realm.id, "lifecycle-client");
    ClientRepo
        .create(&mut conn, &client)
        .await
        .expect("client create");

    (realm, user, client)
}

// ===================================================================
// Realm lifecycle
// ===================================================================

#[tokio::test]
async fn test_realm_find_by_name_not_found() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let found = RealmRepo
        .find_by_name(&mut conn, "nonexistent")
        .await
        .expect("find_by_name should not error on missing realm");
    assert!(found.is_none());
}

#[tokio::test]
async fn test_realm_list_and_count() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    // Initially empty
    let count = RealmRepo.count(&mut conn).await.expect("count failed");
    assert_eq!(count, 0);

    // Create 3 realms
    for i in 0..3 {
        let realm = make_realm(&format!("list-realm-{}", i));
        RealmRepo
            .create(&mut conn, &realm)
            .await
            .expect("realm create");
    }

    let count = RealmRepo.count(&mut conn).await.expect("count failed");
    assert_eq!(count, 3);

    let list = RealmRepo.list(&mut conn, 2, 0).await.expect("list failed");
    assert_eq!(list.len(), 2);

    let list = RealmRepo.list(&mut conn, 2, 2).await.expect("list failed");
    assert_eq!(list.len(), 1);
}

#[tokio::test]
async fn test_realm_soft_delete_excludes_from_queries() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm = make_realm("soft-delete-realm");
    RealmRepo
        .create(&mut conn, &realm)
        .await
        .expect("realm create");

    assert!(
        RealmRepo
            .find_by_id(&mut conn, realm.id)
            .await
            .unwrap()
            .is_some()
    );

    RealmRepo
        .delete(&mut conn, realm.id)
        .await
        .expect("delete failed");

    assert!(
        RealmRepo
            .find_by_id(&mut conn, realm.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        RealmRepo
            .find_by_name(&mut conn, "soft-delete-realm")
            .await
            .unwrap()
            .is_none()
    );

    let count = RealmRepo.count(&mut conn).await.expect("count failed");
    assert_eq!(count, 0);
}

// ===================================================================
// User lifecycle
// ===================================================================

#[tokio::test]
async fn test_user_optional_fields() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm = make_realm("user-optional-realm");
    RealmRepo
        .create(&mut conn, &realm)
        .await
        .expect("realm create");

    // User with all optional fields set
    let user = User {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        email: "full@example.com".to_string(),
        email_verified: true,
        username: Some("fulluser".to_string()),
        password_hash: Some("$argon2id$test".to_string()),
        given_name: Some("Full".to_string()),
        family_name: Some("User".to_string()),
        middle_name: Some("M".to_string()),
        nickname: Some("fullie".to_string()),
        preferred_username: Some("fulluser".to_string()),
        profile: Some("https://example.com/profile".to_string()),
        picture: Some("https://example.com/picture".to_string()),
        website: Some("https://example.com".to_string()),
        gender: Some("male".to_string()),
        birthdate: Some("1990-01-01".to_string()),
        zoneinfo: Some("America/New_York".to_string()),
        phone_number: Some("+1234567890".to_string()),
        phone_number_verified: Some(true),
        locale: "en".into(),
        attributes: serde_json::json!({"key": "value"}),
        enabled: true,
        deleted_at: None,
        updated_at: chrono::Utc::now(),
    };
    UserRepo
        .create(&mut conn, &user)
        .await
        .expect("user create");

    let found = UserRepo
        .find_by_id(&mut conn, user.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.username, Some("fulluser".to_string()));
    assert_eq!(found.given_name, Some("Full".to_string()));
    assert_eq!(found.family_name, Some("User".to_string()));
    assert_eq!(found.phone_number, Some("+1234567890".to_string()));
    assert_eq!(found.locale, "en".to_string());
    assert_eq!(found.password_hash, Some("$argon2id$test".to_string()));
}

#[tokio::test]
async fn test_user_list_with_search() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm = make_realm("user-search-realm");
    RealmRepo
        .create(&mut conn, &realm)
        .await
        .expect("realm create");

    for name in &["alice", "bob", "charlie"] {
        let mut user = make_user(realm.id, &format!("{}@search.com", name));
        user.username = Some(name.to_string());
        UserRepo
            .create(&mut conn, &user)
            .await
            .expect("user create");
    }

    // Search by email
    let list = UserRepo
        .list(&mut conn, Some(realm.id), Some("alice"), 10, 0)
        .await
        .expect("list failed");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].email, "alice@search.com");

    // Count with realm filter
    let count = UserRepo
        .count(&mut conn, Some(realm.id))
        .await
        .expect("count failed");
    assert_eq!(count, 3);
}

#[tokio::test]
async fn test_user_update() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm = make_realm("user-update-realm");
    RealmRepo
        .create(&mut conn, &realm)
        .await
        .expect("realm create");

    let mut user = make_user(realm.id, "update@example.com");
    UserRepo
        .create(&mut conn, &user)
        .await
        .expect("user create");

    user.email = "updated@example.com".to_string();
    user.given_name = Some("Updated".to_string());
    user.enabled = false;
    UserRepo
        .update(&mut conn, &user)
        .await
        .expect("user update");

    let found = UserRepo
        .find_by_id(&mut conn, user.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.email, "updated@example.com");
    assert_eq!(found.given_name, Some("Updated".to_string()));
    assert!(!found.enabled);
}

// ===================================================================
// Client lifecycle
// ===================================================================

#[tokio::test]
async fn test_client_confidential_with_secret() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm = make_realm("client-secret-realm");
    RealmRepo
        .create(&mut conn, &realm)
        .await
        .expect("realm create");

    let client = Client {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        client_id: "confidential-client".to_string(),
        client_type: ClientType::Confidential,
        client_secret_hash: Some("argon2id_hash_of_secret".to_string()),
        name: "Confidential Client".to_string(),
        redirect_uris: vec!["https://app.example.com/callback".to_string()],
        allowed_scopes: vec!["openid".to_string(), "profile".to_string()],
        allowed_grant_types: vec![
            "authorization_code".to_string(),
            "client_credentials".to_string(),
        ],
        pkce_required: false,
        enabled: true,
        deleted_at: None,
    };
    ClientRepo
        .create(&mut conn, &client)
        .await
        .expect("client create");

    let found = ClientRepo
        .find_by_client_id(&mut conn, "confidential-client")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.client_type, ClientType::Confidential);
    assert_eq!(
        found.client_secret_hash,
        Some("argon2id_hash_of_secret".to_string())
    );
    assert!(!found.pkce_required);
    assert_eq!(found.redirect_uris.len(), 1);
    assert_eq!(found.allowed_grant_types.len(), 2);
}

#[tokio::test]
async fn test_client_list_with_filters() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm = make_realm("client-list-realm");
    RealmRepo
        .create(&mut conn, &realm)
        .await
        .expect("realm create");

    for i in 0..3 {
        let client = make_client(realm.id, &format!("list-client-{}", i));
        ClientRepo
            .create(&mut conn, &client)
            .await
            .expect("client create");
    }

    let list = ClientRepo
        .list(&mut conn, Some(realm.id), None, 10, 0)
        .await
        .expect("list failed");
    assert_eq!(list.len(), 3);

    let list = ClientRepo
        .list(&mut conn, Some(realm.id), Some("list-client-1"), 10, 0)
        .await
        .expect("list failed");
    assert_eq!(list.len(), 1);

    let count = ClientRepo
        .count(&mut conn, Some(realm.id))
        .await
        .expect("count failed");
    assert_eq!(count, 3);
}

#[tokio::test]
async fn test_client_update() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm = make_realm("client-update-realm");
    RealmRepo
        .create(&mut conn, &realm)
        .await
        .expect("realm create");

    let mut client = make_client(realm.id, "update-client");
    ClientRepo
        .create(&mut conn, &client)
        .await
        .expect("client create");

    client.name = "Updated Client".to_string();
    client.enabled = false;
    client.redirect_uris = vec!["https://new.example.com/callback".to_string()];
    ClientRepo
        .update(&mut conn, &client)
        .await
        .expect("client update");

    let found = ClientRepo
        .find_by_id(&mut conn, client.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.name, "Updated Client");
    assert!(!found.enabled);
    assert_eq!(
        found.redirect_uris,
        vec!["https://new.example.com/callback"]
    );
}

// ===================================================================
// Session lifecycle
// ===================================================================

#[tokio::test]
async fn test_session_lifecycle_create_find_revoke() {
    let (realm, user, client) = seed_realm_user_client().await;
    let mut conn = test_conn().await;

    let session = make_session(user.id, realm.id, client.id, "lifecycle_hash");
    SessionRepo
        .create(&mut conn, &session)
        .await
        .expect("session create");

    // Find by id
    let found = SessionRepo
        .find_by_id(&mut conn, session.id)
        .await
        .expect("find_by_id failed");
    assert!(found.is_some());

    // Find by access token hash
    let found = SessionRepo
        .find_by_access_token_hash(&mut conn, "lifecycle_hash")
        .await
        .expect("find_by_access_token_hash failed");
    assert!(found.is_some());

    // Revoke
    SessionRepo
        .revoke(&mut conn, session.id)
        .await
        .expect("revoke failed");

    // Revoked session should not be found by access token hash
    let found = SessionRepo
        .find_by_access_token_hash(&mut conn, "lifecycle_hash")
        .await
        .expect("find_by_access_token_hash failed");
    assert!(
        found.is_none(),
        "revoked session should not be found by access token hash"
    );

    // But still found by id (no filter on revoked)
    let found = SessionRepo
        .find_by_id(&mut conn, session.id)
        .await
        .expect("find_by_id failed");
    assert!(found.is_some());
    assert!(found.unwrap().revoked);
}

#[tokio::test]
async fn test_session_refresh_token_lifecycle() {
    let (realm, user, client) = seed_realm_user_client().await;
    let mut conn = test_conn().await;

    let mut session = make_session(user.id, realm.id, client.id, "refresh_lifecycle_hash");
    session.refresh_token_hash = Some("refresh_lifecycle_rhash".to_string());
    SessionRepo
        .create(&mut conn, &session)
        .await
        .expect("session create");

    // Find by refresh token hash (includes FOR UPDATE)
    let found = SessionRepo
        .find_by_refresh_token_hash(&mut conn, "refresh_lifecycle_rhash")
        .await
        .expect("find_by_refresh_token_hash failed");
    assert!(found.is_some());

    // Find active by refresh token hash
    let found = SessionRepo
        .find_active_by_refresh_token_hash(&mut conn, "refresh_lifecycle_rhash")
        .await
        .expect("find_active_by_refresh_token_hash failed");
    assert!(found.is_some());

    // Revoke
    SessionRepo
        .revoke(&mut conn, session.id)
        .await
        .expect("revoke failed");

    // Revoked session should not be found by active refresh token hash
    let found = SessionRepo
        .find_active_by_refresh_token_hash(&mut conn, "refresh_lifecycle_rhash")
        .await
        .expect("find_active failed");
    assert!(found.is_none());
}

#[tokio::test]
async fn test_session_token_rotation_chain() {
    let (realm, user, client) = seed_realm_user_client().await;
    let mut conn = test_conn().await;

    let family_id = Uuid::new_v4();

    // Create initial session
    let mut session1 = make_session(user.id, realm.id, client.id, "rotation_hash_1");
    session1.refresh_token_hash = Some("rotation_rhash_1".to_string());
    session1.token_family_id = Some(family_id);
    SessionRepo
        .create(&mut conn, &session1)
        .await
        .expect("session1 create");

    // Mark as rotated
    SessionRepo
        .mark_rotated(&mut conn, session1.id)
        .await
        .expect("mark_rotated failed");

    // Create rotated session (new tokens, references previous)
    let mut session2 = make_session(user.id, realm.id, client.id, "rotation_hash_2");
    session2.refresh_token_hash = Some("rotation_rhash_2".to_string());
    session2.token_family_id = Some(family_id);
    session2.previous_session_id = Some(session1.id);
    SessionRepo
        .create(&mut conn, &session2)
        .await
        .expect("session2 create");

    // Find the new session by its access token hash
    let found = SessionRepo
        .find_by_access_token_hash(&mut conn, "rotation_hash_2")
        .await
        .expect("find failed");
    assert!(found.is_some());
    let found = found.unwrap();
    assert_eq!(found.previous_session_id, Some(session1.id));
    assert_eq!(found.token_family_id, Some(family_id));

    // Revoke the entire family
    SessionRepo
        .revoke_family(&mut conn, family_id)
        .await
        .expect("revoke_family failed");

    // Both sessions should now be revoked and not findable by active queries
    assert!(
        SessionRepo
            .find_by_access_token_hash(&mut conn, "rotation_hash_1")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        SessionRepo
            .find_by_access_token_hash(&mut conn, "rotation_hash_2")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn test_session_reuse_detection() {
    let (realm, user, client) = seed_realm_user_client().await;
    let mut conn = test_conn().await;

    let session = make_session(user.id, realm.id, client.id, "reuse_hash");
    SessionRepo
        .create(&mut conn, &session)
        .await
        .expect("session create");

    // Mark as reused (token theft detection)
    SessionRepo
        .mark_reused(&mut conn, session.id)
        .await
        .expect("mark_reused failed");

    let found = SessionRepo
        .find_by_id(&mut conn, session.id)
        .await
        .unwrap()
        .unwrap();
    assert!(found.reused_at.is_some(), "reused_at should be set");
}

#[tokio::test]
async fn test_session_revoke_all_for_user() {
    let (realm, user, client) = seed_realm_user_client().await;
    let mut conn = test_conn().await;

    // Create 3 sessions for the same user
    for i in 0..3 {
        let session = make_session(
            user.id,
            realm.id,
            client.id,
            &format!("user_revoke_hash_{}", i),
        );
        SessionRepo
            .create(&mut conn, &session)
            .await
            .expect("session create");
    }

    // Revoke all sessions for the user
    SessionRepo
        .revoke_by_user_id(&mut conn, user.id)
        .await
        .expect("revoke_by_user_id failed");

    // None should be findable by access token hash
    for i in 0..3 {
        let found = SessionRepo
            .find_by_access_token_hash(&mut conn, &format!("user_revoke_hash_{}", i))
            .await
            .unwrap();
        assert!(found.is_none(), "session {} should be revoked", i);
    }
}

#[tokio::test]
async fn test_session_list_and_count() {
    let (realm, user, client) = seed_realm_user_client().await;
    let mut conn = test_conn().await;

    for i in 0..5 {
        let session = make_session(user.id, realm.id, client.id, &format!("list_hash_{}", i));
        SessionRepo
            .create(&mut conn, &session)
            .await
            .expect("session create");
    }

    let count = SessionRepo
        .count(&mut conn, None, None, None)
        .await
        .expect("count failed");
    assert_eq!(count, 5);

    let list = SessionRepo
        .list(&mut conn, Some(user.id), Some(realm.id), None, 3, 0)
        .await
        .expect("list failed");
    assert_eq!(list.len(), 3);

    let list = SessionRepo
        .list(&mut conn, Some(user.id), Some(realm.id), None, 3, 3)
        .await
        .expect("list failed");
    assert_eq!(list.len(), 2);
}

// ===================================================================
// API Key lifecycle
// ===================================================================

#[tokio::test]
async fn test_api_key_lifecycle() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm = make_realm("apikey-lifecycle-realm");
    RealmRepo
        .create(&mut conn, &realm)
        .await
        .expect("realm create");

    let key = make_api_key(realm.id, "lifecycle-key");
    ApiKeyRepo
        .create(&mut conn, &key)
        .await
        .expect("api key create");

    // Find by id
    let found = ApiKeyRepo
        .find_by_id(&mut conn, key.id)
        .await
        .expect("find_by_id failed");
    assert!(found.is_some());

    // Find by prefix (active keys only)
    let found = ApiKeyRepo
        .find_by_prefix(&mut conn, &key.prefix)
        .await
        .expect("find_by_prefix failed");
    assert!(found.is_some());

    // Increment count
    ApiKeyRepo
        .increment_count(&mut conn, key.id)
        .await
        .expect("increment_count failed");
    let found = ApiKeyRepo
        .find_by_id(&mut conn, key.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.request_count, 1);

    // Increment again
    ApiKeyRepo
        .increment_count(&mut conn, key.id)
        .await
        .expect("increment_count failed");
    let found = ApiKeyRepo
        .find_by_id(&mut conn, key.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.request_count, 2);

    // Mark rotated
    ApiKeyRepo
        .mark_rotated(&mut conn, key.id)
        .await
        .expect("mark_rotated failed");
    let found = ApiKeyRepo
        .find_by_id(&mut conn, key.id)
        .await
        .unwrap()
        .unwrap();
    assert!(found.rotated_at.is_some());

    // Revoke
    ApiKeyRepo
        .revoke(&mut conn, key.id)
        .await
        .expect("revoke failed");

    // Revoked key should not be found by prefix
    let found = ApiKeyRepo
        .find_by_prefix(&mut conn, &key.prefix)
        .await
        .expect("find_by_prefix failed");
    assert!(found.is_none(), "revoked key should not be found by prefix");

    // But still found by id
    let found = ApiKeyRepo
        .find_by_id(&mut conn, key.id)
        .await
        .expect("find_by_id failed");
    assert!(found.is_some());
    assert!(found.unwrap().revoked);
}

#[tokio::test]
async fn test_api_key_find_by_realm() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm = make_realm("apikey-realm-realm");
    RealmRepo
        .create(&mut conn, &realm)
        .await
        .expect("realm create");

    for i in 0..3 {
        let key = make_api_key(realm.id, &format!("realm-key-{}", i));
        ApiKeyRepo
            .create(&mut conn, &key)
            .await
            .expect("api key create");
    }

    let keys = ApiKeyRepo
        .find_by_realm(&mut conn, realm.id, false)
        .await
        .expect("find_by_realm failed");
    assert_eq!(keys.len(), 3);

    // Revoke the first
    ApiKeyRepo
        .revoke(&mut conn, keys[0].id)
        .await
        .expect("revoke failed");

    // Active only
    let active = ApiKeyRepo
        .find_by_realm(&mut conn, realm.id, false)
        .await
        .expect("find_by_realm failed");
    assert_eq!(active.len(), 2);

    // Include revoked
    let all = ApiKeyRepo
        .find_by_realm(&mut conn, realm.id, true)
        .await
        .expect("find_by_realm failed");
    assert_eq!(all.len(), 3);
}

#[tokio::test]
async fn test_api_key_expired_not_found_by_prefix() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm = make_realm("apikey-expired-realm");
    RealmRepo
        .create(&mut conn, &realm)
        .await
        .expect("realm create");

    let mut key = make_api_key(realm.id, "expired-key");
    key.expires_at = Some(Utc::now() - chrono::Duration::hours(1));
    ApiKeyRepo
        .create(&mut conn, &key)
        .await
        .expect("api key create");

    // Expired key should not be found by prefix
    let found = ApiKeyRepo
        .find_by_prefix(&mut conn, &key.prefix)
        .await
        .expect("find_by_prefix failed");
    assert!(found.is_none(), "expired key should not be found by prefix");
}

// ===================================================================
// Signing Key lifecycle
// ===================================================================

#[tokio::test]
async fn test_signing_key_lifecycle() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm = make_realm("signing-lifecycle-realm");
    RealmRepo
        .create(&mut conn, &realm)
        .await
        .expect("realm create");

    let key = make_signing_key(realm.id, "lifecycle-kid");
    SigningKeyRepo
        .create(&mut conn, &key)
        .await
        .expect("signing key create");

    // Find by id
    let found = SigningKeyRepo
        .find_by_id(&mut conn, key.id)
        .await
        .expect("find_by_id failed");
    assert!(found.is_some());

    // Find by kid
    let found = SigningKeyRepo
        .find_by_kid(&mut conn, "lifecycle-kid")
        .await
        .expect("find_by_kid failed");
    assert!(found.is_some());

    // Find active by realm
    let active = SigningKeyRepo
        .find_active_by_realm(&mut conn, realm.id)
        .await
        .expect("find_active_by_realm failed");
    assert_eq!(active.len(), 1);

    // Retire the key
    SigningKeyRepo
        .retire(&mut conn, key.id)
        .await
        .expect("retire failed");

    // Should no longer be in active list
    let active = SigningKeyRepo
        .find_active_by_realm(&mut conn, realm.id)
        .await
        .expect("find_active_by_realm failed");
    assert!(active.is_empty());

    // But still findable by id and kid
    assert!(
        SigningKeyRepo
            .find_by_id(&mut conn, key.id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        SigningKeyRepo
            .find_by_kid(&mut conn, "lifecycle-kid")
            .await
            .unwrap()
            .is_some()
    );

    let found = SigningKeyRepo
        .find_by_id(&mut conn, key.id)
        .await
        .unwrap()
        .unwrap();
    assert!(!found.active);
    assert!(found.retired_at.is_some());
}

#[tokio::test]
async fn test_signing_key_update() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm = make_realm("signing-update-realm");
    RealmRepo
        .create(&mut conn, &realm)
        .await
        .expect("realm create");

    let mut key = make_signing_key(realm.id, "update-kid");
    SigningKeyRepo
        .create(&mut conn, &key)
        .await
        .expect("signing key create");

    key.public_key_pem =
        "-----BEGIN PUBLIC KEY-----\nupdated\n-----END PUBLIC KEY-----".to_string();
    key.active = false;
    SigningKeyRepo
        .update(&mut conn, &key)
        .await
        .expect("signing key update");

    let found = SigningKeyRepo
        .find_by_id(&mut conn, key.id)
        .await
        .unwrap()
        .unwrap();
    assert!(!found.active);
    assert!(found.public_key_pem.contains("updated"));
}

// ===================================================================
// Auth Code lifecycle
// ===================================================================

#[tokio::test]
async fn test_auth_code_lifecycle() {
    let (realm, user, client) = seed_realm_user_client().await;
    let mut conn = test_conn().await;

    let code = make_auth_code(client.id, user.id, realm.id, "lifecycle_code");
    AuthCodeRepo
        .create(&mut conn, &code)
        .await
        .expect("auth code create");

    // Find by code (hashes the code internally)
    let found = AuthCodeRepo
        .find_by_code(&mut conn, "lifecycle_code")
        .await
        .expect("find_by_code failed");
    assert!(found.is_some());
    let found = found.unwrap();
    assert!(!found.used);

    // Mark as used
    AuthCodeRepo
        .mark_used(&mut conn, code.id)
        .await
        .expect("mark_used failed");

    // Used code should not be found
    let found = AuthCodeRepo
        .find_by_code(&mut conn, "lifecycle_code")
        .await
        .expect("find_by_code failed");
    assert!(
        found.is_none(),
        "used auth code should not be found by find_by_code"
    );
}

#[tokio::test]
async fn test_auth_code_wrong_code_not_found() {
    let (realm, user, client) = seed_realm_user_client().await;
    let mut conn = test_conn().await;

    let code = make_auth_code(client.id, user.id, realm.id, "correct_code");
    AuthCodeRepo
        .create(&mut conn, &code)
        .await
        .expect("auth code create");

    // Wrong code should not be found
    let found = AuthCodeRepo
        .find_by_code(&mut conn, "wrong_code")
        .await
        .expect("find_by_code failed");
    assert!(found.is_none());
}

// ===================================================================
// Audit Event tests
// ===================================================================

#[tokio::test]
async fn test_audit_event_create_and_find() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm = make_realm("audit-repo-realm");
    RealmRepo
        .create(&mut conn, &realm)
        .await
        .expect("realm create");

    let user = make_user(realm.id, "audit@example.com");
    UserRepo
        .create(&mut conn, &user)
        .await
        .expect("user create");

    let event = make_audit_event(realm.id, "user.login", Some(user.id));
    AuditEventRepo
        .create(&mut conn, &event)
        .await
        .expect("audit event create");

    // Find by id
    let found = AuditEventRepo
        .find_by_id(&mut conn, event.id)
        .await
        .expect("find_by_id failed");
    assert!(found.is_some());
    let found = found.unwrap();
    assert_eq!(found.event_type, "user.login");
    assert_eq!(found.actor_type, ActorType::User);
    assert_eq!(found.actor_id, Some(user.id));

    // Find by realm
    let by_realm = AuditEventRepo
        .find_by_realm(&mut conn, realm.id, 10, 0, None, None, None)
        .await
        .expect("find_by_realm failed");
    assert_eq!(by_realm.len(), 1);

    // Find by actor
    let by_actor = AuditEventRepo
        .find_by_actor(&mut conn, user.id, 10, 0)
        .await
        .expect("find_by_actor failed");
    assert_eq!(by_actor.len(), 1);
}

#[tokio::test]
async fn test_audit_event_count_recent_failures() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm = make_realm("audit-failures-realm");
    RealmRepo
        .create(&mut conn, &realm)
        .await
        .expect("realm create");

    let user = make_user(realm.id, "failures@example.com");
    UserRepo
        .create(&mut conn, &user)
        .await
        .expect("user create");

    // Create 3 LOGIN_FAILURE events
    for _ in 0..3 {
        let event = AuditEvent {
            id: Uuid::new_v4(),
            realm_id: Some(realm.id),
            event_type: "LOGIN_FAILURE".to_string(),
            actor_id: Some(user.id),
            actor_type: ActorType::User,
            target_type: Some("user".to_string()),
            target_id: Some(user.id),
            details: serde_json::json!({"reason": "wrong_password"}),
            ip_address: Some(IpAddr::from_str("10.0.0.1").unwrap()),
            user_agent: Some("test".to_string()),
            created_at: Utc::now(),
        };
        AuditEventRepo
            .create(&mut conn, &event)
            .await
            .expect("audit event create");
    }

    // Count recent failures
    let count = AuditEventRepo
        .count_recent_failures(&mut conn, "failures@example.com", realm.id)
        .await
        .expect("count_recent_failures failed");
    assert_eq!(count, 3);

    // Non-existent user should return 0
    let count = AuditEventRepo
        .count_recent_failures(&mut conn, "nobody@example.com", realm.id)
        .await
        .expect("count_recent_failures failed");
    assert_eq!(count, 0);
}

#[tokio::test]
async fn test_audit_event_system_actor() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm = make_realm("audit-system-realm");
    RealmRepo
        .create(&mut conn, &realm)
        .await
        .expect("realm create");

    // System event (no actor_id)
    let event = AuditEvent {
        id: Uuid::new_v4(),
        realm_id: Some(realm.id),
        event_type: "system.startup".to_string(),
        actor_id: None,
        actor_type: ActorType::System,
        target_type: None,
        target_id: None,
        details: serde_json::json!({"version": "0.1.0"}),
        ip_address: None,
        user_agent: None,
        created_at: Utc::now(),
    };
    AuditEventRepo
        .create(&mut conn, &event)
        .await
        .expect("audit event create");

    let found = AuditEventRepo
        .find_by_id(&mut conn, event.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.actor_type, ActorType::System);
    assert!(found.actor_id.is_none());
}

#[tokio::test]
async fn test_audit_event_list_recent() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    let realm = make_realm("audit-list-realm");
    RealmRepo
        .create(&mut conn, &realm)
        .await
        .expect("realm create");

    for i in 0..5 {
        let event = make_audit_event(realm.id, &format!("event.{}", i), None);
        AuditEventRepo
            .create(&mut conn, &event)
            .await
            .expect("audit event create");
    }

    let list = AuditEventRepo
        .list_recent(&mut conn, 3, 0, None, None, None, None)
        .await
        .expect("list_recent failed");
    assert_eq!(list.len(), 3);

    let list = AuditEventRepo
        .list_recent(&mut conn, 3, 3, None, None, None, None)
        .await
        .expect("list_recent failed");
    assert_eq!(list.len(), 2);

    let count = AuditEventRepo
        .count(&mut conn, Some(realm.id), None, None, None, None)
        .await
        .expect("count failed");
    assert_eq!(count, 5);
}

// ===================================================================
// Cross-repo operations on a single connection
// (Most realistic scenario — mirrors production request handling)
// ===================================================================

#[tokio::test]
async fn test_cross_repo_single_connection() {
    // Simulates a production request: create realm, user, client, session
    // all on the same connection, with interleaved lookups.
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    // 1. Create realm
    let realm = make_realm("cross-repo-realm");
    RealmRepo
        .create(&mut conn, &realm)
        .await
        .expect("realm create");

    // 2. Look up realm (query_one_params after create)
    let found_realm = RealmRepo
        .find_by_name(&mut conn, "cross-repo-realm")
        .await
        .expect("find_by_name failed");
    assert!(found_realm.is_some());

    // 3. Create user
    let user = make_user(realm.id, "cross@example.com");
    UserRepo
        .create(&mut conn, &user)
        .await
        .expect("user create");

    // 4. Look up user (query_one_params after another query_one_params)
    let found_user = UserRepo
        .find_by_email(&mut conn, realm.id, "cross@example.com")
        .await
        .expect("find_by_email failed");
    assert!(found_user.is_some());

    // 5. Create client
    let client = make_client(realm.id, "cross-client");
    ClientRepo
        .create(&mut conn, &client)
        .await
        .expect("client create");

    // 6. Look up client (query_one_params after multiple prior queries)
    let found_client = ClientRepo
        .find_by_client_id(&mut conn, "cross-client")
        .await
        .expect("find_by_client_id failed");
    assert!(found_client.is_some());

    // 7. Create session
    let session = make_session(user.id, realm.id, client.id, "cross_hash");
    SessionRepo
        .create(&mut conn, &session)
        .await
        .expect("session create");

    // 8. Find session by access token hash
    let found_session = SessionRepo
        .find_by_access_token_hash(&mut conn, "cross_hash")
        .await
        .expect("find_by_access_token_hash failed");
    assert!(found_session.is_some());

    // 9. Create audit event
    let event = make_audit_event(realm.id, "user.login", Some(user.id));
    AuditEventRepo
        .create(&mut conn, &event)
        .await
        .expect("audit event create");

    // 10. Count recent failures (query_one_params with subquery)
    let failures = AuditEventRepo
        .count_recent_failures(&mut conn, "cross@example.com", realm.id)
        .await
        .expect("count_recent_failures failed");
    assert_eq!(failures, 0);
}

// ===================================================================
// Concurrent connection tests
// ===================================================================

#[tokio::test]
async fn test_concurrent_connections_isolation() {
    // Two separate connections should see committed data from each other.
    let mut conn1 = test_conn().await;
    clean_database(&mut conn1).await.unwrap();

    let mut conn2 = test_conn().await;

    let realm = make_realm("concurrent-realm");
    RealmRepo
        .create(&mut conn1, &realm)
        .await
        .expect("realm create on conn1");

    // conn2 should see the realm (auto-commit)
    let found = RealmRepo
        .find_by_name(&mut conn2, "concurrent-realm")
        .await
        .expect("find_by_name on conn2 failed");
    assert!(found.is_some(), "conn2 should see data committed by conn1");
}
