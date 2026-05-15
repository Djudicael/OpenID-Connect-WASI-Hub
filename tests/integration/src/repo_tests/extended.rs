//! Extended repository integration tests for repositories not covered in lifecycle.rs.
//!
//! Covers: Role, Group, UserRole, UserGroup, GroupRole, IdentityProvider,
//! Scope, PAR, DeviceCode, PasswordResetToken, EmailVerificationToken,
//! AccountRecoveryToken.

use chrono::Utc;
use oidc_core::models::account_recovery_token::AccountRecoveryToken;
use oidc_core::models::email_verification_token::EmailVerificationToken;
use oidc_core::models::password_reset_token::PasswordResetToken;
use oidc_core::models::{
    Client, ClientType, DeviceCode, Group, IdentityProvider, IdentityProviderType,
    PushedAuthorizationRequest, Role, Scope, User,
};
use oidc_repository::connection::Connection;
use oidc_repository::repositories::account_recovery_token_repo::AccountRecoveryTokenRepo;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::device_code_repo::DeviceCodeRepo;
use oidc_repository::repositories::email_verification_token_repo::EmailVerificationTokenRepo;
use oidc_repository::repositories::group_repo::GroupRepo;
use oidc_repository::repositories::group_role_repo::GroupRoleRepo;
use oidc_repository::repositories::identity_provider_repo::IdentityProviderRepo;
use oidc_repository::repositories::par_repo::ParRepo;
use oidc_repository::repositories::password_reset_token_repo::PasswordResetTokenRepo;
use oidc_repository::repositories::realm_repo::RealmRepo;
use oidc_repository::repositories::role_repo::RoleRepo;
use oidc_repository::repositories::scope_repo::ScopeRepo;
use oidc_repository::repositories::user_group_repo::UserGroupRepo;
use oidc_repository::repositories::user_repo::UserRepo;
use oidc_repository::repositories::user_role_repo::UserRoleRepo;
use std::net::IpAddr;
use std::str::FromStr;
use uuid::Uuid;

use crate::harness::test_conn;

// ===================================================================
// Helpers
// ===================================================================

fn make_realm(name: &str) -> oidc_core::models::Realm {
    oidc_core::models::Realm {
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
        street_address: None,
        locality: None,
        region: None,
        postal_code: None,
        country: None,
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
        redirect_uris: vec!["https://example.com/callback".to_string()],
        allowed_scopes: vec!["openid".to_string()],
        allowed_grant_types: vec!["authorization_code".to_string()],
        pkce_required: true,
        enabled: true,
        deleted_at: None,
        token_endpoint_auth_method: "none".into(),
        jwks_uri: None,
        jwks: None,
        request_uris: vec![],
        client_secret_encrypted: None,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: false,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        post_logout_redirect_uris: vec![],
        subject_type: "public".into(),
        sector_identifier_uri: None,
        response_modes: vec!["query".to_string(), "fragment".to_string()],
        id_token_encrypted_response_alg: None,
        id_token_encrypted_response_enc: None,
        id_token_encryption_key_encrypted: None,
        id_token_encryption_key_pem: None,
        request_object_encryption_alg: None,
        request_object_encryption_enc: None,
        request_object_encryption_key_encrypted: None,
        request_object_encryption_key_pem: None,
    }
}

async fn seed_realm_user_client(conn: &mut Connection) -> (oidc_core::models::Realm, User, Client) {
    let realm = make_realm("ext-realm");
    RealmRepo.create(conn, &realm).await.expect("realm create");
    let user = make_user(realm.id, "ext@example.com");
    UserRepo.create(conn, &user).await.expect("user create");
    let client = make_client(realm.id, "ext-client");
    ClientRepo.create(conn, &client).await.expect("client create");
    (realm, user, client)
}

// ===================================================================
// Role CRUD
// ===================================================================

#[tokio::test]
async fn test_role_crud() {
    let mut conn = test_conn().await;
    let realm = make_realm("role-crud-realm");
    RealmRepo.create(&mut conn, &realm).await.expect("realm create");

    let role = Role {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        name: "admin".to_string(),
        description: Some("Administrator role".to_string()),
        permissions: vec!["users:read".to_string(), "users:write".to_string()],
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    RoleRepo.create(&mut conn, &role).await.expect("role create");

    let found = RoleRepo.find_by_id(&mut conn, role.id).await.unwrap().unwrap();
    assert_eq!(found.name, "admin");
    assert_eq!(found.permissions.len(), 2);

    let found = RoleRepo.find_by_name(&mut conn, realm.id, "admin").await.unwrap().unwrap();
    assert_eq!(found.description, Some("Administrator role".to_string()));

    // Update
    let mut updated = found;
    updated.name = "super-admin".to_string();
    RoleRepo.update(&mut conn, &updated).await.expect("role update");
    let found = RoleRepo.find_by_id(&mut conn, role.id).await.unwrap().unwrap();
    assert_eq!(found.name, "super-admin");

    // Delete (soft)
    RoleRepo.delete(&mut conn, role.id).await.expect("role delete");
    assert!(RoleRepo.find_by_id(&mut conn, role.id).await.unwrap().is_none());
}

#[tokio::test]
async fn test_role_list_and_count_with_realm_filter() {
    let mut conn = test_conn().await;
    let realm = make_realm("role-list-realm");
    RealmRepo.create(&mut conn, &realm).await.expect("realm create");

    for i in 0..5 {
        let role = Role {
            id: Uuid::new_v4(),
            realm_id: realm.id,
            name: format!("role-{}", i),
            description: None,
            permissions: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        RoleRepo.create(&mut conn, &role).await.expect("role create");
    }

    let count = RoleRepo.count(&mut conn, Some(realm.id)).await.unwrap();
    assert_eq!(count, 5);

    let list = RoleRepo.list(&mut conn, Some(realm.id), None, 3, 0).await.unwrap();
    assert_eq!(list.len(), 3);

    let list = RoleRepo.list(&mut conn, Some(realm.id), Some("role-2"), 10, 0).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "role-2");

    // Without realm filter
    let all_count = RoleRepo.count(&mut conn, None).await.unwrap();
    assert!(all_count >= 5);
}

// ===================================================================
// Group CRUD
// ===================================================================

#[tokio::test]
async fn test_group_crud() {
    let mut conn = test_conn().await;
    let realm = make_realm("group-crud-realm");
    RealmRepo.create(&mut conn, &realm).await.expect("realm create");

    let group = Group {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        name: "developers".to_string(),
        description: Some("Dev team".to_string()),
        parent_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    GroupRepo.create(&mut conn, &group).await.expect("group create");

    let found = GroupRepo.find_by_id(&mut conn, group.id).await.unwrap().unwrap();
    assert_eq!(found.name, "developers");

    let found = GroupRepo.find_by_name(&mut conn, realm.id, "developers").await.unwrap().unwrap();
    assert_eq!(found.description, Some("Dev team".to_string()));

    // Update
    let mut updated = found;
    updated.name = "senior-devs".to_string();
    GroupRepo.update(&mut conn, &updated).await.expect("group update");
    let found = GroupRepo.find_by_id(&mut conn, group.id).await.unwrap().unwrap();
    assert_eq!(found.name, "senior-devs");

    // Delete
    GroupRepo.delete(&mut conn, group.id).await.expect("group delete");
    assert!(GroupRepo.find_by_id(&mut conn, group.id).await.unwrap().is_none());
}

#[tokio::test]
async fn test_group_list_and_count() {
    let mut conn = test_conn().await;
    let realm = make_realm("group-list-realm");
    RealmRepo.create(&mut conn, &realm).await.expect("realm create");

    for i in 0..4 {
        let group = Group {
            id: Uuid::new_v4(),
            realm_id: realm.id,
            name: format!("group-{}", i),
            description: None,
            parent_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        GroupRepo.create(&mut conn, &group).await.expect("group create");
    }

    let count = GroupRepo.count(&mut conn, Some(realm.id)).await.unwrap();
    assert_eq!(count, 4);

    let list = GroupRepo.list(&mut conn, Some(realm.id), None, 2, 0).await.unwrap();
    assert_eq!(list.len(), 2);

    // Without realm filter
    let all_count = GroupRepo.count(&mut conn, None).await.unwrap();
    assert!(all_count >= 4);
}

#[tokio::test]
async fn test_group_with_parent() {
    let mut conn = test_conn().await;
    let realm = make_realm("group-parent-realm");
    RealmRepo.create(&mut conn, &realm).await.expect("realm create");

    let parent = Group {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        name: "engineering".to_string(),
        description: None,
        parent_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    GroupRepo.create(&mut conn, &parent).await.expect("parent create");

    let child = Group {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        name: "backend".to_string(),
        description: None,
        parent_id: Some(parent.id),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    GroupRepo.create(&mut conn, &child).await.expect("child create");

    let found = GroupRepo.find_by_id(&mut conn, child.id).await.unwrap().unwrap();
    assert_eq!(found.parent_id, Some(parent.id));
}

// ===================================================================
// User-Role assignments
// ===================================================================

#[tokio::test]
async fn test_user_role_assign_unassign() {
    let mut conn = test_conn().await;
    let (realm, user, _) = seed_realm_user_client(&mut conn).await;

    let role = Role {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        name: "test-role".to_string(),
        description: None,
        permissions: vec![],
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    RoleRepo.create(&mut conn, &role).await.expect("role create");

    // Assign
    UserRoleRepo.assign(&mut conn, user.id, role.id).await.expect("assign");

    // Find roles by user
    let roles = UserRoleRepo.find_roles_by_user(&mut conn, user.id).await.unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].name, "test-role");

    // Find users by role
    let users = UserRoleRepo.find_users_by_role(&mut conn, role.id).await.unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].email, "ext@example.com");

    // Unassign
    UserRoleRepo.unassign(&mut conn, user.id, role.id).await.expect("unassign");

    let roles = UserRoleRepo.find_roles_by_user(&mut conn, user.id).await.unwrap();
    assert!(roles.is_empty());
}

#[tokio::test]
async fn test_user_role_multiple_roles() {
    let mut conn = test_conn().await;
    let (realm, user, _) = seed_realm_user_client(&mut conn).await;

    for i in 0..3 {
        let role = Role {
            id: Uuid::new_v4(),
            realm_id: realm.id,
            name: format!("multi-role-{}", i),
            description: None,
            permissions: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        RoleRepo.create(&mut conn, &role).await.expect("role create");
        UserRoleRepo.assign(&mut conn, user.id, role.id).await.expect("assign");
    }

    let roles = UserRoleRepo.find_roles_by_user(&mut conn, user.id).await.unwrap();
    assert_eq!(roles.len(), 3);
}

// ===================================================================
// User-Group assignments
// ===================================================================

#[tokio::test]
async fn test_user_group_assign_unassign() {
    let mut conn = test_conn().await;
    let (realm, user, _) = seed_realm_user_client(&mut conn).await;

    let group = Group {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        name: "test-group".to_string(),
        description: None,
        parent_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    GroupRepo.create(&mut conn, &group).await.expect("group create");

    // Assign
    UserGroupRepo.assign(&mut conn, user.id, group.id).await.expect("assign");

    // Find groups by user
    let groups = UserGroupRepo.find_groups_by_user(&mut conn, user.id).await.unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].name, "test-group");

    // Find users by group
    let users = UserGroupRepo.find_users_by_group(&mut conn, group.id).await.unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].email, "ext@example.com");

    // Unassign
    UserGroupRepo.unassign(&mut conn, user.id, group.id).await.expect("unassign");

    let groups = UserGroupRepo.find_groups_by_user(&mut conn, user.id).await.unwrap();
    assert!(groups.is_empty());
}

// ===================================================================
// Group-Role assignments
// ===================================================================

#[tokio::test]
async fn test_group_role_assign_unassign() {
    let mut conn = test_conn().await;
    let realm = make_realm("group-role-realm");
    RealmRepo.create(&mut conn, &realm).await.expect("realm create");

    let group = Group {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        name: "role-group".to_string(),
        description: None,
        parent_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    GroupRepo.create(&mut conn, &group).await.expect("group create");

    let role = Role {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        name: "group-role".to_string(),
        description: None,
        permissions: vec!["read".to_string()],
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    RoleRepo.create(&mut conn, &role).await.expect("role create");

    // Assign
    GroupRoleRepo.assign(&mut conn, group.id, role.id).await.expect("assign");

    // Find roles by group
    let roles = GroupRoleRepo.find_roles_by_group(&mut conn, group.id).await.unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].name, "group-role");

    // Unassign
    GroupRoleRepo.unassign(&mut conn, group.id, role.id).await.expect("unassign");

    let roles = GroupRoleRepo.find_roles_by_group(&mut conn, group.id).await.unwrap();
    assert!(roles.is_empty());
}

// ===================================================================
// Identity Provider CRUD
// ===================================================================

#[tokio::test]
async fn test_identity_provider_crud() {
    let mut conn = test_conn().await;
    let realm = make_realm("idp-crud-realm");
    RealmRepo.create(&mut conn, &realm).await.expect("realm create");

    let idp = IdentityProvider {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        alias: "google-test".to_string(),
        display_name: "Google Test".to_string(),
        provider_type: IdentityProviderType::Google,
        enabled: true,
        issuer: "https://accounts.google.com".to_string(),
        authorization_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
        token_url: "https://oauth2.googleapis.com/token".to_string(),
        userinfo_url: "https://openidconnect.googleapis.com/v1/userinfo".to_string(),
        jwks_url: "https://www.googleapis.com/oauth2/v3/certs".to_string(),
        client_id: "test-client-id".to_string(),
        client_secret: "test-client-secret".to_string(),
        scopes: vec!["openid".to_string(), "email".to_string()],
        auto_create_users: true,
        link_users_by_email: false,
        deleted_at: None,
    };
    IdentityProviderRepo.create(&mut conn, &idp).await.expect("idp create");

    // Find by id
    let found = IdentityProviderRepo.find_by_id(&mut conn, idp.id).await.unwrap().unwrap();
    assert_eq!(found.alias, "google-test");
    assert_eq!(found.provider_type, IdentityProviderType::Google);

    // Find by alias
    let found = IdentityProviderRepo.find_by_alias(&mut conn, realm.id, "google-test").await.unwrap().unwrap();
    assert_eq!(found.display_name, "Google Test");

    // Find by realm (enabled only)
    let idps = IdentityProviderRepo.find_by_realm(&mut conn, realm.id).await.unwrap();
    assert_eq!(idps.len(), 1);

    // Update
    let mut updated = found;
    updated.display_name = "Google Updated".to_string();
    updated.enabled = false;
    IdentityProviderRepo.update(&mut conn, &updated).await.expect("idp update");
    let found = IdentityProviderRepo.find_by_id(&mut conn, idp.id).await.unwrap().unwrap();
    assert_eq!(found.display_name, "Google Updated");

    // Delete (soft)
    IdentityProviderRepo.delete(&mut conn, idp.id).await.expect("idp delete");
    assert!(IdentityProviderRepo.find_by_id(&mut conn, idp.id).await.unwrap().is_none());

    // Deleted IDP should not appear in realm list
    let idps = IdentityProviderRepo.find_by_realm(&mut conn, realm.id).await.unwrap();
    assert!(idps.is_empty());
}

#[tokio::test]
async fn test_identity_provider_oidc_type() {
    let mut conn = test_conn().await;
    let realm = make_realm("idp-oidc-realm");
    RealmRepo.create(&mut conn, &realm).await.expect("realm create");

    let idp = IdentityProvider {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        alias: "custom-oidc".to_string(),
        display_name: "Custom OIDC".to_string(),
        provider_type: IdentityProviderType::Oidc,
        enabled: true,
        issuer: "https://custom.example.com".to_string(),
        authorization_url: "https://custom.example.com/authorize".to_string(),
        token_url: "https://custom.example.com/token".to_string(),
        userinfo_url: "https://custom.example.com/userinfo".to_string(),
        jwks_url: "https://custom.example.com/.well-known/jwks.json".to_string(),
        client_id: "oidc-client".to_string(),
        client_secret: "oidc-secret".to_string(),
        scopes: vec!["openid".to_string(), "profile".to_string()],
        auto_create_users: false,
        link_users_by_email: true,
        deleted_at: None,
    };
    IdentityProviderRepo.create(&mut conn, &idp).await.expect("idp create");

    let found = IdentityProviderRepo.find_by_id(&mut conn, idp.id).await.unwrap().unwrap();
    assert_eq!(found.provider_type, IdentityProviderType::Oidc);
    assert!(found.link_users_by_email);
    assert!(!found.auto_create_users);
}

// ===================================================================
// Scope CRUD
// ===================================================================

#[tokio::test]
async fn test_scope_crud() {
    let mut conn = test_conn().await;
    let realm = make_realm("scope-crud-realm");
    RealmRepo.create(&mut conn, &realm).await.expect("realm create");

    let scope = Scope {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        name: "custom:read".to_string(),
        description: Some("Read custom resources".to_string()),
        enabled: true,
    };
    ScopeRepo.create(&mut conn, &scope).await.expect("scope create");

    let found = ScopeRepo.find_by_id(&mut conn, scope.id).await.unwrap().unwrap();
    assert_eq!(found.name, "custom:read");

    let found = ScopeRepo.find_by_name(&mut conn, realm.id, "custom:read").await.unwrap().unwrap();
    assert_eq!(found.description, Some("Read custom resources".to_string()));

    // Update
    let mut updated = found;
    updated.name = "custom:write".to_string();
    updated.enabled = false;
    ScopeRepo.update(&mut conn, &updated).await.expect("scope update");
    let found = ScopeRepo.find_by_id(&mut conn, scope.id).await.unwrap().unwrap();
    assert_eq!(found.name, "custom:write");
    assert!(!found.enabled);

    // Delete
    ScopeRepo.delete(&mut conn, scope.id).await.expect("scope delete");
    assert!(ScopeRepo.find_by_id(&mut conn, scope.id).await.unwrap().is_none());
}

#[tokio::test]
async fn test_scope_list_by_realm() {
    let mut conn = test_conn().await;
    let realm = make_realm("scope-list-realm");
    RealmRepo.create(&mut conn, &realm).await.expect("realm create");

    for name in &["openid", "profile", "email", "custom"] {
        let scope = Scope {
            id: Uuid::new_v4(),
            realm_id: realm.id,
            name: name.to_string(),
            description: None,
            enabled: true,
        };
        ScopeRepo.create(&mut conn, &scope).await.expect("scope create");
    }

    let scopes = ScopeRepo.list_by_realm(&mut conn, realm.id).await.unwrap();
    assert_eq!(scopes.len(), 4);
    // Should be ordered alphabetically
    assert_eq!(scopes[0].name, "custom");
    assert_eq!(scopes[1].name, "email");
}

// ===================================================================
// PAR (Pushed Authorization Request)
// ===================================================================

#[tokio::test]
async fn test_par_lifecycle() {
    let mut conn = test_conn().await;
    let (_, _, client) = seed_realm_user_client(&mut conn).await;

    let par = PushedAuthorizationRequest {
        id: Uuid::new_v4(),
        client_id: client.id,
        realm_id: client.realm_id,
        request_uri_token: "urn:ietf:params:oauth:request_uri:test123".to_string(),
        request_params: serde_json::json!({
            "response_type": "code",
            "scope": "openid profile",
            "redirect_uri": "https://example.com/callback"
        }),
        expires_at: Utc::now() + chrono::Duration::minutes(10),
        used: false,
        created_at: Utc::now(),
    };
    ParRepo.create(&mut conn, &par).await.expect("par create");

    // Find by token
    let found = ParRepo.find_by_request_uri_token(&mut conn, "urn:ietf:params:oauth:request_uri:test123").await.unwrap().unwrap();
    assert!(!found.used);

    // Mark used
    ParRepo.mark_used(&mut conn, par.id).await.expect("mark used");

    // Used PAR should not be found
    let found = ParRepo.find_by_request_uri_token(&mut conn, "urn:ietf:params:oauth:request_uri:test123").await.unwrap();
    assert!(found.is_none(), "used PAR should not be found");
}

#[tokio::test]
async fn test_par_cleanup_expired() {
    let mut conn = test_conn().await;
    let (_, _, client) = seed_realm_user_client(&mut conn).await;

    // Create expired PAR
    let expired_par = PushedAuthorizationRequest {
        id: Uuid::new_v4(),
        client_id: client.id,
        realm_id: client.realm_id,
        request_uri_token: "urn:expired".to_string(),
        request_params: serde_json::json!({}),
        expires_at: Utc::now() - chrono::Duration::hours(1),
        used: false,
        created_at: Utc::now() - chrono::Duration::hours(2),
    };
    ParRepo.create(&mut conn, &expired_par).await.expect("par create");

    // Create valid PAR
    let valid_par = PushedAuthorizationRequest {
        id: Uuid::new_v4(),
        client_id: client.id,
        realm_id: client.realm_id,
        request_uri_token: "urn:valid".to_string(),
        request_params: serde_json::json!({}),
        expires_at: Utc::now() + chrono::Duration::hours(1),
        used: false,
        created_at: Utc::now(),
    };
    ParRepo.create(&mut conn, &valid_par).await.expect("par create");

    let deleted = ParRepo.cleanup_expired(&mut conn).await.unwrap();
    assert_eq!(deleted, 1);

    // Valid PAR should still be findable
    let found = ParRepo.find_by_request_uri_token(&mut conn, "urn:valid").await.unwrap();
    assert!(found.is_some());
}

// ===================================================================
// Device Code
// ===================================================================

#[tokio::test]
async fn test_device_code_lifecycle() {
    let mut conn = test_conn().await;
    let (_, user, client) = seed_realm_user_client(&mut conn).await;

    let device_code = DeviceCode {
        id: Uuid::new_v4(),
        client_id: client.id,
        realm_id: client.realm_id,
        device_code: "device_hash_test".to_string(),
        user_code: "ABCD-EFGH".to_string(),
        verification_uri: "https://example.com/device".to_string(),
        verification_uri_complete: Some("https://example.com/device?user_code=ABCD-EFGH".to_string()),
        expires_at: Utc::now() + chrono::Duration::minutes(15),
        interval: 5,
        used: false,
        authorized: false,
        user_id: None,
        scope: vec!["openid".to_string()],
        created_at: Utc::now(),
    };
    DeviceCodeRepo.create(&mut conn, &device_code).await.expect("device code create");

    // Find by device code hash
    let found = DeviceCodeRepo.find_by_device_code(&mut conn, "device_hash_test").await.unwrap().unwrap();
    assert!(!found.authorized);

    // Find by user code
    let found = DeviceCodeRepo.find_by_user_code(&mut conn, "ABCD-EFGH").await.unwrap().unwrap();
    assert_eq!(found.user_code, "ABCD-EFGH");

    // Mark authorized
    DeviceCodeRepo.mark_authorized(&mut conn, device_code.id, user.id).await.expect("mark authorized");
    let found = DeviceCodeRepo.find_by_device_code(&mut conn, "device_hash_test").await.unwrap().unwrap();
    assert!(found.authorized);
    assert_eq!(found.user_id, Some(user.id));

    // Mark used
    DeviceCodeRepo.mark_used(&mut conn, device_code.id).await.expect("mark used");
    let found = DeviceCodeRepo.find_by_device_code(&mut conn, "device_hash_test").await.unwrap();
    assert!(found.is_none(), "used device code should not be found");
}

#[tokio::test]
async fn test_device_code_cleanup_expired() {
    let mut conn = test_conn().await;
    let (_, _, client) = seed_realm_user_client(&mut conn).await;

    // Create expired device code
    let expired = DeviceCode {
        id: Uuid::new_v4(),
        client_id: client.id,
        realm_id: client.realm_id,
        device_code: "expired_hash".to_string(),
        user_code: "EXPI-RED".to_string(),
        verification_uri: "https://example.com/device".to_string(),
        verification_uri_complete: None,
        expires_at: Utc::now() - chrono::Duration::hours(1),
        interval: 5,
        used: false,
        authorized: false,
        user_id: None,
        scope: vec![],
        created_at: Utc::now() - chrono::Duration::hours(2),
    };
    DeviceCodeRepo.create(&mut conn, &expired).await.expect("device code create");

    // Create valid device code
    let valid = DeviceCode {
        id: Uuid::new_v4(),
        client_id: client.id,
        realm_id: client.realm_id,
        device_code: "valid_hash".to_string(),
        user_code: "VALID-12".to_string(),
        verification_uri: "https://example.com/device".to_string(),
        verification_uri_complete: None,
        expires_at: Utc::now() + chrono::Duration::hours(1),
        interval: 5,
        used: false,
        authorized: false,
        user_id: None,
        scope: vec![],
        created_at: Utc::now(),
    };
    DeviceCodeRepo.create(&mut conn, &valid).await.expect("device code create");

    let deleted = DeviceCodeRepo.cleanup_expired(&mut conn).await.unwrap();
    assert_eq!(deleted, 1);

    let found = DeviceCodeRepo.find_by_device_code(&mut conn, "valid_hash").await.unwrap();
    assert!(found.is_some());
}

// ===================================================================
// Password Reset Token
// ===================================================================

#[tokio::test]
async fn test_password_reset_token_lifecycle() {
    let mut conn = test_conn().await;
    let (_, user, _) = seed_realm_user_client(&mut conn).await;

    let token = PasswordResetToken {
        id: Uuid::new_v4(),
        user_id: user.id,
        realm_id: user.realm_id,
        token_hash: "reset_hash_test".to_string(),
        used: false,
        expires_at: Utc::now() + chrono::Duration::hours(1),
        created_at: Utc::now(),
    };
    PasswordResetTokenRepo.create(&mut conn, &token).await.expect("token create");

    // Find by hash
    let found = PasswordResetTokenRepo.find_by_token_hash(&mut conn, "reset_hash_test").await.unwrap().unwrap();
    assert!(!found.used);
    assert_eq!(found.user_id, user.id);

    // Mark used
    PasswordResetTokenRepo.mark_used(&mut conn, token.id).await.expect("mark used");
    let found = PasswordResetTokenRepo.find_by_token_hash(&mut conn, "reset_hash_test").await.unwrap();
    assert!(found.is_none(), "used token should not be found");
}

#[tokio::test]
async fn test_password_reset_token_cleanup_expired() {
    let mut conn = test_conn().await;
    let (_, user, _) = seed_realm_user_client(&mut conn).await;

    // Create expired token
    let expired = PasswordResetToken {
        id: Uuid::new_v4(),
        user_id: user.id,
        realm_id: user.realm_id,
        token_hash: "expired_reset_hash".to_string(),
        used: false,
        expires_at: Utc::now() - chrono::Duration::hours(1),
        created_at: Utc::now() - chrono::Duration::hours(2),
    };
    PasswordResetTokenRepo.create(&mut conn, &expired).await.expect("token create");

    // Create valid token
    let valid = PasswordResetToken {
        id: Uuid::new_v4(),
        user_id: user.id,
        realm_id: user.realm_id,
        token_hash: "valid_reset_hash".to_string(),
        used: false,
        expires_at: Utc::now() + chrono::Duration::hours(1),
        created_at: Utc::now(),
    };
    PasswordResetTokenRepo.create(&mut conn, &valid).await.expect("token create");

    let deleted = PasswordResetTokenRepo.cleanup_expired(&mut conn).await.unwrap();
    assert_eq!(deleted, 1);

    let found = PasswordResetTokenRepo.find_by_token_hash(&mut conn, "valid_reset_hash").await.unwrap();
    assert!(found.is_some());
}

// ===================================================================
// Email Verification Token
// ===================================================================

#[tokio::test]
async fn test_email_verification_token_lifecycle() {
    let mut conn = test_conn().await;
    let (_, user, _) = seed_realm_user_client(&mut conn).await;

    let token = EmailVerificationToken {
        id: Uuid::new_v4(),
        user_id: user.id,
        realm_id: user.realm_id,
        token_hash: "email_verify_hash".to_string(),
        used: false,
        expires_at: Utc::now() + chrono::Duration::hours(24),
        created_at: Utc::now(),
    };
    EmailVerificationTokenRepo.create(&mut conn, &token).await.expect("token create");

    // Find by hash
    let found = EmailVerificationTokenRepo.find_by_token_hash(&mut conn, "email_verify_hash").await.unwrap().unwrap();
    assert!(!found.used);
    assert_eq!(found.user_id, user.id);

    // Mark used
    EmailVerificationTokenRepo.mark_used(&mut conn, token.id).await.expect("mark used");
    let found = EmailVerificationTokenRepo.find_by_token_hash(&mut conn, "email_verify_hash").await.unwrap();
    assert!(found.is_none(), "used token should not be found");
}

#[tokio::test]
async fn test_email_verification_token_cleanup_expired() {
    let mut conn = test_conn().await;
    let (_, user, _) = seed_realm_user_client(&mut conn).await;

    let expired = EmailVerificationToken {
        id: Uuid::new_v4(),
        user_id: user.id,
        realm_id: user.realm_id,
        token_hash: "expired_email_hash".to_string(),
        used: false,
        expires_at: Utc::now() - chrono::Duration::hours(1),
        created_at: Utc::now() - chrono::Duration::hours(25),
    };
    EmailVerificationTokenRepo.create(&mut conn, &expired).await.expect("token create");

    let valid = EmailVerificationToken {
        id: Uuid::new_v4(),
        user_id: user.id,
        realm_id: user.realm_id,
        token_hash: "valid_email_hash".to_string(),
        used: false,
        expires_at: Utc::now() + chrono::Duration::hours(24),
        created_at: Utc::now(),
    };
    EmailVerificationTokenRepo.create(&mut conn, &valid).await.expect("token create");

    let deleted = EmailVerificationTokenRepo.cleanup_expired(&mut conn).await.unwrap();
    assert_eq!(deleted, 1);

    let found = EmailVerificationTokenRepo.find_by_token_hash(&mut conn, "valid_email_hash").await.unwrap();
    assert!(found.is_some());
}

// ===================================================================
// Account Recovery Token
// ===================================================================

#[tokio::test]
async fn test_account_recovery_token_lifecycle() {
    let mut conn = test_conn().await;
    let (_, user, _) = seed_realm_user_client(&mut conn).await;
    let admin_id = Uuid::new_v4();

    let (token, raw_token) = AccountRecoveryToken::new(
        user.id,
        user.realm_id,
        admin_id,
        Some(IpAddr::from_str("127.0.0.1").unwrap()),
    ).expect("token creation failed");

    AccountRecoveryTokenRepo.create(&mut conn, &token).await.expect("token create");

    // Find by token hash
    let found = AccountRecoveryTokenRepo.find_by_token_hash(&mut conn, &token.token_hash).await.unwrap().unwrap();
    assert!(!found.used);
    assert_eq!(found.user_id, user.id);
    assert_eq!(found.created_by, admin_id);

    // Verify raw token
    assert!(AccountRecoveryToken::verify(&raw_token, &found.token_hash));

    // Mark used
    AccountRecoveryTokenRepo.mark_used(&mut conn, token.id).await.expect("mark used");
    let found = AccountRecoveryTokenRepo.find_by_token_hash(&mut conn, &token.token_hash).await.unwrap();
    assert!(found.is_none(), "used token should not be found");
}

#[tokio::test]
async fn test_account_recovery_token_cleanup_expired() {
    let mut conn = test_conn().await;
    let (_, user, _) = seed_realm_user_client(&mut conn).await;
    let admin_id = Uuid::new_v4();

    // Create expired token
    let expired = AccountRecoveryToken {
        id: Uuid::new_v4(),
        user_id: user.id,
        realm_id: user.realm_id,
        token_hash: "expired_recovery_hash".to_string(),
        used: false,
        expires_at: Utc::now() - chrono::Duration::hours(1),
        created_at: Utc::now() - chrono::Duration::hours(2),
        created_by: admin_id,
        creator_ip: Some(IpAddr::from_str("127.0.0.1").unwrap()),
    };
    AccountRecoveryTokenRepo.create(&mut conn, &expired).await.expect("token create");

    // Create valid token
    let (valid, _) = AccountRecoveryToken::new(user.id, user.realm_id, admin_id, None).expect("token creation failed");
    AccountRecoveryTokenRepo.create(&mut conn, &valid).await.expect("token create");

    let deleted = AccountRecoveryTokenRepo.cleanup_expired(&mut conn).await.unwrap();
    assert_eq!(deleted, 1);

    let found = AccountRecoveryTokenRepo.find_by_token_hash(&mut conn, &valid.token_hash).await.unwrap();
    assert!(found.is_some());
}
