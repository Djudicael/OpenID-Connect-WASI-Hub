use chrono::Utc;
use oidc_core::models::{Client, ClientType, Realm, Role, User};
use oidc_repository::repositories::{
    client_repo::ClientRepo, realm_repo::RealmRepo, role_composite_repo::RoleCompositeRepo,
    role_repo::RoleRepo, user_repo::UserRepo, user_role_repo::UserRoleRepo,
};
use uuid::Uuid;

use crate::harness::test_conn;

fn role(realm_id: Uuid, client_id: Option<Uuid>, name: &str, permissions: &[&str]) -> Role {
    Role {
        id: Uuid::new_v4(),
        realm_id,
        client_id,
        name: name.into(),
        description: None,
        permissions: permissions.iter().map(|value| (*value).into()).collect(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[tokio::test]
async fn client_and_nested_composite_roles_expand_effectively() {
    let mut conn = test_conn().await;
    let realm = Realm {
        id: Uuid::new_v4(),
        name: format!("client-roles-{}", Uuid::new_v4()),
        display_name: "Client roles".into(),
        enabled: true,
        config: serde_json::json!({}),
        deleted_at: None,
    };
    RealmRepo.create(&mut conn, &realm).await.unwrap();
    let client = Client {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        client_id: format!("portal-{}", Uuid::new_v4()),
        client_type: ClientType::Public,
        client_secret_hash: None,
        name: "Portal".into(),
        redirect_uris: vec!["https://example.test/callback".into()],
        allowed_scopes: vec!["openid".into(), "roles".into()],
        allowed_grant_types: vec!["authorization_code".into()],
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
        response_modes: vec!["query".into()],
        id_token_encrypted_response_alg: None,
        id_token_encrypted_response_enc: None,
        id_token_encryption_key_encrypted: None,
        id_token_encryption_key_pem: None,
        request_object_encryption_alg: None,
        request_object_encryption_enc: None,
        request_object_encryption_key_encrypted: None,
        request_object_encryption_key_pem: None,
    };
    ClientRepo.create(&mut conn, &client).await.unwrap();
    let user = User {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        email: format!("roles-{}@example.test", Uuid::new_v4()),
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
        street_address: None,
        locality: None,
        region: None,
        postal_code: None,
        country: None,
        locale: "en".into(),
        attributes: serde_json::json!({}),
        enabled: true,
        deleted_at: None,
        updated_at: Utc::now(),
    };
    UserRepo.create(&mut conn, &user).await.unwrap();

    let employee = role(realm.id, None, "employee", &["profile:read"]);
    let operator = role(realm.id, Some(client.id), "operator", &["jobs:run"]);
    let auditor = role(realm.id, Some(client.id), "auditor", &["audit:read"]);
    for item in [&employee, &operator, &auditor] {
        RoleRepo.create(&mut conn, item).await.unwrap();
    }
    RoleCompositeRepo
        .add(&mut conn, employee.id, operator.id)
        .await
        .unwrap();
    RoleCompositeRepo
        .add(&mut conn, operator.id, auditor.id)
        .await
        .unwrap();
    UserRoleRepo
        .assign(&mut conn, user.id, employee.id)
        .await
        .unwrap();

    let effective = RoleRepo
        .find_effective_by_user_id(&mut conn, user.id)
        .await
        .unwrap();
    assert_eq!(effective.len(), 3);
    let permissions = UserRoleRepo
        .find_effective_permissions(&mut conn, user.id)
        .await
        .unwrap();
    assert!(permissions.contains(&"jobs:run".to_string()));
    assert!(permissions.contains(&"audit:read".to_string()));
    let names = RoleRepo
        .find_effective_names_by_user_id(&mut conn, user.id)
        .await
        .unwrap();
    assert!(names.contains(&("employee".into(), None)));
    assert!(names.contains(&("operator".into(), Some(client.client_id.clone()))));
    assert!(
        RoleCompositeRepo
            .add(&mut conn, auditor.id, employee.id)
            .await
            .is_err()
    );
}
