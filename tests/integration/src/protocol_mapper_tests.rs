use chrono::Utc;
use oidc_core::models::{
    Client, ClientType, ProtocolMapper, ProtocolMapperType, Realm, Role, Scope, User,
};
use oidc_repository::repositories::{
    client_repo::ClientRepo, protocol_mapper_repo::ProtocolMapperRepo, realm_repo::RealmRepo,
    role_repo::RoleRepo, scope_repo::ScopeRepo, user_repo::UserRepo, user_role_repo::UserRoleRepo,
};
use uuid::Uuid;

use crate::harness::test_conn;

#[tokio::test]
async fn assigned_client_scopes_resolve_defaults_and_protocol_claims() {
    let mut conn = test_conn().await;
    let realm = Realm {
        id: Uuid::new_v4(),
        name: format!("mappers-{}", Uuid::new_v4()),
        display_name: "Mapper tests".into(),
        enabled: true,
        config: serde_json::json!({}),
        deleted_at: None,
    };
    RealmRepo.create(&mut conn, &realm).await.unwrap();
    let client = Client {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        client_id: format!("mapped-app-{}", Uuid::new_v4()),
        client_type: ClientType::Public,
        client_secret_hash: None,
        name: "Mapped app".into(),
        redirect_uris: vec!["https://example.test/callback".into()],
        allowed_scopes: vec!["openid".into()],
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
    let scope = Scope {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        name: "employee".into(),
        description: None,
        enabled: true,
    };
    ScopeRepo.create(&mut conn, &scope).await.unwrap();
    ScopeRepo
        .assign_to_client(&mut conn, client.id, scope.id, "default")
        .await
        .unwrap();

    let department = ProtocolMapper {
        id: Uuid::new_v4(),
        scope_id: scope.id,
        name: "department".into(),
        mapper_type: ProtocolMapperType::UserAttribute,
        claim_name: Some("employee.department".into()),
        source: Some("department".into()),
        claim_value: None,
        multivalued: false,
        add_to_access_token: true,
        add_to_id_token: true,
        add_to_userinfo: true,
    };
    let audience = ProtocolMapper {
        id: Uuid::new_v4(),
        scope_id: scope.id,
        name: "employee-api audience".into(),
        mapper_type: ProtocolMapperType::Audience,
        claim_name: None,
        source: None,
        claim_value: Some(serde_json::json!("employee-api")),
        multivalued: false,
        add_to_access_token: true,
        add_to_id_token: false,
        add_to_userinfo: false,
    };
    ProtocolMapperRepo
        .create(&mut conn, &department)
        .await
        .unwrap();
    ProtocolMapperRepo
        .create(&mut conn, &audience)
        .await
        .unwrap();

    let user = User {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        email: format!("mapper-{}@example.test", Uuid::new_v4()),
        email_verified: true,
        username: Some("mapped-user".into()),
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
        attributes: serde_json::json!({"department":"engineering"}),
        enabled: true,
        deleted_at: None,
        updated_at: Utc::now(),
    };
    UserRepo.create(&mut conn, &user).await.unwrap();
    let realm_role = Role {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        client_id: None,
        name: "employee".into(),
        description: None,
        permissions: vec![],
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let client_role = Role {
        id: Uuid::new_v4(),
        realm_id: realm.id,
        client_id: Some(client.id),
        name: "operator".into(),
        description: None,
        permissions: vec![],
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    RoleRepo.create(&mut conn, &realm_role).await.unwrap();
    RoleRepo.create(&mut conn, &client_role).await.unwrap();
    UserRoleRepo
        .assign(&mut conn, user.id, realm_role.id)
        .await
        .unwrap();
    UserRoleRepo
        .assign(&mut conn, user.id, client_role.id)
        .await
        .unwrap();
    for mapper in [
        ProtocolMapper {
            id: Uuid::new_v4(),
            scope_id: scope.id,
            name: "realm roles".into(),
            mapper_type: ProtocolMapperType::RealmRoles,
            claim_name: Some("entitlements.realm".into()),
            source: None,
            claim_value: None,
            multivalued: true,
            add_to_access_token: true,
            add_to_id_token: true,
            add_to_userinfo: true,
        },
        ProtocolMapper {
            id: Uuid::new_v4(),
            scope_id: scope.id,
            name: "application roles".into(),
            mapper_type: ProtocolMapperType::ClientRoles,
            claim_name: Some("entitlements.application".into()),
            source: Some(client.client_id.clone()),
            claim_value: None,
            multivalued: true,
            add_to_access_token: true,
            add_to_id_token: true,
            add_to_userinfo: true,
        },
    ] {
        ProtocolMapperRepo.create(&mut conn, &mapper).await.unwrap();
    }

    let scopes = ScopeRepo
        .resolve_names_for_client(
            &mut conn,
            client.id,
            &["openid".into()],
            &client.allowed_scopes,
        )
        .await
        .unwrap();
    assert_eq!(scopes, vec!["openid", "employee"]);
    let mapped = oidc_oidc::protocol_mappers::resolve_mapped_claims(
        &mut conn,
        client.id,
        Some(&user),
        &scopes,
    )
    .await
    .unwrap();
    assert_eq!(mapped.access_token["employee"]["department"], "engineering");
    assert_eq!(mapped.id_token["employee"]["department"], "engineering");
    assert_eq!(mapped.userinfo["employee"]["department"], "engineering");
    assert_eq!(mapped.access_audiences, vec!["employee-api"]);
    assert!(mapped.id_audiences.is_empty());
    assert_eq!(
        mapped.access_token["entitlements"]["realm"],
        serde_json::json!(["employee"])
    );
    assert_eq!(
        mapped.access_token["entitlements"]["application"],
        serde_json::json!(["operator"])
    );

    assert!(
        ScopeRepo
            .resolve_names_for_client(
                &mut conn,
                client.id,
                &["unknown".into()],
                &client.allowed_scopes
            )
            .await
            .is_err()
    );
}

#[test]
fn mapper_validation_rejects_protected_claims_and_missing_sources() {
    let mapper = ProtocolMapper {
        id: Uuid::new_v4(),
        scope_id: Uuid::new_v4(),
        name: "unsafe".into(),
        mapper_type: ProtocolMapperType::UserAttribute,
        claim_name: Some("sub".into()),
        source: Some("employee_id".into()),
        claim_value: None,
        multivalued: false,
        add_to_access_token: true,
        add_to_id_token: true,
        add_to_userinfo: true,
    };
    assert!(mapper.validate().is_err());
}
