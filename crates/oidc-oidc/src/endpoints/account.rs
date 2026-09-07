//! Authenticated end-user account management.

use axum::{
    Json,
    http::{HeaderMap, header::AUTHORIZATION},
};
use oidc_core::{
    OidcError,
    models::{ActorType, AuditEvent, User},
    utils::{generate_uuid_v7, is_valid_email, sha2_256_hex},
};
use oidc_repository::repositories::{
    audit_event_repo::AuditEventRepo, client_repo::ClientRepo,
    federated_identity_repo::FederatedIdentityRepo, identity_provider_repo::IdentityProviderRepo,
    realm_repo::RealmRepo, session_repo::SessionRepo, user_consent_repo::UserConsentRepo,
    user_repo::UserRepo, user_role_repo::UserRoleRepo,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::state::OidcState;

struct AccountContext {
    user: User,
    session_id: Uuid,
}

async fn current_account(
    state: &OidcState,
    headers: &HeaderMap,
) -> Result<AccountContext, OidcError> {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| OidcError::AuthenticationFailed("Bearer token required".into()))?
        .to_string();
    state
        .verify_access_token_with_claims_any_issuer(&token)
        .await?;
    let mut conn = state.connect().await?;
    let session = SessionRepo
        .find_by_access_token_hash(&mut conn, &sha2_256_hex(&token))
        .await?
        .ok_or_else(|| OidcError::AuthenticationFailed("Active session required".into()))?;
    let user_id = session
        .user_id
        .ok_or_else(|| OidcError::AuthenticationFailed("User session required".into()))?;
    let user = UserRepo
        .find_by_id(&mut conn, user_id)
        .await?
        .filter(|user| user.enabled)
        .ok_or_else(|| OidcError::AuthenticationFailed("Active user required".into()))?;
    Ok(AccountContext {
        user,
        session_id: session.id,
    })
}

fn optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim().to_string();
        (!value.is_empty()).then_some(value)
    })
}

fn public_profile(user: &User, administration_access: bool) -> Value {
    json!({
        "id": user.id,
        "realm_id": user.realm_id,
        "email": user.email,
        "email_verified": user.email_verified,
        "username": user.username,
        "given_name": user.given_name,
        "family_name": user.family_name,
        "middle_name": user.middle_name,
        "nickname": user.nickname,
        "preferred_username": user.preferred_username,
        "picture": user.picture,
        "website": user.website,
        "gender": user.gender,
        "birthdate": user.birthdate,
        "zoneinfo": user.zoneinfo,
        "phone_number": user.phone_number,
        "street_address": user.street_address,
        "locality": user.locality,
        "region": user.region,
        "postal_code": user.postal_code,
        "country": user.country,
        "locale": user.locale,
        "has_password": user.password_hash.is_some(),
        "administration_access": administration_access,
        "updated_at": user.updated_at,
    })
}

pub async fn profile_handler(
    state: OidcState,
    headers: HeaderMap,
) -> Result<Json<Value>, OidcError> {
    let account = current_account(&state, &headers).await?;
    let mut conn = state.connect().await?;
    let permissions = UserRoleRepo
        .find_effective_permissions(&mut conn, account.user.id)
        .await?;
    Ok(Json(public_profile(&account.user, !permissions.is_empty())))
}

#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub email: Option<String>,
    pub current_password: Option<String>,
    pub username: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub nickname: Option<String>,
    pub preferred_username: Option<String>,
    pub picture: Option<String>,
    pub website: Option<String>,
    pub gender: Option<String>,
    pub birthdate: Option<String>,
    pub zoneinfo: Option<String>,
    pub phone_number: Option<String>,
    pub street_address: Option<String>,
    pub locality: Option<String>,
    pub region: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
    pub locale: Option<String>,
}

pub async fn update_profile_handler(
    state: OidcState,
    headers: HeaderMap,
    req: UpdateProfileRequest,
) -> Result<Json<Value>, OidcError> {
    let account = current_account(&state, &headers).await?;
    let mut user = account.user;
    let mut conn = state.connect().await?;
    if let Some(email) = req.email.map(|email| email.trim().to_lowercase())
        && email != user.email
    {
        if !is_valid_email(&email) {
            return Err(OidcError::InvalidInput(
                "Enter a valid email address".into(),
            ));
        }
        let current = req.current_password.as_deref().unwrap_or_default();
        let valid = user
            .password_hash
            .as_deref()
            .is_some_and(|hash| state.hasher.verify(current, hash).unwrap_or(false));
        if !valid {
            return Err(OidcError::InvalidInput(
                "Current password is required to change email".into(),
            ));
        }
        if UserRepo
            .find_by_email(&mut conn, user.realm_id, &email)
            .await?
            .is_some_and(|existing| existing.id != user.id)
        {
            return Err(OidcError::Conflict(
                "An account already uses this email address".into(),
            ));
        }
        user.email = email;
        user.email_verified = false;
    }
    user.username = optional(req.username);
    user.given_name = optional(req.given_name);
    user.family_name = optional(req.family_name);
    user.middle_name = optional(req.middle_name);
    user.nickname = optional(req.nickname);
    user.preferred_username = optional(req.preferred_username);
    user.picture = optional(req.picture);
    user.website = optional(req.website);
    user.gender = optional(req.gender);
    user.birthdate = optional(req.birthdate);
    user.zoneinfo = optional(req.zoneinfo);
    user.phone_number = optional(req.phone_number);
    user.street_address = optional(req.street_address);
    user.locality = optional(req.locality);
    user.region = optional(req.region);
    user.postal_code = optional(req.postal_code);
    user.country = optional(req.country).map(|country| country.to_uppercase());
    user.locale = optional(req.locale).unwrap_or_else(|| "en".into());
    user.validate()?;
    UserRepo.update(&mut conn, &user).await?;
    audit(&mut conn, &user, "ACCOUNT_PROFILE_UPDATED", json!({})).await;
    let permissions = UserRoleRepo
        .find_effective_permissions(&mut conn, user.id)
        .await?;
    Ok(Json(public_profile(&user, !permissions.is_empty())))
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

pub async fn change_password_handler(
    state: OidcState,
    headers: HeaderMap,
    req: ChangePasswordRequest,
) -> Result<Json<Value>, OidcError> {
    let account = current_account(&state, &headers).await?;
    let current_hash = account.user.password_hash.as_deref().ok_or_else(|| {
        OidcError::InvalidInput("This account does not have a local password".into())
    })?;
    if !state.hasher.verify(&req.current_password, current_hash)? {
        return Err(OidcError::InvalidInput(
            "Current password is incorrect".into(),
        ));
    }
    if state.hasher.verify(&req.new_password, current_hash)? {
        return Err(OidcError::InvalidInput(
            "Choose a different password".into(),
        ));
    }
    let mut conn = state.connect().await?;
    let realm = RealmRepo
        .find_by_id(&mut conn, account.user.realm_id)
        .await?
        .ok_or_else(|| OidcError::Internal("Realm not found".into()))?;
    let policy = oidc_core::models::PasswordPolicy::from_realm_config(&realm.config);
    policy
        .validate_password(&req.new_password)
        .map_err(|error| OidcError::InvalidInput(error.to_string()))?;
    let mut user = account.user;
    user.password_hash = Some(state.hasher.hash(&req.new_password)?);
    UserRepo.update(&mut conn, &user).await?;
    SessionRepo
        .revoke_other_user_sessions(&mut conn, user.id, account.session_id)
        .await?;
    audit(&mut conn, &user, "ACCOUNT_PASSWORD_CHANGED", json!({})).await;
    Ok(Json(
        json!({"changed": true, "other_sessions_revoked": true}),
    ))
}

pub async fn sessions_handler(
    state: OidcState,
    headers: HeaderMap,
) -> Result<Json<Value>, OidcError> {
    let account = current_account(&state, &headers).await?;
    let mut conn = state.connect().await?;
    let sessions = SessionRepo
        .find_active_grants_by_user_id(&mut conn, account.user.id)
        .await?;
    let mut items = Vec::with_capacity(sessions.len());
    for session in sessions {
        let client = ClientRepo.find_by_id(&mut conn, session.client_id).await?;
        items.push(json!({
            "id": session.id,
            "client_id": client.as_ref().map(|client| client.client_id.as_str()).unwrap_or("unknown"),
            "client_name": client.as_ref().map(|client| client.name.as_str()).unwrap_or("Unknown application"),
            "created_at": session.created_at,
            "last_used_at": session.last_used_at,
            "expires_at": session.refresh_expires_at.unwrap_or(session.expires_at),
            "maximum_expires_at": session.offline_max_expires_at,
            "offline": session.offline_session,
            "current": session.id == account.session_id,
            "authentication_methods": session.amr,
        }));
    }
    Ok(Json(json!({"items": items})))
}

pub async fn revoke_session_handler(
    state: OidcState,
    headers: HeaderMap,
    id: Uuid,
) -> Result<Json<Value>, OidcError> {
    let account = current_account(&state, &headers).await?;
    let mut conn = state.connect().await?;
    let session = SessionRepo
        .find_by_id(&mut conn, id)
        .await?
        .filter(|session| session.user_id == Some(account.user.id))
        .ok_or_else(|| OidcError::NotFound("session".into()))?;
    if let Some(family_id) = session.token_family_id {
        SessionRepo.revoke_family(&mut conn, family_id).await?;
    } else {
        SessionRepo.revoke(&mut conn, session.id).await?;
    }
    audit(
        &mut conn,
        &account.user,
        "ACCOUNT_SESSION_REVOKED",
        json!({"session_id": id}),
    )
    .await;
    Ok(Json(
        json!({"revoked": true, "current": id == account.session_id}),
    ))
}

pub async fn linked_identities_handler(
    state: OidcState,
    headers: HeaderMap,
) -> Result<Json<Value>, OidcError> {
    let account = current_account(&state, &headers).await?;
    let mut conn = state.connect().await?;
    let identities = FederatedIdentityRepo
        .find_by_user_id(&mut conn, account.user.id)
        .await?;
    let mut items = Vec::with_capacity(identities.len());
    for identity in identities {
        let provider = IdentityProviderRepo
            .find_by_id(&mut conn, identity.identity_provider_id)
            .await?;
        items.push(json!({
            "id": identity.id,
            "provider": provider.as_ref().map(|provider| provider.display_name.as_str()).unwrap_or("Unavailable provider"),
            "alias": provider.as_ref().map(|provider| provider.alias.as_str()),
            "username": identity.upstream_username,
            "email": identity.upstream_email,
            "created_at": identity.created_at,
            "last_used_at": identity.last_used_at,
        }));
    }
    Ok(Json(
        json!({"items": items, "has_password": account.user.password_hash.is_some()}),
    ))
}

pub async fn unlink_identity_handler(
    state: OidcState,
    headers: HeaderMap,
    id: Uuid,
) -> Result<Json<Value>, OidcError> {
    let account = current_account(&state, &headers).await?;
    let mut conn = state.connect().await?;
    let identities = FederatedIdentityRepo
        .find_by_user_id(&mut conn, account.user.id)
        .await?;
    if account.user.password_hash.is_none() && identities.len() <= 1 {
        return Err(OidcError::InvalidInput(
            "Add a local password or another identity before unlinking this sign-in method".into(),
        ));
    }
    if FederatedIdentityRepo
        .delete_for_user(&mut conn, id, account.user.id)
        .await?
        == 0
    {
        return Err(OidcError::NotFound("linked identity".into()));
    }
    audit(
        &mut conn,
        &account.user,
        "ACCOUNT_IDENTITY_UNLINKED",
        json!({"identity_id": id}),
    )
    .await;
    Ok(Json(json!({"unlinked": true})))
}

pub async fn applications_handler(
    state: OidcState,
    headers: HeaderMap,
) -> Result<Json<Value>, OidcError> {
    let account = current_account(&state, &headers).await?;
    let mut conn = state.connect().await?;
    let consents = UserConsentRepo
        .list_by_user(&mut conn, account.user.id)
        .await?;
    let active_sessions = SessionRepo
        .find_active_grants_by_user_id(&mut conn, account.user.id)
        .await?;
    let mut items = Vec::with_capacity(consents.len());
    for consent in consents {
        if let Some(client) = ClientRepo.find_by_id(&mut conn, consent.client_id).await? {
            let session_count = active_sessions
                .iter()
                .filter(|session| session.client_id == client.id)
                .count();
            items.push(json!({
                "id": client.id,
                "client_id": client.client_id,
                "name": client.name,
                "scopes": consent.scopes,
                "granted_at": consent.created_at,
                "updated_at": consent.updated_at,
                "active_sessions": session_count,
            }));
        }
    }
    Ok(Json(json!({"items": items})))
}

pub async fn revoke_application_handler(
    state: OidcState,
    headers: HeaderMap,
    client_id: Uuid,
) -> Result<Json<Value>, OidcError> {
    let account = current_account(&state, &headers).await?;
    let mut conn = state.connect().await?;
    if UserConsentRepo
        .revoke(&mut conn, account.user.id, client_id)
        .await?
        == 0
    {
        return Err(OidcError::NotFound("application grant".into()));
    }
    SessionRepo
        .revoke_by_user_and_client(&mut conn, account.user.id, client_id)
        .await?;
    audit(
        &mut conn,
        &account.user,
        "ACCOUNT_APPLICATION_REVOKED",
        json!({"client_id": client_id}),
    )
    .await;
    Ok(Json(json!({"revoked": true})))
}

async fn audit(
    conn: &mut oidc_repository::Connection,
    user: &User,
    event_type: &str,
    details: Value,
) {
    let event = AuditEvent {
        id: generate_uuid_v7(),
        realm_id: Some(user.realm_id),
        event_type: event_type.into(),
        actor_id: Some(user.id),
        actor_type: ActorType::User,
        target_type: Some("user".into()),
        target_id: Some(user.id),
        details,
        ip_address: None,
        user_agent: None,
        created_at: chrono::Utc::now(),
    };
    if let Err(error) = AuditEventRepo.create(conn, &event).await {
        tracing::warn!("failed to record account event: {error}");
    }
}
