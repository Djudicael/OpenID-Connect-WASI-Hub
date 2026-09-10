use axum::Json;
use chrono::{Duration, Utc};
use oidc_core::{
    OidcError,
    models::{AuthenticationFlowConfig, Realm, RequiredActionKind, RequiredActionSession, User},
    traits::hasher::{Argon2idHasher, Hasher},
    utils::{generate_opaque_token, generate_uuid_v7, sha2_256_hex},
};
use oidc_repository::{
    Connection,
    repositories::{
        mfa_repo::MfaRepo, required_action_repo::RequiredActionRepo, session_repo::SessionRepo,
        user_repo::UserRepo,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::state::OidcState;

const ACTION_SESSION_MINUTES: i64 = 10;

#[derive(Debug, Serialize)]
pub struct RequiredActionChallenge {
    pub required_actions: Vec<String>,
    pub action_token: String,
    pub expires_in: i64,
    pub terms: Option<Value>,
    pub user_email: String,
    pub realm: String,
}

fn profile_complete(user: &User) -> bool {
    user.given_name
        .as_deref()
        .is_some_and(|v| !v.trim().is_empty())
        && user
            .family_name
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty())
}

pub async fn pending_actions(
    conn: &mut Connection,
    user: &User,
    realm: &Realm,
) -> Result<Vec<RequiredActionKind>, OidcError> {
    let mut pending = RequiredActionRepo.list(conn, user.id).await?;
    let flow = AuthenticationFlowConfig::from_realm_config(&realm.config);
    let has_mfa = MfaRepo.find_totp(conn, user.id).await?.is_some()
        || !MfaRepo.list_webauthn(conn, user.id).await?.is_empty();

    pending.retain(|action| match action {
        RequiredActionKind::VerifyEmail => !user.email_verified,
        RequiredActionKind::UpdateProfile => !profile_complete(user),
        RequiredActionKind::ConfigureMfa => !has_mfa,
        RequiredActionKind::AcceptTerms => flow.terms.enabled && !flow.terms.version.is_empty(),
        RequiredActionKind::UpdatePassword => true,
    });
    if flow.terms.enabled
        && !flow.terms.version.is_empty()
        && RequiredActionRepo
            .has_accepted_terms(conn, user.id, &flow.terms.version)
            .await?
    {
        pending.retain(|action| *action != RequiredActionKind::AcceptTerms);
    }

    if flow.enabled {
        if flow.require_verified_email && !user.email_verified {
            pending.push(RequiredActionKind::VerifyEmail);
        }
        if flow.require_complete_profile && !profile_complete(user) {
            pending.push(RequiredActionKind::UpdateProfile);
        }
        if flow.require_mfa && !has_mfa {
            pending.push(RequiredActionKind::ConfigureMfa);
        }
        if flow.terms.enabled
            && !flow.terms.version.is_empty()
            && !RequiredActionRepo
                .has_accepted_terms(conn, user.id, &flow.terms.version)
                .await?
        {
            pending.push(RequiredActionKind::AcceptTerms);
        }
    }

    pending.sort_by_key(|action| {
        flow.action_order
            .iter()
            .position(|v| v == action)
            .unwrap_or(usize::MAX)
    });
    pending.dedup();
    Ok(pending)
}

pub async fn create_challenge(
    conn: &mut Connection,
    user: &User,
    realm: &Realm,
    client_id: uuid::Uuid,
    actions: Vec<RequiredActionKind>,
) -> Result<RequiredActionChallenge, OidcError> {
    let token = generate_opaque_token()?;
    let session = RequiredActionSession {
        id: generate_uuid_v7(),
        token_hash: sha2_256_hex(&token),
        user_id: user.id,
        realm_id: realm.id,
        client_id,
        expires_at: Utc::now() + Duration::minutes(ACTION_SESSION_MINUTES),
        used_at: None,
    };
    RequiredActionRepo.create_session(conn, &session).await?;
    let flow = AuthenticationFlowConfig::from_realm_config(&realm.config);
    let terms = actions.contains(&RequiredActionKind::AcceptTerms).then(|| {
        json!({
            "version": flow.terms.version,
            "text": flow.terms.text,
        })
    });
    Ok(RequiredActionChallenge {
        required_actions: actions
            .into_iter()
            .map(|v| v.as_str().to_string())
            .collect(),
        action_token: token,
        expires_in: ACTION_SESSION_MINUTES * 60,
        terms,
        user_email: user.email.clone(),
        realm: realm.name.clone(),
    })
}

pub async fn action_user(
    state: &OidcState,
    token: &str,
) -> Result<(RequiredActionSession, User, Realm), OidcError> {
    let mut conn = state.connect().await?;
    let session = RequiredActionRepo
        .find_session(&mut conn, &sha2_256_hex(token))
        .await?
        .ok_or_else(|| {
            OidcError::AuthenticationFailed("Required-action session is invalid or expired".into())
        })?;
    let user = UserRepo
        .find_by_id(&mut conn, session.user_id)
        .await?
        .ok_or_else(|| OidcError::AuthenticationFailed("User not found".into()))?;
    let realm = oidc_repository::repositories::realm_repo::RealmRepo
        .find_by_id(&mut conn, session.realm_id)
        .await?
        .ok_or_else(|| OidcError::AuthenticationFailed("Realm not found".into()))?;
    Ok((session, user, realm))
}

#[derive(Debug, Deserialize)]
pub struct ActionTokenRequest {
    pub action_token: String,
}
#[derive(Debug, Deserialize)]
pub struct PasswordRequest {
    pub action_token: String,
    pub new_password: String,
}
#[derive(Debug, Deserialize)]
pub struct ProfileRequest {
    pub action_token: String,
    pub given_name: String,
    pub family_name: String,
    pub username: Option<String>,
}
#[derive(Debug, Deserialize)]
pub struct TermsRequest {
    pub action_token: String,
    pub version: String,
    pub accepted: bool,
}

async fn response_status(state: &OidcState, token: &str) -> Result<Json<Value>, OidcError> {
    let (session, user, realm) = action_user(state, token).await?;
    let mut conn = state.connect().await?;
    let actions = pending_actions(&mut conn, &user, &realm).await?;
    if actions.is_empty() {
        RequiredActionRepo
            .use_session(&mut conn, session.id)
            .await?;
    }
    let flow = AuthenticationFlowConfig::from_realm_config(&realm.config);
    Ok(Json(json!({
        "complete": actions.is_empty(),
        "required_actions": actions.iter().map(|v|v.as_str()).collect::<Vec<_>>(),
        "terms": actions.contains(&RequiredActionKind::AcceptTerms).then(|| json!({"version":flow.terms.version,"text":flow.terms.text}))
        ,"user_email": user.email,
        "realm": realm.name
    })))
}

pub async fn status_handler(
    state: OidcState,
    req: ActionTokenRequest,
) -> Result<Json<Value>, OidcError> {
    response_status(&state, &req.action_token).await
}

pub async fn password_handler(
    state: OidcState,
    req: PasswordRequest,
) -> Result<Json<Value>, OidcError> {
    let (_, mut user, realm) = action_user(&state, &req.action_token).await?;
    let mut conn = state.connect().await?;
    if !RequiredActionRepo
        .list(&mut conn, user.id)
        .await?
        .contains(&RequiredActionKind::UpdatePassword)
    {
        return Err(OidcError::InvalidInput(
            "Password update is not required".into(),
        ));
    }
    oidc_core::models::PasswordPolicy::from_realm_config(&realm.config)
        .validate_password(&req.new_password)
        .map_err(|e| OidcError::InvalidInput(e.to_string()))?;
    if user.password_hash.as_deref().is_some_and(|hash| {
        Argon2idHasher::new()
            .verify(&req.new_password, hash)
            .unwrap_or(false)
    }) {
        return Err(OidcError::InvalidInput(
            "Choose a password you have not already used".into(),
        ));
    }
    user.password_hash = Some(Argon2idHasher::new().hash(&req.new_password)?);
    UserRepo.update(&mut conn, &user).await?;
    SessionRepo.revoke_by_user_id(&mut conn, user.id).await?;
    RequiredActionRepo
        .complete(&mut conn, user.id, RequiredActionKind::UpdatePassword)
        .await?;
    response_status(&state, &req.action_token).await
}

pub async fn profile_handler(
    state: OidcState,
    req: ProfileRequest,
) -> Result<Json<Value>, OidcError> {
    let (_, mut user, _) = action_user(&state, &req.action_token).await?;
    if req.given_name.trim().is_empty() || req.family_name.trim().is_empty() {
        return Err(OidcError::InvalidInput(
            "First and last name are required".into(),
        ));
    }
    user.given_name = Some(req.given_name.trim().into());
    user.family_name = Some(req.family_name.trim().into());
    user.username = req
        .username
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let mut conn = state.connect().await?;
    UserRepo.update(&mut conn, &user).await?;
    RequiredActionRepo
        .complete(&mut conn, user.id, RequiredActionKind::UpdateProfile)
        .await?;
    response_status(&state, &req.action_token).await
}

pub async fn terms_handler(state: OidcState, req: TermsRequest) -> Result<Json<Value>, OidcError> {
    if !req.accepted {
        return Err(OidcError::AuthorizationDenied(
            "The terms must be accepted to continue".into(),
        ));
    }
    let (_, user, realm) = action_user(&state, &req.action_token).await?;
    let flow = AuthenticationFlowConfig::from_realm_config(&realm.config);
    if !flow.terms.enabled || flow.terms.version != req.version {
        return Err(OidcError::InvalidInput(
            "Terms version is no longer current".into(),
        ));
    }
    let mut conn = state.connect().await?;
    RequiredActionRepo
        .accept_terms(&mut conn, user.id, &req.version)
        .await?;
    RequiredActionRepo
        .complete(&mut conn, user.id, RequiredActionKind::AcceptTerms)
        .await?;
    response_status(&state, &req.action_token).await
}

pub async fn complete_mfa_handler(
    state: OidcState,
    req: ActionTokenRequest,
) -> Result<Json<Value>, OidcError> {
    let (_, user, _) = action_user(&state, &req.action_token).await?;
    let mut conn = state.connect().await?;
    let configured = MfaRepo.find_totp(&mut conn, user.id).await?.is_some()
        || !MfaRepo.list_webauthn(&mut conn, user.id).await?.is_empty();
    if !configured {
        return Err(OidcError::InvalidInput(
            "Configure an authenticator before continuing".into(),
        ));
    }
    RequiredActionRepo
        .complete(&mut conn, user.id, RequiredActionKind::ConfigureMfa)
        .await?;
    response_status(&state, &req.action_token).await
}
