use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, header};
use chrono::Utc;
use oidc_core::OidcError;
use oidc_core::models::{
    OrganizationInvitationStatus, OrganizationMembership, OrganizationMembershipKind, User,
};
use oidc_core::utils::{generate_uuid_v7, is_strong_password, is_valid_username, sha2_256_hex};
use oidc_repository::mapper::pg_err;
use oidc_repository::repositories::organization_repo::OrganizationRepo;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::repositories::user_repo::UserRepo;
use oidc_repository::with_transaction;
use serde::{Deserialize, Serialize};

use crate::session_cookie;
use crate::state::OidcState;

#[derive(Debug, Deserialize)]
pub struct AcceptOrganizationInvitationRequest {
    pub token: String,
    pub password: Option<String>,
    pub username: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AcceptOrganizationInvitationResponse {
    pub organization_id: String,
    pub organization_alias: String,
    pub user_id: String,
    pub account_created: bool,
    pub redirect_url: Option<String>,
}

pub async fn accept_organization_invitation(
    State(state): State<OidcState>,
    headers: HeaderMap,
    Json(request): Json<AcceptOrganizationInvitationRequest>,
) -> Result<Json<AcceptOrganizationInvitationResponse>, OidcError> {
    if request.token.is_empty() {
        return Err(OidcError::InvalidInput(
            "invitation token is required".into(),
        ));
    }
    if let Some(username) = request.username.as_deref()
        && !is_valid_username(username)
    {
        return Err(OidcError::InvalidInput("username is invalid".into()));
    }

    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_string);
    let browser_session_id = state
        .decode_encryption_key()
        .ok()
        .and_then(|key| session_cookie::extract_session_id_from_headers(&headers, &key));
    if let Some(token) = bearer.as_deref() {
        state
            .verify_access_token_with_claims_any_issuer(token)
            .await?;
    }
    let mut conn = state.connect().await?;
    with_transaction!(conn, pg_err, {
        let invitation = OrganizationRepo
            .find_invitation_by_token_hash(&mut conn, &sha2_256_hex(&request.token))
            .await?
            .ok_or(OidcError::InvalidRequest)?;
        if invitation.status != OrganizationInvitationStatus::Pending
            || invitation.expires_at <= Utc::now()
        {
            return Err(OidcError::InvalidRequest);
        }
        let organization = OrganizationRepo
            .find_by_id(&mut conn, invitation.organization_id)
            .await?
            .filter(|organization| organization.enabled)
            .ok_or_else(|| OidcError::NotFound("organization".into()))?;

        let (user, account_created) = match UserRepo
            .find_by_email(&mut conn, organization.realm_id, &invitation.email)
            .await?
        {
            Some(user) => {
                if let Some(session_id) = browser_session_id {
                    let session_id = session_id.parse().map_err(|_| {
                        OidcError::AuthenticationFailed("invalid browser session".into())
                    })?;
                    let session = SessionRepo
                        .find_by_id(&mut conn, session_id)
                        .await?
                        .filter(|session| !session.revoked)
                        .ok_or(OidcError::AuthenticationFailed(
                            "invalid browser session".into(),
                        ))?;
                    if session.user_id != Some(user.id) {
                        return Err(OidcError::AuthenticationFailed(
                            "the signed-in account does not match the invitation".into(),
                        ));
                    }
                    (user, false)
                } else if let Some(token) = bearer.as_deref() {
                    let session = SessionRepo
                        .find_by_access_token_hash(&mut conn, &sha2_256_hex(token))
                        .await?
                        .filter(|session| !session.revoked)
                        .ok_or(OidcError::AuthenticationFailed(
                            "invalid access token session".into(),
                        ))?;
                    if session.user_id != Some(user.id) {
                        return Err(OidcError::AuthenticationFailed(
                            "the signed-in account does not match the invitation".into(),
                        ));
                    }
                    (user, false)
                } else {
                    let password_hash = user.password_hash.as_deref().ok_or_else(|| {
                        OidcError::AuthenticationFailed(
                            "this account must sign in through its identity provider".into(),
                        )
                    })?;
                    let password = request.password.as_deref().unwrap_or("");
                    if !state.hasher.verify(password, password_hash)? {
                        return Err(OidcError::AuthenticationFailed(
                            "invalid invitation credentials".into(),
                        ));
                    }
                    (user, false)
                }
            }
            None => {
                let password = request.password.as_deref().unwrap_or("");
                if !is_strong_password(password) {
                    return Err(OidcError::InvalidInput(
                        "password must contain at least eight characters, uppercase, lowercase, and a digit"
                            .into(),
                    ));
                }
                let now = Utc::now();
                let user = User {
                    id: generate_uuid_v7(),
                    realm_id: organization.realm_id,
                    email: invitation.email.clone(),
                    email_verified: true,
                    username: request.username.clone(),
                    password_hash: Some(state.hasher.hash(password)?),
                    given_name: invitation.first_name.clone(),
                    family_name: invitation.last_name.clone(),
                    middle_name: None,
                    nickname: None,
                    preferred_username: request.username.clone(),
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
                    updated_at: now,
                };
                UserRepo.create(&mut conn, &user).await?;
                (user, true)
            }
        };

        OrganizationRepo
            .add_member(
                &mut conn,
                &OrganizationMembership {
                    organization_id: organization.id,
                    user_id: user.id,
                    kind: if account_created {
                        OrganizationMembershipKind::Managed
                    } else {
                        OrganizationMembershipKind::Unmanaged
                    },
                    joined_at: Utc::now(),
                },
            )
            .await?;
        if OrganizationRepo
            .accept_invitation(&mut conn, invitation.id)
            .await?
            == 0
        {
            return Err(OidcError::InvalidRequest);
        }

        Ok(Json(AcceptOrganizationInvitationResponse {
            organization_id: organization.id.to_string(),
            organization_alias: organization.alias,
            user_id: user.id.to_string(),
            account_created,
            redirect_url: organization.redirect_url,
        }))
    })
}
