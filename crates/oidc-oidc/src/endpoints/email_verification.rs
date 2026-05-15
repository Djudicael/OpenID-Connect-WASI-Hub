//! Email verification endpoints.

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};

use oidc_core::OidcError;
use oidc_core::models::EmailVerificationToken;
use oidc_core::utils::{generate_opaque_token, generate_uuid_v7, sha2_256_hex};
use oidc_repository::mapper::pg_err;
use oidc_repository::repositories::email_verification_token_repo::EmailVerificationTokenRepo;
use oidc_repository::repositories::realm_repo::RealmRepo;
use oidc_repository::repositories::user_repo::UserRepo;
use oidc_repository::with_transaction;

use crate::state::OidcState;

/// Request body for requesting email verification.
#[derive(Debug, Deserialize)]
pub struct EmailVerificationRequestRequest {
    /// The user's email address.
    pub email: String,
    /// Optional realm name. Defaults to "master".
    pub realm: Option<String>,
}

/// Response for a successful email verification request.
#[derive(Debug, Serialize)]
pub struct EmailVerificationRequestResponse {
    pub message: String,
}

/// Request body for confirming email verification.
#[derive(Debug, Deserialize)]
pub struct EmailVerificationConfirmRequest {
    /// The verification token received via email.
    pub token: String,
}

/// Response for a successful email verification confirmation.
#[derive(Debug, Serialize)]
pub struct EmailVerificationConfirmResponse {
    pub message: String,
}

/// Initiate an email verification.
///
/// This endpoint always returns success even if the email doesn't exist,
/// to prevent email enumeration attacks.
pub async fn email_verification_request_handler(
    State(state): State<OidcState>,
    Json(req): Json<EmailVerificationRequestRequest>,
) -> Result<Json<EmailVerificationRequestResponse>, OidcError> {
    let realm_name = req.realm.as_deref().unwrap_or("master");

    let mut conn = state.connect().await?;

    let realm = match RealmRepo.find_by_name(&mut conn, realm_name).await {
        Ok(Some(r)) if r.enabled => r,
        _ => {
            return Ok(Json(EmailVerificationRequestResponse {
                message: "If the email exists, a verification link has been sent.".to_string(),
            }));
        }
    };

    let user = match UserRepo
        .find_by_email(&mut conn, realm.id, &req.email)
        .await
    {
        Ok(Some(u)) if u.enabled => u,
        _ => {
            return Ok(Json(EmailVerificationRequestResponse {
                message: "If the email exists, a verification link has been sent.".to_string(),
            }));
        }
    };

    // If already verified, still return success
    if user.email_verified {
        return Ok(Json(EmailVerificationRequestResponse {
            message: "Email is already verified.".to_string(),
        }));
    }

    // Generate verification token
    let verification_token = generate_opaque_token()?;
    let token_hash = sha2_256_hex(&verification_token);
    let now = chrono::Utc::now();

    let email_token = EmailVerificationToken {
        id: generate_uuid_v7(),
        user_id: user.id,
        realm_id: realm.id,
        email: user.email.clone(),
        token_hash,
        used: false,
        expires_at: now + chrono::Duration::hours(24),
        created_at: now,
    };

    with_transaction!(conn, pg_err, {
        EmailVerificationTokenRepo
            .create(&mut conn, &email_token)
            .await
    })?;

    // Send verification email
    let verification_url = format!(
        "{}/verify-email?token={}&email={}",
        state.issuer,
        urlencoding::encode(&verification_token),
        urlencoding::encode(&req.email),
    );

    // Best-effort email sending — don't fail the request if email fails
    if let Err(e) = state
        .email_sender
        .send_email_verification(&req.email, &verification_url)
        .await
    {
        tracing::warn!("Failed to send email verification to {}: {}", req.email, e);
    }

    Ok(Json(EmailVerificationRequestResponse {
        message: "If the email exists, a verification link has been sent.".to_string(),
    }))
}

/// Confirm an email verification.
pub async fn email_verification_confirm_handler(
    State(state): State<OidcState>,
    Json(req): Json<EmailVerificationConfirmRequest>,
) -> Result<Json<EmailVerificationConfirmResponse>, OidcError> {
    let token_hash = sha2_256_hex(&req.token);

    let mut conn = state.connect().await?;

    with_transaction!(conn, pg_err, {
        let email_token = match EmailVerificationTokenRepo
            .find_by_token_hash(&mut conn, &token_hash)
            .await
        {
            Ok(Some(t)) => t,
            Ok(None) => return Err(OidcError::InvalidRequest),
            Err(e) => return Err(OidcError::Internal(e.to_string())),
        };

        let mut user = match UserRepo.find_by_id(&mut conn, email_token.user_id).await {
            Ok(Some(u)) => u,
            Ok(None) => return Err(OidcError::NotFound("user".into())),
            Err(e) => return Err(OidcError::Internal(e.to_string())),
        };

        // Verify the email matches
        if user.email != email_token.email {
            return Err(OidcError::InvalidRequest);
        }

        user.email_verified = true;
        UserRepo.update(&mut conn, &user).await?;

        EmailVerificationTokenRepo
            .mark_used(&mut conn, email_token.id)
            .await?;

        Ok(Json(EmailVerificationConfirmResponse {
            message: "Email has been verified successfully.".to_string(),
        }))
    })
}
