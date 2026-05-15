//! Password reset endpoints for self-service password reset.

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};

use oidc_core::OidcError;
use oidc_core::models::PasswordResetToken;
use oidc_core::utils::{generate_opaque_token, generate_uuid_v7, sha2_256_hex};
use oidc_repository::mapper::pg_err;
use oidc_repository::repositories::password_reset_token_repo::PasswordResetTokenRepo;
use oidc_repository::repositories::realm_repo::RealmRepo;
use oidc_repository::repositories::user_repo::UserRepo;
use oidc_repository::with_transaction;

use crate::state::OidcState;

/// Request body for initiating a password reset.
#[derive(Debug, Deserialize)]
pub struct PasswordResetRequestRequest {
    /// The user's email address.
    pub email: String,
    /// Optional realm name. Defaults to "master".
    pub realm: Option<String>,
}

/// Response for a successful password reset request.
#[derive(Debug, Serialize)]
pub struct PasswordResetRequestResponse {
    /// A message indicating the request was processed.
    pub message: String,
}

/// Request body for confirming a password reset.
#[derive(Debug, Deserialize)]
pub struct PasswordResetConfirmRequest {
    /// The reset token received via email.
    pub token: String,
    /// The new password.
    pub new_password: String,
}

/// Response for a successful password reset confirmation.
#[derive(Debug, Serialize)]
pub struct PasswordResetConfirmResponse {
    /// A message indicating the password was reset.
    pub message: String,
}

/// Initiate a password reset.
///
/// This endpoint always returns success even if the email doesn't exist,
/// to prevent email enumeration attacks.
pub async fn password_reset_request_handler(
    State(state): State<OidcState>,
    Json(req): Json<PasswordResetRequestRequest>,
) -> Result<Json<PasswordResetRequestResponse>, OidcError> {
    let realm_name = req.realm.as_deref().unwrap_or("master");

    let mut conn = state.connect().await?;

    // Find the realm
    let realm = match RealmRepo.find_by_name(&mut conn, realm_name).await {
        Ok(Some(r)) if r.enabled => r,
        _ => {
            // Return success even if realm not found (prevent enumeration)
            return Ok(Json(PasswordResetRequestResponse {
                message: "If the email exists, a reset link has been sent.".to_string(),
            }));
        }
    };

    // Find the user
    let user = match UserRepo
        .find_by_email(&mut conn, realm.id, &req.email)
        .await
    {
        Ok(Some(u)) if u.enabled => u,
        _ => {
            // Return success even if user not found (prevent enumeration)
            return Ok(Json(PasswordResetRequestResponse {
                message: "If the email exists, a reset link has been sent.".to_string(),
            }));
        }
    };

    // Generate reset token
    let reset_token = generate_opaque_token()?;
    let token_hash = sha2_256_hex(&reset_token);
    let now = chrono::Utc::now();

    let password_reset = PasswordResetToken {
        id: generate_uuid_v7(),
        user_id: user.id,
        realm_id: realm.id,
        token_hash: token_hash,
        used: false,
        expires_at: now + chrono::Duration::minutes(15),
        created_at: now,
    };

    with_transaction!(conn, pg_err, {
        PasswordResetTokenRepo
            .create(&mut conn, &password_reset)
            .await
    })?;

    // Send reset email
    let reset_url = format!(
        "{}/reset-password?token={}&email={}",
        state.issuer,
        urlencoding::encode(&reset_token),
        urlencoding::encode(&req.email),
    );

    // Best-effort email sending — don't fail the request if email fails
    if let Err(e) = state
        .email_sender
        .send_password_reset_email(&req.email, &reset_url)
        .await
    {
        tracing::warn!(
            "Failed to send password reset email to {}: {}",
            req.email,
            e
        );
    }

    Ok(Json(PasswordResetRequestResponse {
        message: "If the email exists, a reset link has been sent.".to_string(),
    }))
}

/// Confirm a password reset.
///
/// Validates the reset token and updates the user's password.
pub async fn password_reset_confirm_handler(
    State(state): State<OidcState>,
    Json(req): Json<PasswordResetConfirmRequest>,
) -> Result<Json<PasswordResetConfirmResponse>, OidcError> {
    // Validate new password strength
    if req.new_password.len() < 8 {
        return Err(OidcError::InvalidInput(
            "Password must be at least 8 characters".to_string(),
        ));
    }

    let token_hash = sha2_256_hex(&req.token);

    let mut conn = state.connect().await?;

    with_transaction!(conn, pg_err, {
        // Find the reset token
        let reset_token = match PasswordResetTokenRepo
            .find_by_token_hash(&mut conn, &token_hash)
            .await
        {
            Ok(Some(t)) => t,
            Ok(None) => return Err(OidcError::InvalidRequest),
            Err(e) => return Err(OidcError::Internal(e.to_string())),
        };

        // Find the user
        let mut user = match UserRepo.find_by_id(&mut conn, reset_token.user_id).await {
            Ok(Some(u)) => u,
            Ok(None) => return Err(OidcError::NotFound("user".into())),
            Err(e) => return Err(OidcError::Internal(e.to_string())),
        };

        // Hash the new password
        let new_hash = state.hasher.hash(&req.new_password)?;
        user.password_hash = Some(new_hash);

        // Update user
        UserRepo.update(&mut conn, &user).await?;

        // Mark token as used
        PasswordResetTokenRepo
            .mark_used(&mut conn, reset_token.id)
            .await?;

        Ok(Json(PasswordResetConfirmResponse {
            message: "Password has been reset successfully.".to_string(),
        }))
    })
}
