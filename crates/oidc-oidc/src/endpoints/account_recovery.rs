//! Account recovery confirmation endpoint (public, no auth required).

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use crate::errors::OidcErrorResponse;
use crate::state::OidcState;

#[derive(Debug, Deserialize)]
pub struct AccountRecoveryConfirmRequest {
    pub token: String,
    pub new_password: String,
}

/// Confirm account recovery — validates the one-time token and sets a new password.
pub async fn confirm_account_recovery(
    State(state): State<OidcState>,
    Json(req): Json<AccountRecoveryConfirmRequest>,
) -> Result<Response, OidcErrorResponse> {
    // 1. Hash the provided token and look it up
    let token_hash = oidc_core::utils::sha2_256_hex(&req.token);

    let mut conn = match wasi_pg_client::Connection::connect(&state.db_config).await {
        Ok(c) => Ok(oidc_repository::Connection::from_pg_client(c)),
        Err(e) => {
            tracing::error!("db connect error: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
    .map_err(|s| OidcErrorResponse::from_status(s))?;

    let recovery_token =
        match oidc_repository::repositories::account_recovery_token_repo::AccountRecoveryTokenRepo
            .find_by_token_hash(&mut conn, &token_hash)
            .await
        {
            Ok(Some(t)) => t,
            Ok(None) => {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "invalid_token"})),
                )
                    .into_response());
            }
            Err(e) => {
                tracing::error!("account recovery lookup error: {e}");
                return Ok((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "internal"})),
                )
                    .into_response());
            }
        };

    // 2. Validate the token (checks hash, expiry, usage)
    if let Err(e) = recovery_token.validate(&req.token) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("{}", e)})),
        )
            .into_response());
    }

    // 3. Validate new password against realm policy
    let user = match oidc_repository::repositories::user_repo::UserRepo
        .find_by_id(&mut conn, recovery_token.user_id)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(json!({"error": "user_not_found"})),
            )
                .into_response());
        }
        Err(e) => {
            tracing::error!("account recovery user fetch error: {e}");
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response());
        }
    };

    // Fetch realm for password policy
    let realm = oidc_repository::repositories::realm_repo::RealmRepo
        .find_by_id(&mut conn, user.realm_id)
        .await
        .ok()
        .flatten();

    let policy = if let Some(ref r) = realm {
        oidc_core::models::PasswordPolicy::from_realm_config(&r.config)
    } else {
        oidc_core::models::PasswordPolicy::default()
    };

    if let Err(violation) = policy.validate_password(&req.new_password) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "password_policy_violation",
                "violated_rules": violation.rules
            })),
        )
            .into_response());
    }

    // 4. Hash the new password
    let password_hash = match state.hasher.hash(&req.new_password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("account recovery hash error: {e}");
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response());
        }
    };

    // 5. Update user password
    let mut updated_user = user.clone();
    updated_user.password_hash = Some(password_hash);
    if let Err(e) = oidc_repository::repositories::user_repo::UserRepo
        .update(&mut conn, &updated_user)
        .await
    {
        tracing::error!("account recovery password update error: {e}");
        return Ok((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "internal"})),
        )
            .into_response());
    }

    // 6. Mark token as used
    if let Err(e) =
        oidc_repository::repositories::account_recovery_token_repo::AccountRecoveryTokenRepo
            .mark_used(&mut conn, recovery_token.id)
            .await
    {
        tracing::warn!("account recovery mark_used error: {e}");
    }

    // 7. Audit event
    let audit = oidc_core::models::AuditEvent {
        id: oidc_core::utils::generate_uuid_v7(),
        realm_id: Some(user.realm_id),
        event_type: "user.account_recovery_completed".to_string(),
        actor_id: Some(recovery_token.created_by),
        actor_type: oidc_core::models::audit_event::ActorType::User,
        target_type: Some("user".to_string()),
        target_id: Some(user.id),
        details: json!({}),
        ip_address: None,
        user_agent: None,
        created_at: chrono::Utc::now(),
    };
    let _ = oidc_repository::repositories::audit_event_repo::AuditEventRepo
        .create(&mut conn, &audit)
        .await;

    let _ = conn.close().await;

    Ok(Json(json!({"recovered": true})).into_response())
}
