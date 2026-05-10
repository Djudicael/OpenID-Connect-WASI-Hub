//! Refresh Token flow.

use oidc_core::OidcError;
use oidc_core::models::Session;
use oidc_core::traits::token_service::{IdTokenExtraClaims, TokenService};
use oidc_core::utils::{generate_opaque_token, generate_uuid_v7, sha2_256_hex};
use oidc_repository::mapper::pg_err;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::repositories::user_repo::UserRepo;
use oidc_repository::with_transaction;
use serde_json::{Value, json};

use crate::state::OidcState;

/// Refresh Token flow handler.
pub struct RefreshTokenFlow;

impl RefreshTokenFlow {
    /// Execute the refresh token flow with rotation and family detection.
    pub async fn execute(state: &OidcState, refresh_token: &str) -> Result<Value, OidcError> {
        let mut conn = state.connect().await?;

        with_transaction!(conn, pg_err, {
            let refresh_hash = sha2_256_hex(refresh_token);

            // --- Look up session by refresh token hash ---
            let session = match SessionRepo
                .find_by_refresh_token_hash(&mut conn, &refresh_hash)
                .await?
            {
                Some(s) => s,
                None => return Err(OidcError::InvalidRequest),
            };

            if session.revoked || session.family_revoked {
                return Err(OidcError::InvalidRequest);
            }

            // --- Token theft detection ---
            // If this session was already rotated (has a successor), it's a reuse
            if session.rotated_at.is_some() {
                // Mark as reused and revoke the entire family
                SessionRepo.mark_reused(&mut conn, session.id).await?;
                if let Some(family_id) = session.token_family_id {
                    SessionRepo.revoke_family(&mut conn, family_id).await?;
                }
                return Err(OidcError::InvalidRequest);
            }

            // --- Fetch user for ID token claims ---
            let user = match UserRepo.find_by_id(&mut conn, session.user_id).await? {
                Some(u) => u,
                None => return Err(OidcError::NotFound("user".into())),
            };

            // --- Issue new tokens ---
            let subject = session.user_id.to_string();
            let audience = session.client_id.to_string();
            let scopes = session.scope.clone();

            let access_token = state
                .token_service
                .issue_access_token(&subject, &audience, &scopes)
                .await?;

            let at_hash = oidc_core::utils::compute_at_hash(&access_token);

            let id_token_extra = IdTokenExtraClaims {
                at_hash: Some(at_hash),
                auth_time: Some(chrono::Utc::now().timestamp()),
                email: Some(user.email.clone()),
                email_verified: Some(user.email_verified),
                name: user.username.clone(),
                given_name: user.given_name.clone(),
                family_name: user.family_name.clone(),
                ..Default::default()
            };

            let id_token = state
                .token_service
                .issue_id_token(&subject, &audience, Some(id_token_extra))
                .await?;

            // --- Store new session with rotation chain ---
            let new_access_hash = sha2_256_hex(&access_token);
            let new_refresh_token_value = generate_opaque_token()?;
            let new_refresh_hash = Some(sha2_256_hex(&new_refresh_token_value));
            let now = chrono::Utc::now();

            let new_session = Session {
                id: generate_uuid_v7(),
                user_id: session.user_id,
                realm_id: session.realm_id,
                client_id: session.client_id,
                grant_type: "refresh_token".to_string(),
                access_token_hash: new_access_hash,
                refresh_token_hash: new_refresh_hash,
                id_token_jti: None,
                scope: scopes.clone(),
                revoked: false,
                expires_at: now + chrono::Duration::minutes(15),
                refresh_expires_at: Some(now + chrono::Duration::days(7)),
                created_at: now,
                last_used_at: None,
                token_family_id: session.token_family_id,
                previous_session_id: Some(session.id),
                rotated_at: None,
                reused_at: None,
                family_revoked: false,
            };

            SessionRepo.create(&mut conn, &new_session).await?;

            // Mark the old session as rotated via the repository
            SessionRepo.mark_rotated(&mut conn, session.id).await?;

            Ok(json!({
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": 900,
                "refresh_token": new_refresh_token_value,
                "id_token": id_token,
                "scope": scopes.join(" "),
            }))
        })
    }
}
