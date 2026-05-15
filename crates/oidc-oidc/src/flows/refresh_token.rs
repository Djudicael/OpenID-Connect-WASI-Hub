//! Refresh Token flow.

use oidc_core::OidcError;
use oidc_core::models::Session;
use oidc_core::traits::token_service::{IdTokenExtraClaims, TokenService};
use oidc_core::utils::{generate_opaque_token, generate_uuid_v7, sha2_256_hex};
use oidc_repository::mapper::pg_err;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::repositories::user_repo::UserRepo;
use oidc_repository::with_transaction;
use serde_json::{Value, json};

use crate::state::OidcState;

/// Refresh Token flow handler.
pub struct RefreshTokenFlow;

impl RefreshTokenFlow {
    /// Execute the refresh token flow with rotation and family detection.
    ///
    /// When `dpop_jkt` is provided, the access token is bound to the DPoP
    /// key via a `cnf.jkt` claim and `token_type` is `"DPoP"` (RFC 9449).
    pub async fn execute(
        state: &OidcState,
        refresh_token: &str,
        dpop_jkt: Option<&str>,
    ) -> Result<Value, OidcError> {
        let refresh_hash = sha2_256_hex(refresh_token);

        // --- Phase 1: Check for replay / theft detection ---
        // This runs in its own transaction so that revocation changes are
        // committed even though we return an error.
        {
            let mut conn = state.connect().await?;
            conn.begin().await.map_err(pg_err)?;

            let session = match SessionRepo
                .find_by_refresh_token_hash(&mut conn, &refresh_hash)
                .await?
            {
                Some(s) => s,
                None => {
                    let _ = conn.rollback().await;
                    return Err(OidcError::InvalidRequest);
                }
            };

            if session.revoked || session.family_revoked {
                let _ = conn.rollback().await;
                return Err(OidcError::InvalidRequest);
            }

            // --- Token theft detection ---
            // If this session was already rotated (has a successor), it's a reuse.
            // Commit the revocation before returning the error.
            if session.rotated_at.is_some() {
                SessionRepo.mark_reused(&mut conn, session.id).await?;
                if let Some(family_id) = session.token_family_id {
                    SessionRepo.revoke_family(&mut conn, family_id).await?;
                }
                conn.commit().await.map_err(pg_err)?;
                return Err(OidcError::InvalidRequest);
            }

            // No theft — rollback to release the FOR UPDATE lock.
            let _ = conn.rollback().await;
        }

        // --- Phase 2: Normal rotation ---
        let mut conn = state.connect().await?;

        with_transaction!(conn, pg_err, {
            // Re-fetch the session (we verified above it's not revoked/rotated).
            let session = match SessionRepo
                .find_by_refresh_token_hash(&mut conn, &refresh_hash)
                .await?
            {
                Some(s) if !s.revoked && !s.family_revoked && s.rotated_at.is_none() => s,
                Some(_) => return Err(OidcError::InvalidRequest),
                None => return Err(OidcError::InvalidRequest),
            };

            // --- Fetch user for ID token claims ---
            let user_id = session.user_id.ok_or(OidcError::NotFound("user".into()))?;
            let user = match UserRepo.find_by_id(&mut conn, user_id).await? {
                Some(u) => u,
                None => return Err(OidcError::NotFound("user".into())),
            };

            // --- Issue new tokens ---
            // Compute subject based on client's subject_type
            // We need to look up the client to check subject_type
            let client = match ClientRepo.find_by_id(&mut conn, session.client_id).await? {
                Some(c) if c.enabled => c,
                Some(_) => return Err(OidcError::InvalidClient),
                None => return Err(OidcError::InvalidClient),
            };

            let subject = if client.subject_type == "pairwise" {
                let sector = oidc_core::utils::extract_sector_identifier(
                    client.sector_identifier_uri.as_deref(),
                    &client.redirect_uris,
                )
                .unwrap_or_default();
                oidc_core::utils::compute_pairwise_sub(
                    &user_id.to_string(),
                    &sector,
                    &state.pairwise_salt,
                )
            } else {
                user_id.to_string()
            };
            let audience = session.client_id.to_string();
            let scopes = session.scope.clone();

            // Generate sid early so it can be included in both the ID token and session
            let sid = oidc_core::utils::generate_sid().unwrap_or_default();

            let token_svc = state.token_service_for_realm(session.realm_id).await?;
            let access_token = token_svc
                .issue_access_token(&subject, &audience, &scopes, dpop_jkt, None)
                .await?;

            let at_hash = oidc_core::utils::compute_at_hash(&access_token);

            let id_token_extra = IdTokenExtraClaims {
                at_hash: Some(at_hash),
                auth_time: Some(chrono::Utc::now().timestamp()),
                sid: Some(sid.clone()),
                email: Some(user.email.clone()),
                email_verified: Some(user.email_verified),
                name: user.username.clone(),
                given_name: user.given_name.clone(),
                family_name: user.family_name.clone(),
                acr: Some("urn:mace:incommon:iap:silver".to_string()),
                amr: Some(vec!["pwd".to_string()]),
                ..Default::default()
            };

            let id_token = token_svc
                .issue_id_token(&subject, &audience, Some(id_token_extra))
                .await?;

            // Optionally encrypt the ID token if the client has JWE configured
            let id_token = crate::flows::maybe_encrypt_id_token(state, &id_token, &client)?;

            // --- Store new session with rotation chain ---
            let new_access_hash = sha2_256_hex(&access_token);
            let new_refresh_token_value = generate_opaque_token()?;
            let new_refresh_hash = Some(sha2_256_hex(&new_refresh_token_value));
            let now = chrono::Utc::now();

            let new_session = Session {
                id: generate_uuid_v7(),
                sid,
                user_id: Some(user_id),
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
                authorization_details: None,
            };

            SessionRepo.create(&mut conn, &new_session).await?;

            // Mark the old session as rotated via the repository
            SessionRepo.mark_rotated(&mut conn, session.id).await?;

            let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };

            Ok(json!({
                "access_token": access_token,
                "token_type": token_type,
                "expires_in": 900,
                "refresh_token": new_refresh_token_value,
                "id_token": id_token,
                "scope": scopes.join(" "),
            }))
        })
    }
}
