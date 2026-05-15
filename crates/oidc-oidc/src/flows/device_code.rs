//! Device Authorization Grant flow (RFC 8628).

use oidc_core::OidcError;
use oidc_core::models::Session;
use oidc_core::traits::token_service::{IdTokenExtraClaims, TokenService};
use oidc_core::utils::{generate_opaque_token, generate_uuid_v7, sha2_256_hex};
use oidc_repository::mapper::pg_err;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::device_code_repo::DeviceCodeRepo;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::repositories::user_repo::UserRepo;
use oidc_repository::with_transaction;
use serde_json::{Value, json};

use crate::state::OidcState;

/// Device Authorization Grant flow handler.
pub struct DeviceCodeFlow;

impl DeviceCodeFlow {
    /// Execute the device code flow.
    ///
    /// Per RFC 8628 §3.4, the client polls the token endpoint with the device code.
    /// Returns:
    /// - `authorization_pending` if the user has not yet authorized
    /// - `slow_down` if the client is polling too fast
    /// - `expired_token` if the device code has expired
    /// - `access_denied` if the device code was already used
    /// - Token response on success
    ///
    /// When `dpop_jkt` is provided, the access token is bound to the DPoP
    /// key via a `cnf.jkt` claim and `token_type` is `"DPoP"` (RFC 9449).
    pub async fn execute(
        state: &OidcState,
        device_code: &str,
        client_id: &str,
        dpop_jkt: Option<&str>,
    ) -> Result<Value, OidcError> {
        let device_code_hash = sha2_256_hex(device_code);

        let mut conn = state.connect().await?;

        with_transaction!(conn, pg_err, {
            // --- Find the device code by hash ---
            let dc = match DeviceCodeRepo
                .find_by_device_code(&mut conn, &device_code_hash)
                .await?
            {
                Some(dc) => dc,
                None => return Err(OidcError::ExpiredToken),
            };

            // --- Verify client matches ---
            if dc.client_id.to_string() != client_id {
                return Err(OidcError::InvalidClient);
            }

            // --- Check if expired ---
            if dc.expires_at < chrono::Utc::now() {
                return Err(OidcError::ExpiredToken);
            }

            // --- Check if already used ---
            if dc.used {
                return Err(OidcError::AuthorizationDenied(
                    "Device code already exchanged".into(),
                ));
            }

            // --- Check if not yet authorized ---
            if !dc.authorized {
                return Err(OidcError::AuthorizationPending);
            }

            // --- Fetch the user who authorized ---
            let user_id = dc.user_id.ok_or_else(|| OidcError::AuthorizationPending)?;
            let user = match UserRepo.find_by_id(&mut conn, user_id).await? {
                Some(u) => u,
                None => return Err(OidcError::NotFound("user".into())),
            };

            // --- Fetch the client for subject type ---
            let client = match ClientRepo.find_by_client_id(&mut conn, client_id).await? {
                Some(c) if c.enabled => c,
                _ => return Err(OidcError::InvalidClient),
            };

            // --- Mark device code as used ---
            DeviceCodeRepo.mark_used(&mut conn, dc.id).await?;

            // --- Issue tokens ---
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
            let audience = client.client_id.clone();
            let scopes = dc.scope.clone();

            let sid = oidc_core::utils::generate_sid().unwrap_or_default();

            let token_svc = state.token_service_for_realm(dc.realm_id).await?;
            let access_token = token_svc
                .issue_access_token(&subject, &audience, &scopes, dpop_jkt, None, None)
                .await?;

            let at_hash = oidc_core::utils::compute_at_hash(&access_token);

            let id_token_extra = IdTokenExtraClaims {
                nonce: None,
                at_hash: Some(at_hash),
                c_hash: None,
                auth_time: Some(chrono::Utc::now().timestamp()),
                sid: Some(sid.clone()),
                email: Some(user.email.clone()),
                email_verified: Some(user.email_verified),
                name: user.username.clone(),
                given_name: user.given_name.clone(),
                family_name: user.family_name.clone(),
                middle_name: user.middle_name.clone(),
                nickname: user.nickname.clone(),
                preferred_username: user.preferred_username.clone(),
                profile: user.profile.clone(),
                picture: user.picture.clone(),
                website: user.website.clone(),
                gender: user.gender.clone(),
                birthdate: user.birthdate.clone(),
                zoneinfo: user.zoneinfo.clone(),
                locale: Some(user.locale.clone()),
                phone_number: user.phone_number.clone(),
                phone_number_verified: user.phone_number_verified,
                updated_at: Some(user.updated_at.timestamp()),
                acr: Some(oidc_core::utils::ACR_BRONZE.to_string()),
                amr: Some(vec![oidc_core::utils::AMR_DEVICE_CODE.to_string()]),
                azp: None, // Device code flow does not currently support resource indicators
            };

            let id_token = token_svc
                .issue_id_token(&subject, &audience, Some(id_token_extra))
                .await?;

            // Optionally encrypt the ID token if the client has JWE configured
            let id_token = crate::flows::maybe_encrypt_id_token(state, &id_token, &client)?;

            // --- Store session with token family ---
            let access_hash = sha2_256_hex(&access_token);
            let refresh_token_value = generate_opaque_token()?;
            let refresh_hash = Some(sha2_256_hex(&refresh_token_value));
            let token_family_id = generate_uuid_v7();
            let now = chrono::Utc::now();

            let session = Session {
                id: generate_uuid_v7(),
                sid,
                user_id: Some(user_id),
                realm_id: dc.realm_id,
                client_id: client.id,
                grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
                access_token_hash: access_hash,
                refresh_token_hash: refresh_hash,
                id_token_jti: None,
                scope: scopes.clone(),
                revoked: false,
                expires_at: now + chrono::Duration::minutes(15),
                refresh_expires_at: Some(now + chrono::Duration::days(7)),
                created_at: now,
                last_used_at: None,
                token_family_id: Some(token_family_id),
                previous_session_id: None,
                rotated_at: None,
                reused_at: None,
                family_revoked: false,
                authorization_details: None,
                resource: vec![],
            };

            SessionRepo.create(&mut conn, &session).await?;

            let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };

            Ok(json!({
                "access_token": access_token,
                "token_type": token_type,
                "expires_in": 900,
                "refresh_token": refresh_token_value,
                "id_token": id_token,
                "scope": scopes.join(" "),
            }))
        })
    }
}
