//! Authorization Code + PKCE flow.

use oidc_core::OidcError;
use oidc_core::models::Session;
use oidc_core::traits::token_service::{IdTokenExtraClaims, TokenService};
use oidc_core::utils::{generate_opaque_token, generate_uuid_v7, sha2_256_hex, verify_s256};
use oidc_repository::mapper::pg_err;
use oidc_repository::repositories::auth_code_repo::AuthCodeRepo;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::repositories::user_repo::UserRepo;
use oidc_repository::with_transaction;
use serde_json::{Value, json};

use crate::state::OidcState;

/// Authorization Code flow handler.
pub struct AuthorizationCodeFlow;

impl AuthorizationCodeFlow {
    /// Execute the authorization code flow.
    ///
    /// When `dpop_jkt` is provided, the access token is bound to the DPoP
    /// key via a `cnf.jkt` claim and `token_type` is `"DPoP"` (RFC 9449).
    pub async fn execute(
        state: &OidcState,
        code: &str,
        redirect_uri: &str,
        client_id: &str,
        code_verifier: &str,
        dpop_jkt: Option<&str>,
    ) -> Result<Value, OidcError> {
        let mut conn = state.connect().await?;

        with_transaction!(conn, pg_err, {
            // --- Look up and validate the authorization code ---
            let auth_code = match AuthCodeRepo.find_by_code(&mut conn, code).await? {
                Some(ac) => ac,
                None => return Err(OidcError::InvalidRequest),
            };

            if auth_code.used {
                return Err(OidcError::InvalidRequest);
            }

            if auth_code.redirect_uri != redirect_uri {
                return Err(OidcError::InvalidRequest);
            }

            // --- Validate client ---
            let client = match ClientRepo.find_by_client_id(&mut conn, client_id).await? {
                Some(c) if c.id == auth_code.client_id && c.enabled => c,
                Some(_) => return Err(OidcError::InvalidClient),
                None => return Err(OidcError::InvalidClient),
            };

            // --- PKCE verification ---
            // Only S256 is supported — plain method is not allowed
            if !verify_s256(code_verifier, &auth_code.code_challenge) {
                return Err(OidcError::InvalidRequest);
            }

            // --- Mark code as used ---
            AuthCodeRepo.mark_used(&mut conn, auth_code.id).await?;

            // --- Fetch user for ID token claims ---
            let user = match UserRepo.find_by_id(&mut conn, auth_code.user_id).await? {
                Some(u) => u,
                None => return Err(OidcError::NotFound("user".into())),
            };

            // --- Issue tokens ---
            let subject = auth_code.user_id.to_string();
            let audience = client.client_id.clone();
            let scopes = auth_code.scope.clone();

            let token_svc = state.token_service_for_realm(auth_code.realm_id).await?;
            let access_token = token_svc
                .issue_access_token(&subject, &audience, &scopes, dpop_jkt)
                .await?;

            let at_hash = oidc_core::utils::compute_at_hash(&access_token);
            let c_hash = oidc_core::utils::compute_c_hash(code);

            let id_token_extra = IdTokenExtraClaims {
                nonce: auth_code.nonce.clone(),
                at_hash: Some(at_hash),
                c_hash: Some(c_hash),
                auth_time: Some(chrono::Utc::now().timestamp()),
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
            };

            let id_token = token_svc
                .issue_id_token(&subject, &audience, Some(id_token_extra))
                .await?;

            // --- Store session with token family ---
            let access_hash = sha2_256_hex(&access_token);
            let refresh_token_value = generate_opaque_token()?;
            let refresh_hash = Some(sha2_256_hex(&refresh_token_value));
            let token_family_id = generate_uuid_v7();
            let now = chrono::Utc::now();

            let session = Session {
                id: generate_uuid_v7(),
                user_id: Some(auth_code.user_id),
                realm_id: auth_code.realm_id,
                client_id: client.id,
                grant_type: "authorization_code".to_string(),
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
