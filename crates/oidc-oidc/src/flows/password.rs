//! Resource Owner Password Credentials flow.

use oidc_core::OidcError;
use oidc_core::models::Session;
use oidc_core::models::audit_event::{ActorType, AuditEvent};
use oidc_core::traits::hasher::{Argon2idHasher, Hasher};
use oidc_core::traits::token_service::{IdTokenExtraClaims, TokenService};
use oidc_core::utils::{generate_opaque_token, generate_uuid_v7, is_valid_email, sha2_256_hex};
use oidc_repository::mapper::pg_err;
use oidc_repository::repositories::audit_event_repo::AuditEventRepo;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::realm_repo::RealmRepo;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::repositories::user_repo::UserRepo;
use oidc_repository::with_transaction;

use crate::state::OidcState;

/// Result of a successful password flow execution.
pub struct PasswordFlowResult {
    pub access_token: String,
    pub refresh_token: String,
    pub id_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub session_id: String,
    pub user_id: String,
    pub user_email: String,
    pub user_username: Option<String>,
    pub user_given_name: Option<String>,
    pub user_family_name: Option<String>,
}

/// Resource Owner Password Credentials flow handler.
pub struct PasswordFlow;

impl PasswordFlow {
    /// Execute the password flow.
    ///
    /// If `realm_name` is provided, authenticates against that realm.
    /// Defaults to `"master"` (backward-compatible).
    ///
    /// When `dpop_jkt` is provided, the access token is bound to the DPoP
    /// key via a `cnf.jkt` claim and `token_type` is `"DPoP"` (RFC 9449).
    pub async fn execute(
        state: &OidcState,
        email: &str,
        password: &str,
        client_id: Option<&str>,
        realm_name: Option<&str>,
        dpop_jkt: Option<&str>,
    ) -> Result<PasswordFlowResult, OidcError> {
        // --- Input validation ---
        if !is_valid_email(email) {
            return Err(OidcError::AuthenticationFailed(
                "Invalid credentials".to_string(),
            ));
        }
        if password.is_empty() || password.len() < 8 {
            return Err(OidcError::AuthenticationFailed(
                "Invalid credentials".to_string(),
            ));
        }

        let mut conn = state.connect().await?;

        with_transaction!(conn, pg_err, {
            // Resolve realm by name (defaults to "master" for backward compat)
            let realm_name = realm_name.unwrap_or("master");
            let realm = match RealmRepo.find_by_name(&mut conn, realm_name).await? {
                Some(r) => r,
                None => {
                    return Err(OidcError::AuthenticationFailed(
                        "Invalid credentials".to_string(),
                    ));
                }
            };

            if !realm.enabled {
                return Err(OidcError::AuthorizationDenied("Realm disabled".to_string()));
            }

            // --- Brute-force protection: check failed attempts ---
            let failure_count = AuditEventRepo
                .count_recent_failures(&mut conn, email, realm.id)
                .await?;
            if failure_count >= 5 {
                return Err(OidcError::AuthorizationDenied(
                    "Too many failed attempts. Please try again later.".to_string(),
                ));
            }

            // Find user by email
            let user = match UserRepo.find_by_email(&mut conn, realm.id, email).await? {
                Some(u) => u,
                None => {
                    // Perform dummy hash verification to prevent timing oracle
                    let _ = state.hasher.verify(
                        "dummy",
                        "$argon2id$v=19$m=19456,t=2,p=1$dummysalt$dummyhash",
                    );
                    return Err(OidcError::AuthenticationFailed(
                        "Invalid credentials".to_string(),
                    ));
                }
            };

            if !user.enabled {
                return Err(OidcError::AuthorizationDenied(
                    "Account disabled".to_string(),
                ));
            }

            // Verify password
            let password_hash = match user.password_hash {
                Some(ref h) => h,
                None => {
                    return Err(OidcError::AuthenticationFailed(
                        "Invalid credentials".to_string(),
                    ));
                }
            };

            let hasher = Argon2idHasher::new();
            let valid = match hasher.verify(password, password_hash) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("Internal error: verify failed: {}", e);
                    return Err(OidcError::Internal(e.to_string()));
                }
            };

            if !valid {
                // Log failed attempt for brute-force tracking via the repository
                let audit = AuditEvent {
                    id: generate_uuid_v7(),
                    realm_id: Some(realm.id),
                    event_type: "LOGIN_FAILURE".to_string(),
                    actor_id: None,
                    actor_type: ActorType::User,
                    target_type: None,
                    target_id: None,
                    details: serde_json::json!({"email": email}),
                    ip_address: None,
                    user_agent: None,
                    created_at: chrono::Utc::now(),
                };
                let _ = AuditEventRepo.create(&mut conn, &audit).await;
                return Err(OidcError::AuthenticationFailed(
                    "Invalid credentials".to_string(),
                ));
            }

            // Find client using realm-scoped lookup
            let client_id_str = client_id.unwrap_or("admin-ui");
            let client = match ClientRepo
                .find_by_client_id_in_realm(&mut conn, client_id_str, realm.id)
                .await
            {
                Ok(Some(c)) if c.enabled => c,
                Ok(Some(_)) => return Err(OidcError::InvalidClient),
                Ok(None) => return Err(OidcError::InvalidClient),
                Err(e) => {
                    tracing::error!("Internal error: {}", e);
                    return Err(OidcError::Internal(e.to_string()));
                }
            };

            // Issue tokens
            // Compute subject based on client's subject_type
            let subject = if client.subject_type == "pairwise" {
                let sector = oidc_core::utils::extract_sector_identifier(
                    client.sector_identifier_uri.as_deref(),
                    &client.redirect_uris,
                )
                .unwrap_or_default();
                oidc_core::utils::compute_pairwise_sub(
                    &user.id.to_string(),
                    &sector,
                    &state.pairwise_salt,
                )
            } else {
                user.id.to_string()
            };
            let audience = client.client_id.clone();
            let scopes = vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "admin".to_string(),
            ];

            // Generate sid early so it can be included in both the ID token and session
            let sid = oidc_core::utils::generate_sid().unwrap_or_default();

            let token_svc = state.token_service_for_realm(user.realm_id).await?;
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
                amr: Some(vec![oidc_core::utils::AMR_PWD.to_string()]),
                azp: None, // Password flow does not currently support resource indicators
                address: None,
                roles: None,
                groups: None,
            };

            let id_token = token_svc
                .issue_id_token(&subject, &audience, Some(id_token_extra))
                .await?;

            // Optionally encrypt the ID token if the client has JWE configured
            let id_token = crate::flows::maybe_encrypt_id_token(state, &id_token, &client)?;

            let refresh_token = generate_opaque_token()?;

            // Store session
            let now = chrono::Utc::now();
            let session = Session {
                id: generate_uuid_v7(),
                sid,
                user_id: Some(user.id),
                realm_id: user.realm_id,
                client_id: client.id,
                grant_type: "password".to_string(),
                access_token_hash: sha2_256_hex(&access_token),
                refresh_token_hash: Some(sha2_256_hex(&refresh_token)),
                id_token_jti: None,
                scope: scopes.clone(),
                revoked: false,
                expires_at: now + chrono::Duration::minutes(15),
                refresh_expires_at: Some(now + chrono::Duration::days(7)),
                created_at: now,
                last_used_at: None,
                token_family_id: Some(generate_uuid_v7()),
                previous_session_id: None,
                rotated_at: None,
                reused_at: None,
                family_revoked: false,
                authorization_details: None,
                resource: vec![],
            };

            SessionRepo.create(&mut conn, &session).await?;

            let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };

            Ok(PasswordFlowResult {
                access_token,
                refresh_token,
                id_token,
                token_type: token_type.to_string(),
                expires_in: 900,
                session_id: session.id.to_string(),
                user_id: user.id.to_string(),
                user_email: user.email,
                user_username: user.username,
                user_given_name: user.given_name,
                user_family_name: user.family_name,
            })
        })
    }
}
