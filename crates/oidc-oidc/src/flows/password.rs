//! Resource Owner Password Credentials flow.

use oidc_core::OidcError;
use oidc_core::models::Session;
use oidc_core::models::audit_event::{ActorType, AuditEvent};
use oidc_core::traits::hasher::{Argon2idHasher, Hasher};
use oidc_core::traits::token_service::{AccessTokenExtraClaims, IdTokenExtraClaims, TokenService};
use oidc_core::utils::{generate_opaque_token, generate_uuid_v7, sha2_256_hex};
use oidc_repository::mapper::pg_err;
use oidc_repository::repositories::audit_event_repo::AuditEventRepo;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::mfa_repo::MfaRepo;
use oidc_repository::repositories::organization_repo::OrganizationRepo;
use oidc_repository::repositories::realm_repo::RealmRepo;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::repositories::user_consent_repo::UserConsentRepo;
use oidc_repository::repositories::user_federation_repo::UserFederationRepo;
use oidc_repository::repositories::user_repo::UserRepo;
use oidc_repository::with_transaction;

use crate::endpoints::mfa::{self, LoginMfaChallenge, LoginMfaProof};
use crate::endpoints::required_actions::{self, RequiredActionChallenge};
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

pub enum PasswordFlowOutcome {
    Authenticated(PasswordFlowResult),
    MfaRequired(LoginMfaChallenge),
    RequiredActions(RequiredActionChallenge),
    MfaRejected,
}

/// Resource Owner Password Credentials flow handler.
pub struct PasswordFlow;

async fn authenticate_directory(
    state: &OidcState,
    conn: &mut oidc_repository::Connection,
    realm_id: uuid::Uuid,
    identifier: &str,
    password: &str,
) -> Result<Option<(oidc_core::models::User, String)>, OidcError> {
    let providers = UserFederationRepo.list_enabled(conn, realm_id).await?;
    for provider in providers {
        if provider.provider_type == oidc_core::models::UserFederationType::Kerberos {
            continue;
        }
        match crate::federation::authenticate(state, &provider, identifier, password).await {
            Ok(Some(directory_user)) => {
                let user =
                    crate::federation::import_user(conn, &provider, &directory_user, true).await?;
                return Ok(Some((user, provider.provider_type.to_string())));
            }
            Ok(None) => {}
            Err(error) => {
                // A failed provider must not prevent a lower-priority directory from authenticating.
                tracing::warn!(provider_id = %provider.id, "directory authentication provider failed: {error}");
            }
        }
    }
    Ok(None)
}

async fn authenticate_kerberos_directory(
    state: &OidcState,
    conn: &mut oidc_repository::Connection,
    realm_id: uuid::Uuid,
    token: &str,
) -> Result<Option<oidc_core::models::User>, OidcError> {
    for provider in UserFederationRepo.list_enabled(conn, realm_id).await? {
        if provider.provider_type != oidc_core::models::UserFederationType::Kerberos {
            continue;
        }
        match crate::federation::authenticate_kerberos(state, &provider, token).await {
            Ok(Some(directory_user)) => {
                return crate::federation::import_user(conn, &provider, &directory_user, true)
                    .await
                    .map(Some);
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(provider_id = %provider.id, "Kerberos authentication provider failed: {error}");
            }
        }
    }
    Ok(None)
}

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
        mfa_proof: Option<&LoginMfaProof>,
        requested_scopes: &[String],
        requested_acr_values: &[String],
        kerberos_token: Option<&str>,
    ) -> Result<PasswordFlowOutcome, OidcError> {
        // --- Input validation ---
        if kerberos_token.is_none() && (email.trim().is_empty() || email.len() > 320) {
            return Err(OidcError::AuthenticationFailed(
                "Invalid credentials".to_string(),
            ));
        }
        if kerberos_token.is_none() && (password.is_empty() || password.len() < 8) {
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
            let failure_count = if kerberos_token.is_some() {
                0
            } else {
                AuditEventRepo
                    .count_recent_failures(&mut conn, email, realm.id)
                    .await?
            };
            if failure_count >= 5 {
                return Err(OidcError::AuthorizationDenied(
                    "Too many failed attempts. Please try again later.".to_string(),
                ));
            }

            // Resolve local users first, then enabled LDAP/Active Directory providers.
            let mut federation_amr = None;
            let user = if let Some(token) = kerberos_token {
                match authenticate_kerberos_directory(state, &mut conn, realm.id, token).await? {
                    Some(user) => {
                        federation_amr = Some("kerberos".to_string());
                        user
                    }
                    None => {
                        return Err(OidcError::AuthenticationFailed(
                            "Invalid credentials".to_string(),
                        ));
                    }
                }
            } else {
                let local_user = if email.contains('@') {
                    UserRepo.find_by_email(&mut conn, realm.id, email).await?
                } else {
                    UserRepo
                        .find_by_username(&mut conn, realm.id, email)
                        .await?
                };
                if local_user
                    .as_ref()
                    .and_then(|user| user.password_hash.as_ref())
                    .is_some()
                {
                    local_user.expect("local password user was checked")
                } else {
                    match authenticate_directory(state, &mut conn, realm.id, email, password)
                        .await?
                    {
                        Some((user, amr)) => {
                            federation_amr = Some(amr);
                            user
                        }
                        None => {
                            let _ = state.hasher.verify(
                                "dummy",
                                "$argon2id$v=19$m=19456,t=2,p=1$dummysalt$dummyhash",
                            );
                            return Err(OidcError::AuthenticationFailed(
                                "Invalid credentials".to_string(),
                            ));
                        }
                    }
                }
            };

            if !user.enabled {
                return Err(OidcError::AuthorizationDenied(
                    "Account disabled".to_string(),
                ));
            }
            if OrganizationRepo
                .is_managed_user_blocked(&mut conn, user.id)
                .await?
            {
                return Err(OidcError::AuthorizationDenied(
                    "Account organization is disabled".to_string(),
                ));
            }

            // Directory passwords are verified by the configured gateway.
            let valid = if federation_amr.is_some() {
                true
            } else {
                let password_hash = user
                    .password_hash
                    .as_ref()
                    .ok_or_else(|| OidcError::AuthenticationFailed("Invalid credentials".into()))?;
                let hasher = Argon2idHasher::new();
                hasher.verify(password, password_hash).map_err(|e| {
                    tracing::error!("Internal error: verify failed: {e}");
                    OidcError::Internal(e.to_string())
                })?
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

            let has_mfa = MfaRepo.find_totp(&mut conn, user.id).await?.is_some()
                || !MfaRepo.list_webauthn(&mut conn, user.id).await?.is_empty();
            let (acr, mut amr) = if has_mfa {
                match mfa_proof {
                    Some(proof) => {
                        let Some(verified) = mfa::verify_login(
                            &mut conn, state, user.id, realm.id, client.id, proof,
                        )
                        .await?
                        else {
                            return Ok(PasswordFlowOutcome::MfaRejected);
                        };
                        (oidc_core::utils::ACR_SILVER.to_string(), verified.amr)
                    }
                    None => {
                        let challenge =
                            mfa::begin_login(&mut conn, state, user.id, realm.id, client.id)
                                .await?;
                        return Ok(PasswordFlowOutcome::MfaRequired(challenge));
                    }
                }
            } else {
                (oidc_core::utils::ACR_BRONZE.to_string(), {
                    let mut methods = vec![oidc_core::utils::AMR_PWD.to_string()];
                    if let Some(method) = federation_amr.clone() {
                        methods.push(method);
                    }
                    methods
                })
            };
            if let Some(method) = federation_amr {
                if method == "kerberos" {
                    amr.retain(|value| value != oidc_core::utils::AMR_PWD);
                }
                if !amr.contains(&method) {
                    amr.push(method);
                }
            }

            let mut actions = required_actions::pending_actions(&mut conn, &user, &realm).await?;
            let flow =
                oidc_core::models::AuthenticationFlowConfig::from_realm_config(&realm.config);
            let step_up = requested_acr_values
                .iter()
                .any(|v| v == oidc_core::utils::ACR_SILVER)
                || (flow.enabled
                    && flow.step_up.enabled
                    && (flow.step_up.client_ids.is_empty()
                        || flow
                            .step_up
                            .client_ids
                            .iter()
                            .any(|v| v == &client.client_id))
                    && (flow.step_up.scopes.is_empty()
                        || flow
                            .step_up
                            .scopes
                            .iter()
                            .any(|v| requested_scopes.contains(v))));
            if step_up
                && !has_mfa
                && !actions.contains(&oidc_core::models::RequiredActionKind::ConfigureMfa)
            {
                actions.push(oidc_core::models::RequiredActionKind::ConfigureMfa);
            }
            if !actions.is_empty() {
                let challenge = required_actions::create_challenge(
                    &mut conn, &user, &realm, client.id, actions,
                )
                .await?;
                return Ok(PasswordFlowOutcome::RequiredActions(challenge));
            }

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
            if requested_scopes
                .iter()
                .any(|scope| scope == "offline_access")
            {
                return Err(OidcError::InvalidScope(
                    "offline_access requires an interactive authorization code flow".into(),
                ));
            }
            let requested = if requested_scopes.is_empty() {
                client
                    .allowed_scopes
                    .iter()
                    .filter(|scope| scope.as_str() != "offline_access")
                    .cloned()
                    .collect()
            } else {
                requested_scopes.to_vec()
            };
            let scopes = oidc_repository::repositories::scope_repo::ScopeRepo
                .resolve_names_for_client(&mut conn, client.id, &requested, &client.allowed_scopes)
                .await?;
            let role_claims = crate::role_claims::resolve_role_claims(&mut conn, user.id).await?;
            let mapped_claims = crate::protocol_mappers::resolve_mapped_claims(
                &mut conn,
                client.id,
                Some(&user),
                &scopes,
            )
            .await?;

            // Generate sid early so it can be included in both the ID token and session
            let sid = oidc_core::utils::generate_sid().unwrap_or_default();

            let token_svc = state.token_service_for_realm(user.realm_id).await?;
            let access_token = token_svc
                .issue_access_token_with_extra(
                    &subject,
                    &audience,
                    &scopes,
                    dpop_jkt,
                    None,
                    None,
                    Some(AccessTokenExtraClaims {
                        custom_claims: mapped_claims.access_token.clone(),
                        additional_audiences: mapped_claims.access_audiences.clone(),
                        ..Default::default()
                    }),
                )
                .await?;

            let at_hash = oidc_core::utils::compute_at_hash(&access_token);

            let id_token_extra = IdTokenExtraClaims {
                custom_claims: mapped_claims.id_token,
                additional_audiences: mapped_claims.id_audiences,
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
                acr: Some(acr.clone()),
                amr: Some(amr.clone()),
                azp: None, // Password flow does not currently support resource indicators
                address: None,
                roles: role_claims.roles,
                realm_access: role_claims.realm_access,
                resource_access: role_claims.resource_access,
                groups: None,
                organization: None,
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
                grant_type: if amr.iter().any(|method| method == "kerberos") {
                    "kerberos"
                } else {
                    "password"
                }
                .to_string(),
                access_token_hash: sha2_256_hex(&access_token),
                refresh_token_hash: Some(sha2_256_hex(&refresh_token)),
                id_token_jti: None,
                scope: scopes.clone(),
                revoked: false,
                expires_at: now + chrono::Duration::minutes(15),
                refresh_expires_at: Some(now + chrono::Duration::days(7)),
                offline_session: false,
                offline_max_expires_at: None,
                created_at: now,
                last_used_at: None,
                token_family_id: Some(generate_uuid_v7()),
                previous_session_id: None,
                rotated_at: None,
                reused_at: None,
                family_revoked: false,
                authorization_details: None,
                resource: vec![],
                acr,
                amr,
            };

            SessionRepo.create(&mut conn, &session).await?;
            UserConsentRepo
                .grant(&mut conn, user.id, user.realm_id, client.id, &scopes)
                .await?;

            let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };

            Ok(PasswordFlowOutcome::Authenticated(PasswordFlowResult {
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
            }))
        })
    }
}
