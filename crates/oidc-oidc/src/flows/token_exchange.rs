//! Token Exchange flow (RFC 8693).

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

/// RFC 8693 token type URNs.
const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
const TOKEN_TYPE_REFRESH_TOKEN: &str = "urn:ietf:params:oauth:token-type:refresh_token";
const TOKEN_TYPE_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
const TOKEN_TYPE_SAML2: &str = "urn:ietf:params:oauth:token-type:saml2";

/// Token Exchange flow handler (RFC 8693).
pub struct TokenExchangeFlow;

impl TokenExchangeFlow {
    /// Execute the token exchange flow per RFC 8693.
    ///
    /// Allows a client to exchange one token for another, optionally with
    /// delegation/impersonation semantics via an `actor_token`.
    ///
    /// When `dpop_jkt` is provided, the access token is bound to the DPoP
    /// key via a `cnf.jkt` claim and `token_type` is `"DPoP"` (RFC 9449).
    #[allow(clippy::too_many_arguments)]
    pub async fn execute(
        state: &OidcState,
        subject_token: &str,
        subject_token_type: &str,
        actor_token: Option<&str>,
        actor_token_type: Option<&str>,
        resource: Option<&str>,
        audience: Option<&str>,
        scopes: Option<&[String]>,
        requested_token_type: Option<&str>,
        client_id: &str,
        dpop_jkt: Option<&str>,
    ) -> Result<Value, OidcError> {
        // ── 1. Validate subject_token_type ──────────────────────────────
        Self::validate_subject_token_type(subject_token_type)?;

        // ── 2. Validate requested_token_type (defaults to access_token) ─
        let requested_type = requested_token_type.unwrap_or(TOKEN_TYPE_ACCESS_TOKEN);
        Self::validate_requested_token_type(requested_type)?;

        // ── 3. Verify subject_token and extract subject ──────────────────
        let (subject, subject_realm_id, subject_user_id) =
            Self::verify_subject_token(state, subject_token, subject_token_type).await?;

        // ── 4. Verify actor_token if provided ────────────────────────────
        let actor_subject = if let (Some(at), Some(att)) = (actor_token, actor_token_type) {
            Some(Self::verify_actor_token(state, at, att).await?)
        } else {
            None
        };

        // ── 5. Look up the client and validate it is confidential ────────
        let mut conn = state.connect().await?;

        with_transaction!(conn, pg_err, {
            let client = match ClientRepo.find_by_client_id(&mut conn, client_id).await? {
                Some(c) if c.enabled => c,
                Some(_) => return Err(OidcError::InvalidClient),
                None => return Err(OidcError::InvalidClient),
            };

            // Token exchange requires a confidential client
            if client.client_type != oidc_core::models::client::ClientType::Confidential {
                tracing::warn!(
                    client_id = client_id,
                    "Token exchange attempted with public client"
                );
                return Err(OidcError::UnauthorizedClient);
            }

            // ── 6. Resolve scopes ────────────────────────────────────────
            let resolved_scopes: Vec<String> = match scopes {
                Some(s) if !s.is_empty() => {
                    // Validate requested scopes are allowed for the client
                    let invalid: Vec<&String> = s
                        .iter()
                        .filter(|sc| !client.allowed_scopes.contains(sc))
                        .collect();
                    if !invalid.is_empty() {
                        return Err(OidcError::InvalidScope(format!(
                            "Scopes not allowed: {}",
                            invalid
                                .iter()
                                .map(|s| s.as_str())
                                .collect::<Vec<_>>()
                                .join(" ")
                        )));
                    }
                    s.to_vec()
                }
                _ => client.allowed_scopes.clone(),
            };

            // ── 7. Compute audience ──────────────────────────────────────
            let resolved_audience = audience
                .map(|a| a.to_string())
                .unwrap_or_else(|| client.client_id.clone());

            // ── 8. Issue the requested token type ────────────────────────
            let token_svc = state.token_service_for_realm(subject_realm_id).await?;

            match requested_type {
                TOKEN_TYPE_ACCESS_TOKEN => {
                    Self::issue_access_token(
                        &token_svc,
                        &mut conn,
                        &subject,
                        &resolved_audience,
                        &resolved_scopes,
                        &client,
                        subject_realm_id,
                        subject_user_id,
                        actor_subject.as_deref(),
                        resource,
                        dpop_jkt,
                    )
                    .await
                }
                TOKEN_TYPE_REFRESH_TOKEN => {
                    Self::issue_refresh_token(
                        &token_svc,
                        &mut conn,
                        &subject,
                        &resolved_audience,
                        &resolved_scopes,
                        &client,
                        subject_realm_id,
                        subject_user_id,
                        actor_subject.as_deref(),
                        resource,
                        dpop_jkt,
                    )
                    .await
                }
                TOKEN_TYPE_ID_TOKEN => {
                    Self::issue_id_token(
                        state,
                        &token_svc,
                        &mut conn,
                        &subject,
                        &resolved_audience,
                        &resolved_scopes,
                        &client,
                        subject_realm_id,
                        subject_user_id,
                        actor_subject.as_deref(),
                        resource,
                        dpop_jkt,
                    )
                    .await
                }
                _ => Err(OidcError::InvalidRequest),
            }
        })
    }

    /// Validate the `subject_token_type` parameter.
    fn validate_subject_token_type(ty: &str) -> Result<(), OidcError> {
        match ty {
            TOKEN_TYPE_ACCESS_TOKEN | TOKEN_TYPE_REFRESH_TOKEN | TOKEN_TYPE_ID_TOKEN => Ok(()),
            TOKEN_TYPE_SAML2 => Err(OidcError::InvalidSubjectToken(
                "SAML2 tokens are not supported".to_string(),
            )),
            _ => Err(OidcError::InvalidSubjectToken(format!(
                "Unknown subject_token_type: {ty}"
            ))),
        }
    }

    /// Validate the `requested_token_type` parameter.
    fn validate_requested_token_type(ty: &str) -> Result<(), OidcError> {
        match ty {
            TOKEN_TYPE_ACCESS_TOKEN | TOKEN_TYPE_REFRESH_TOKEN | TOKEN_TYPE_ID_TOKEN => Ok(()),
            _ => Err(OidcError::InvalidRequest),
        }
    }

    /// Verify the `subject_token` and return `(subject, realm_id, user_id)`.
    async fn verify_subject_token(
        state: &OidcState,
        token: &str,
        token_type: &str,
    ) -> Result<(String, uuid::Uuid, Option<uuid::Uuid>), OidcError> {
        match token_type {
            TOKEN_TYPE_ACCESS_TOKEN => {
                let token_svc = state.token_service.clone();
                let claims = token_svc.verify_access_token_with_claims(token).await?;
                let realm_id = Self::resolve_realm_id_from_issuer(state, &claims.iss).await?;
                Ok((claims.sub, realm_id, None))
            }
            TOKEN_TYPE_REFRESH_TOKEN => {
                let refresh_hash = sha2_256_hex(token);
                let mut conn = state.connect().await?;
                let session = match SessionRepo
                    .find_by_refresh_token_hash(&mut conn, &refresh_hash)
                    .await?
                {
                    Some(s) if !s.revoked && !s.family_revoked => s,
                    Some(_) => {
                        return Err(OidcError::InvalidSubjectToken(
                            "Refresh token is revoked".to_string(),
                        ));
                    }
                    None => {
                        return Err(OidcError::InvalidSubjectToken(
                            "Refresh token not found".to_string(),
                        ));
                    }
                };
                let user_id = session.user_id;
                // Look up the user to get the subject identifier
                let subject = match user_id {
                    Some(uid) => match UserRepo.find_by_id(&mut conn, uid).await? {
                        Some(u) => u.id.to_string(),
                        None => uid.to_string(),
                    },
                    None => {
                        return Err(OidcError::InvalidSubjectToken(
                            "Refresh token has no associated user".to_string(),
                        ));
                    }
                };
                Ok((subject, session.realm_id, user_id))
            }
            TOKEN_TYPE_ID_TOKEN => {
                let token_svc = state.token_service.clone();
                let sub = token_svc.verify_id_token(token).await?;
                let realm_id = Self::resolve_realm_id_from_issuer(state, &state.issuer).await?;
                // Try to resolve user_id from the subject
                let user_id = uuid::Uuid::parse_str(&sub).ok();
                Ok((sub, realm_id, user_id))
            }
            _ => Err(OidcError::InvalidSubjectToken(format!(
                "Unsupported subject_token_type: {token_type}"
            ))),
        }
    }

    /// Verify the `actor_token` and return the actor subject.
    async fn verify_actor_token(
        state: &OidcState,
        token: &str,
        token_type: &str,
    ) -> Result<String, OidcError> {
        match token_type {
            TOKEN_TYPE_ACCESS_TOKEN => {
                let token_svc = state.token_service.clone();
                let claims = token_svc.verify_access_token_with_claims(token).await?;
                Ok(claims.sub)
            }
            TOKEN_TYPE_ID_TOKEN => {
                let token_svc = state.token_service.clone();
                let sub = token_svc.verify_id_token(token).await?;
                Ok(sub)
            }
            TOKEN_TYPE_REFRESH_TOKEN => {
                let refresh_hash = sha2_256_hex(token);
                let mut conn = state.connect().await?;
                let session = match SessionRepo
                    .find_by_refresh_token_hash(&mut conn, &refresh_hash)
                    .await?
                {
                    Some(s) if !s.revoked && !s.family_revoked => s,
                    Some(_) => {
                        return Err(OidcError::InvalidActorToken(
                            "Actor refresh token is revoked".to_string(),
                        ));
                    }
                    None => {
                        return Err(OidcError::InvalidActorToken(
                            "Actor refresh token not found".to_string(),
                        ));
                    }
                };
                match session.user_id {
                    Some(uid) => Ok(uid.to_string()),
                    None => Err(OidcError::InvalidActorToken(
                        "Actor refresh token has no associated user".to_string(),
                    )),
                }
            }
            _ => Err(OidcError::InvalidActorToken(format!(
                "Unsupported actor_token_type: {token_type}"
            ))),
        }
    }

    /// Resolve a realm_id from the issuer URL.
    ///
    /// Falls back to the "master" realm if no specific realm can be determined.
    async fn resolve_realm_id_from_issuer(
        state: &OidcState,
        _issuer: &str,
    ) -> Result<uuid::Uuid, OidcError> {
        // For simplicity, we look up the master realm.
        // In a multi-realm deployment, the issuer URL encodes the realm.
        let mut conn = state.connect().await?;
        use oidc_repository::repositories::realm_repo::RealmRepo;
        match RealmRepo.find_by_name(&mut conn, "master").await? {
            Some(r) => Ok(r.id),
            None => Err(OidcError::Internal("master realm not found".to_string())),
        }
    }

    /// Issue an access token in response to a token exchange.
    #[allow(clippy::too_many_arguments)]
    async fn issue_access_token(
        token_svc: &crate::tokens::JwtTokenService,
        conn: &mut oidc_repository::Connection,
        subject: &str,
        audience: &str,
        scopes: &[String],
        client: &oidc_core::models::Client,
        realm_id: uuid::Uuid,
        user_id: Option<uuid::Uuid>,
        actor: Option<&str>,
        resource: Option<&str>,
        dpop_jkt: Option<&str>,
    ) -> Result<Value, OidcError> {
        // Issue access token — `may_act` is included in the response metadata
        // per RFC 8693 §4.1 (not embedded in the JWT itself).
        let access_token = token_svc
            .issue_access_token(
                subject,
                audience,
                scopes,
                dpop_jkt,
                None,
                resource.map(|r| vec![r.to_string()]).as_deref(),
            )
            .await?;

        let access_hash = sha2_256_hex(&access_token);
        let now = chrono::Utc::now();
        let sid = oidc_core::utils::generate_sid().unwrap_or_default();

        let session = Session {
            id: generate_uuid_v7(),
            sid,
            user_id,
            realm_id,
            client_id: client.id,
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            access_token_hash: access_hash,
            refresh_token_hash: None,
            id_token_jti: None,
            scope: scopes.to_vec(),
            revoked: false,
            expires_at: now + chrono::Duration::minutes(15),
            refresh_expires_at: None,
            created_at: now,
            last_used_at: None,
            token_family_id: None,
            previous_session_id: None,
            rotated_at: None,
            reused_at: None,
            family_revoked: false,
            authorization_details: None,
            resource: resource.map(|r| vec![r.to_string()]).unwrap_or_default(),
        };

        SessionRepo.create(conn, &session).await?;

        let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };

        let mut response = json!({
            "access_token": access_token,
            "issued_token_type": TOKEN_TYPE_ACCESS_TOKEN,
            "token_type": token_type,
            "expires_in": 900,
            "scope": scopes.join(" "),
        });

        // Include `may_act` in the response if actor is present (RFC 8693 §2.2.1)
        if let Some(actor_sub) = actor {
            response["may_act"] = json!({"sub": actor_sub});
        }

        // Include `resource` if provided
        if let Some(res) = resource {
            response["resource"] = json!(res);
        }

        Ok(response)
    }

    /// Issue a refresh token in response to a token exchange.
    #[allow(clippy::too_many_arguments)]
    async fn issue_refresh_token(
        token_svc: &crate::tokens::JwtTokenService,
        conn: &mut oidc_repository::Connection,
        subject: &str,
        audience: &str,
        scopes: &[String],
        client: &oidc_core::models::Client,
        realm_id: uuid::Uuid,
        user_id: Option<uuid::Uuid>,
        actor: Option<&str>,
        resource: Option<&str>,
        dpop_jkt: Option<&str>,
    ) -> Result<Value, OidcError> {
        let access_token = token_svc
            .issue_access_token(
                subject,
                audience,
                scopes,
                dpop_jkt,
                None,
                resource.map(|r| vec![r.to_string()]).as_deref(),
            )
            .await?;

        let refresh_token_value = generate_opaque_token()?;
        let access_hash = sha2_256_hex(&access_token);
        let refresh_hash = sha2_256_hex(&refresh_token_value);
        let now = chrono::Utc::now();
        let token_family_id = generate_uuid_v7();
        let sid = oidc_core::utils::generate_sid().unwrap_or_default();

        let session = Session {
            id: generate_uuid_v7(),
            sid,
            user_id,
            realm_id,
            client_id: client.id,
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            access_token_hash: access_hash,
            refresh_token_hash: Some(refresh_hash),
            id_token_jti: None,
            scope: scopes.to_vec(),
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
            resource: resource.map(|r| vec![r.to_string()]).unwrap_or_default(),
        };

        SessionRepo.create(conn, &session).await?;

        let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };

        let mut response = json!({
            "access_token": access_token,
            "issued_token_type": TOKEN_TYPE_REFRESH_TOKEN,
            "token_type": token_type,
            "expires_in": 900,
            "refresh_token": refresh_token_value,
            "scope": scopes.join(" "),
        });

        if let Some(actor_sub) = actor {
            response["may_act"] = json!({"sub": actor_sub});
        }

        if let Some(res) = resource {
            response["resource"] = json!(res);
        }

        Ok(response)
    }

    /// Issue an ID token in response to a token exchange.
    #[allow(clippy::too_many_arguments)]
    async fn issue_id_token(
        state: &OidcState,
        token_svc: &crate::tokens::JwtTokenService,
        conn: &mut oidc_repository::Connection,
        subject: &str,
        audience: &str,
        scopes: &[String],
        client: &oidc_core::models::Client,
        realm_id: uuid::Uuid,
        user_id: Option<uuid::Uuid>,
        actor: Option<&str>,
        resource: Option<&str>,
        dpop_jkt: Option<&str>,
    ) -> Result<Value, OidcError> {
        // Also issue an access token for the session
        let access_token = token_svc
            .issue_access_token(
                subject,
                audience,
                scopes,
                dpop_jkt,
                None,
                resource.map(|r| vec![r.to_string()]).as_deref(),
            )
            .await?;

        let at_hash = oidc_core::utils::compute_at_hash(&access_token);

        // Build ID token extra claims
        let mut id_token_extra = IdTokenExtraClaims {
            at_hash: Some(at_hash),
            auth_time: Some(chrono::Utc::now().timestamp()),
            acr: Some(oidc_core::utils::ACR_BRONZE.to_string()),
            amr: Some(vec![oidc_core::utils::AMR_TOKEN_EXCHANGE.to_string()]),
            // Set azp when resource indicator is present (OIDC Core §2, RFC 8707)
            azp: resource.map(|_| audience.to_string()),
            ..Default::default()
        };

        // Populate user claims if we have a user_id
        if let Some(uid) = user_id {
            if let Some(user) = UserRepo.find_by_id(conn, uid).await? {
                id_token_extra.email = Some(user.email.clone());
                id_token_extra.email_verified = Some(user.email_verified);
                id_token_extra.name = user.username.clone();
                id_token_extra.given_name = user.given_name.clone();
                id_token_extra.family_name = user.family_name.clone();
                id_token_extra.locale = Some(user.locale.clone());
            }
        }

        let id_token = token_svc
            .issue_id_token(subject, audience, Some(id_token_extra))
            .await?;

        // Optionally encrypt the ID token if the client has JWE configured
        let id_token = crate::flows::maybe_encrypt_id_token(state, &id_token, client)?;

        let access_hash = sha2_256_hex(&access_token);
        let now = chrono::Utc::now();
        let sid = oidc_core::utils::generate_sid().unwrap_or_default();

        let session = Session {
            id: generate_uuid_v7(),
            sid,
            user_id,
            realm_id,
            client_id: client.id,
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            access_token_hash: access_hash,
            refresh_token_hash: None,
            id_token_jti: None,
            scope: scopes.to_vec(),
            revoked: false,
            expires_at: now + chrono::Duration::minutes(15),
            refresh_expires_at: None,
            created_at: now,
            last_used_at: None,
            token_family_id: None,
            previous_session_id: None,
            rotated_at: None,
            reused_at: None,
            family_revoked: false,
            authorization_details: None,
            resource: resource.map(|r| vec![r.to_string()]).unwrap_or_default(),
        };

        SessionRepo.create(conn, &session).await?;

        let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };

        let mut response = json!({
            "access_token": access_token,
            "issued_token_type": TOKEN_TYPE_ID_TOKEN,
            "token_type": token_type,
            "expires_in": 900,
            "id_token": id_token,
            "scope": scopes.join(" "),
        });

        // Include `act` claim info in the response if actor is present (RFC 8693 §4.2)
        if let Some(actor_sub) = actor {
            response["act"] = json!({"sub": actor_sub});
        }

        if let Some(res) = resource {
            response["resource"] = json!(res);
        }

        Ok(response)
    }
}
