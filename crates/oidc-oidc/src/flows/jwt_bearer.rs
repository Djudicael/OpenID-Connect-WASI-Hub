//! JWT Bearer Token grant flow (RFC 7523 §2.1).
//!
//! A client presents a signed JWT assertion to the token endpoint to obtain
//! an access token. The assertion is signed by the client's private key and
//! verified against the client's registered JWKS.
//!
//! - If `sub` == `iss`, the client is acting on its own behalf (like client_credentials).
//! - If `sub` != `iss`, the client is acting on behalf of a user (delegation).
//! - No refresh token is issued (per RFC 7523).
//! - No ID token is issued (this is an OAuth2 grant, not OIDC).

use oidc_core::OidcError;
use oidc_core::models::Session;
use oidc_core::traits::TokenService;
use oidc_core::utils::{generate_uuid_v7, sha2_256_hex};
use oidc_repository::mapper::pg_err;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::repositories::user_repo::UserRepo;
use oidc_repository::with_transaction;
use serde_json::{Value, json};

use crate::state::OidcState;
use crate::tokens::JwtTokenService;

/// JWT Bearer Token grant flow handler.
pub struct JwtBearerFlow;

/// Claims expected in a JWT bearer assertion per RFC 7523 §3.
///
/// Unlike `ClientAssertionClaims` (used for `private_key_jwt` client
/// authentication), the JWT bearer assertion allows `sub != iss` and
/// includes an optional `scope` claim.
#[derive(Debug, serde::Deserialize)]
struct JwtBearerAssertionClaims {
    /// Issuer — must match the client_id.
    iss: String,
    /// Subject — the resource owner (user or client).
    sub: String,
    /// Audience — must be the token endpoint URL.
    aud: String,
    /// Expiration time (seconds since epoch).
    exp: i64,
    /// Issued at (optional, seconds since epoch).
    #[serde(default)]
    iat: Option<i64>,
    /// JWT ID — optional, for replay protection.
    #[allow(dead_code)]
    jti: Option<String>,
    /// Scope — optional, space-separated scope string.
    scope: Option<String>,
}

impl JwtBearerFlow {
    /// Execute the JWT Bearer Token grant flow.
    ///
    /// When `dpop_jkt` is provided, the access token is bound to the DPoP
    /// key via a `cnf.jkt` claim and `token_type` is `"DPoP"` (RFC 9449).
    pub async fn execute(
        state: &OidcState,
        assertion: &str,
        scope: Option<&str>,
        client_id: &str,
        dpop_jkt: Option<&str>,
    ) -> Result<Value, OidcError> {
        // ── Step 1: Parse the JWT assertion (unverified) to extract claims ──
        // We reuse the low-level parser from JwtTokenService, but then
        // re-deserialize the claims payload into our own struct that
        // includes the `scope` field and optional `iat`.
        let (header, _raw_claims, signing_input, signature) =
            JwtTokenService::parse_client_assertion_unverified(assertion)?;

        // Re-parse the claims portion into our JwtBearerAssertionClaims
        let parts: Vec<&str> = assertion.split('.').collect();
        let claims_json = crate::tokens::jwt_service::b64_decode(parts[1])
            .map_err(|_| OidcError::InvalidClientAssertion("invalid claims encoding".into()))?;
        let claims: JwtBearerAssertionClaims = serde_json::from_slice(&claims_json)
            .map_err(|_| OidcError::InvalidClientAssertion("invalid claims JSON".into()))?;

        // ── Step 2: Validate required claims per RFC 7523 §3 ──
        let token_endpoint = format!("{}/oidc/token", state.issuer);
        let now = chrono::Utc::now().timestamp();

        // iss must match the authenticated client_id
        if claims.iss != client_id {
            tracing::warn!(
                "JWT bearer assertion iss mismatch: expected={}, got={}",
                client_id,
                claims.iss
            );
            return Err(OidcError::InvalidClientAssertion(
                "iss does not match client_id".into(),
            ));
        }

        // aud must be the token endpoint URL
        if claims.aud != token_endpoint {
            tracing::warn!(
                "JWT bearer assertion aud mismatch: expected={}, got={}",
                token_endpoint,
                claims.aud
            );
            return Err(OidcError::InvalidClientAssertion(
                "aud does not match token endpoint".into(),
            ));
        }

        // exp must not be in the past
        if claims.exp < now {
            return Err(OidcError::InvalidClientAssertion(
                "JWT bearer assertion expired".into(),
            ));
        }

        // iat must not be too far in the future (≤ 5 minutes)
        if let Some(iat) = claims.iat {
            if iat > now + 300 {
                return Err(OidcError::InvalidClientAssertion(
                    "JWT bearer assertion issued too far in the future".into(),
                ));
            }
        }

        // ── Step 3: Look up the client and verify the JWT signature ──
        let mut conn = state.connect().await?;

        with_transaction!(conn, pg_err, {
            let client = match ClientRepo.find_by_client_id(&mut conn, &claims.iss).await? {
                Some(c) if c.enabled => c,
                Some(_) => return Err(OidcError::InvalidClient),
                None => return Err(OidcError::InvalidClient),
            };

            // The client must have JWKS registered to verify the assertion
            let jwks = client.jwks.as_ref().ok_or_else(|| {
                OidcError::InvalidClientAssertion(
                    "client has no jwks registered for JWT bearer verification".into(),
                )
            })?;

            // Verify the signature against the client's JWKS
            let jwk = crate::tokens::jwt_service::find_jwk_in_jwks(jwks, &header.kid, &header.alg)?;
            crate::tokens::jwt_service::verify_signature_with_jwk(
                signing_input.as_bytes(),
                &signature,
                &jwk,
            )?;

            // ── Step 4: Determine the subject and scopes ──
            let is_self_issued = claims.sub == claims.iss;

            // Resolve the effective scopes: prefer the request `scope` param,
            // then the assertion `scope` claim, then fall back to the client's
            // allowed scopes.
            let requested_scopes: Vec<String> = scope
                .map(|s| s.split_whitespace().map(|s| s.to_string()).collect())
                .or(claims
                    .scope
                    .map(|s| s.split_whitespace().map(|s| s.to_string()).collect()))
                .unwrap_or_default();

            // Filter requested scopes against client's allowed scopes
            let effective_scopes: Vec<String> = if requested_scopes.is_empty() {
                client.allowed_scopes.clone()
            } else {
                requested_scopes
                    .into_iter()
                    .filter(|s| client.allowed_scopes.contains(s))
                    .collect()
            };

            if effective_scopes.is_empty() {
                return Err(OidcError::InvalidScope(
                    "no valid scopes requested or allowed".into(),
                ));
            }

            // Determine the subject for the access token
            let (subject, user_id) = if is_self_issued {
                // Client acting on its own behalf — sub is the client_id
                (client.client_id.clone(), None)
            } else {
                // Client acting on behalf of a user — look up the user
                // The sub claim should be a user UUID
                let user_uuid = uuid::Uuid::parse_str(&claims.sub).map_err(|_| {
                    OidcError::InvalidClientAssertion(
                        "sub claim is not a valid user identifier".into(),
                    )
                })?;

                let user = match UserRepo.find_by_id(&mut conn, user_uuid).await? {
                    Some(u) if u.enabled => u,
                    Some(_) => {
                        return Err(OidcError::InvalidClientAssertion(
                            "user referenced in sub is disabled".into(),
                        ));
                    }
                    None => {
                        return Err(OidcError::InvalidClientAssertion(
                            "user referenced in sub not found".into(),
                        ));
                    }
                };

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

                (subject, Some(user.id))
            };

            // ── Step 5: Issue access token ──
            let token_svc = state.token_service_for_realm(client.realm_id).await?;
            let access_token = token_svc
                .issue_access_token(
                    &subject,
                    &client.client_id,
                    &effective_scopes,
                    dpop_jkt,
                    None,
                    None,
                )
                .await?;

            let access_hash = sha2_256_hex(&access_token);
            let now_time = chrono::Utc::now();

            // ── Step 6: Create session record ──
            let session = Session {
                id: generate_uuid_v7(),
                sid: oidc_core::utils::generate_sid().unwrap_or_default(),
                user_id,
                realm_id: client.realm_id,
                client_id: client.id,
                grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
                access_token_hash: access_hash,
                refresh_token_hash: None, // No refresh token for JWT bearer grant
                id_token_jti: None,       // No ID token for JWT bearer grant
                scope: effective_scopes.clone(),
                revoked: false,
                expires_at: now_time + chrono::Duration::minutes(15),
                refresh_expires_at: None,
                created_at: now_time,
                last_used_at: None,
                token_family_id: None,
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
                "scope": effective_scopes.join(" "),
            }))
        })
    }
}
