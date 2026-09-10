//! Client Credentials flow.

use oidc_core::OidcError;
use oidc_core::models::Session;
use oidc_core::traits::token_service::{AccessTokenExtraClaims, TokenService};
use oidc_core::utils::{generate_uuid_v7, sha2_256_hex};
use oidc_repository::mapper::pg_err;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::with_transaction;
use serde_json::{Value, json};

use crate::state::OidcState;

/// Client Credentials flow handler.
pub struct ClientCredentialsFlow;

impl ClientCredentialsFlow {
    /// Execute the client credentials flow.
    ///
    /// When `dpop_jkt` is provided, the access token is bound to the DPoP
    /// key via a `cnf.jkt` claim and `token_type` is `"DPoP"` (RFC 9449).
    pub async fn execute(
        state: &OidcState,
        client: &oidc_core::models::Client,
        requested_scopes: &[String],
        dpop_jkt: Option<&str>,
    ) -> Result<Value, OidcError> {
        let mut conn = state.connect().await?;

        with_transaction!(conn, pg_err, {
            if !client.enabled {
                return Err(OidcError::InvalidClient);
            }
            if requested_scopes
                .iter()
                .any(|scope| scope == "offline_access")
            {
                return Err(OidcError::InvalidScope(
                    "offline_access requires an end-user authorization code flow".into(),
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
            let mapped_claims =
                crate::protocol_mappers::resolve_mapped_claims(&mut conn, client.id, None, &scopes)
                    .await?;

            let token_svc = state.token_service_for_realm(client.realm_id).await?;
            let access_token = token_svc
                .issue_access_token_with_extra(
                    &client.client_id,
                    &client.client_id,
                    &scopes,
                    dpop_jkt,
                    None,
                    None,
                    Some(AccessTokenExtraClaims {
                        custom_claims: mapped_claims.access_token,
                        additional_audiences: mapped_claims.access_audiences,
                        ..Default::default()
                    }),
                )
                .await?;

            let access_hash = sha2_256_hex(&access_token);
            let now = chrono::Utc::now();

            // Create a session record so the token can be introspected and revoked.
            // Client credentials have no end-user, so user_id is NULL.
            let session = Session {
                id: generate_uuid_v7(),
                sid: oidc_core::utils::generate_sid().unwrap_or_default(),
                user_id: None, // no end-user for client_credentials
                realm_id: client.realm_id,
                client_id: client.id,
                grant_type: "client_credentials".to_string(),
                access_token_hash: access_hash,
                refresh_token_hash: None, // No refresh token for client credentials
                id_token_jti: None,
                scope: scopes.clone(),
                revoked: false,
                expires_at: now + chrono::Duration::minutes(15),
                refresh_expires_at: None,
                offline_session: false,
                offline_max_expires_at: None,
                created_at: now,
                last_used_at: None,
                token_family_id: None,
                previous_session_id: None,
                rotated_at: None,
                reused_at: None,
                family_revoked: false,
                authorization_details: None,
                resource: vec![],
                acr: oidc_core::utils::ACR_BRONZE.to_string(),
                amr: vec!["client_secret".to_string()],
            };

            SessionRepo.create(&mut conn, &session).await?;

            let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };

            Ok(json!({
                "access_token": access_token,
                "token_type": token_type,
                "expires_in": 900,
                "scope": scopes.join(" "),
            }))
        })
    }
}
