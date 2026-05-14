use axum::Json;
use serde_json::Value;

use crate::state::OidcState;

/// JWKS endpoint handler.
pub async fn jwks_handler(state: OidcState) -> Result<Json<Value>, oidc_core::OidcError> {
    let jwks = state.token_service.jwks()?;
    Ok(Json(serde_json::to_value(jwks).map_err(|e| {
        oidc_core::OidcError::Internal(format!("jwks serialize: {e}"))
    })?))
}

/// Per-realm JWKS endpoint handler.
/// Returns the realm's public signing keys (RSA + Ed25519) from the
/// realm_signing_keys table without exposing private key material.
pub async fn realm_jwks_handler(
    state: OidcState,
    realm: String,
) -> Result<Json<Value>, oidc_core::OidcError> {
    let mut conn = state.connect().await?;
    let realm_entity = match oidc_repository::repositories::realm_repo::RealmRepo
        .find_by_name(&mut conn, &realm)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return Err(oidc_core::OidcError::NotFound("realm".into())),
        Err(e) => return Err(oidc_core::OidcError::Internal(e.to_string())),
    };

    let keys = match oidc_repository::repositories::realm_signing_keys_repo::RealmSigningKeysRepo
        .find_by_realm_id(&mut conn, realm_entity.id)
        .await
    {
        Ok(Some(k)) => k,
        Ok(None) => {
            // Fallback: if no realm-specific keys exist, return global JWKS.
            let jwks = state.token_service.jwks()?;
            return Ok(Json(serde_json::to_value(jwks).map_err(|e| {
                oidc_core::OidcError::Internal(format!("jwks serialize: {e}"))
            })?));
        }
        Err(e) => return Err(oidc_core::OidcError::Internal(e.to_string())),
    };

    let jwks = crate::tokens::JwtTokenService::jwks_from_public_keys(
        &keys.rsa_kid,
        &keys.rsa_public_n,
        &keys.rsa_public_e,
        &keys.ed25519_kid,
        &keys.ed25519_public_x,
    );

    Ok(Json(serde_json::to_value(jwks).map_err(|e| {
        oidc_core::OidcError::Internal(format!("jwks serialize: {e}"))
    })?))
}
