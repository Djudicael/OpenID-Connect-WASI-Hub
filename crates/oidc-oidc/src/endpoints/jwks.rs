use axum::Json;
use serde_json::Value;

use crate::state::OidcState;

/// JWKS endpoint handler.
pub async fn jwks_handler(state: OidcState) -> Result<Json<Value>, oidc_core::OidcError> {
    let jwks = state.token_service.jwks()?;
    Ok(Json(serde_json::to_value(jwks)
        .map_err(|e| oidc_core::OidcError::Internal(format!("jwks serialize: {e}")))?))
}
