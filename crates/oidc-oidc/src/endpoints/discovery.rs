use axum::Json;
use serde_json::{json, Value};

use crate::state::OidcState;

/// OIDC Discovery document handler.
pub async fn discovery_handler(state: OidcState) -> Json<Value> {
    Json(json!({
        "issuer": state.issuer,
        "authorization_endpoint": format!("{}/oidc/authorize", state.issuer),
        "token_endpoint": format!("{}/oidc/token", state.issuer),
        "userinfo_endpoint": format!("{}/oidc/userinfo", state.issuer),
        "jwks_uri": format!("{}/oidc/jwks", state.issuer),
        "scopes_supported": ["openid", "profile", "email"],
        "response_types_supported": ["code", "id_token", "code id_token"],
        "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256", "EdDSA"],
        "code_challenge_methods_supported": ["S256"],
    }))
}
