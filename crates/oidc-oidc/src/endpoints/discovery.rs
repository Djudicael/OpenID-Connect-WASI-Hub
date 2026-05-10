use axum::Json;
use serde_json::{Value, json};

use crate::state::OidcState;

/// OIDC Discovery document handler.
/// Returns a complete discovery document per OpenID Connect Discovery 1.0.
pub async fn discovery_handler(state: OidcState) -> Json<Value> {
    Json(json!({
        "issuer": state.issuer,
        "authorization_endpoint": format!("{}/oidc/authorize", state.issuer),
        "token_endpoint": format!("{}/oidc/token", state.issuer),
        "userinfo_endpoint": format!("{}/oidc/userinfo", state.issuer),
        "jwks_uri": format!("{}/oidc/jwks", state.issuer),
        "registration_endpoint": format!("{}/oidc/register", state.issuer),
        "end_session_endpoint": format!("{}/oidc/logout", state.issuer),
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256", "EdDSA"],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat",
            "name", "given_name", "family_name",
            "email", "email_verified"
        ],
        "code_challenge_methods_supported": ["S256"],
    }))
}
