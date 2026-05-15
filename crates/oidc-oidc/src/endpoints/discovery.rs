use axum::Json;
use serde_json::{Value, json};

use oidc_core::models::ResponseType;

use crate::state::OidcState;

/// OIDC Discovery document handler.
/// Returns a complete discovery document per OpenID Connect Discovery 1.0.
pub async fn discovery_handler(state: OidcState) -> Json<Value> {
    let response_types: Vec<String> = ResponseType::ALL_SUPPORTED
        .iter()
        .map(|rt| rt.to_string())
        .collect();
    Json(json!({
        "issuer": state.issuer,
        "authorization_endpoint": format!("{}/oidc/authorize", state.issuer),
        "token_endpoint": format!("{}/oidc/token", state.issuer),
        "userinfo_endpoint": format!("{}/oidc/userinfo", state.issuer),
        "jwks_uri": format!("{}/oidc/jwks", state.issuer),
        "pushed_authorization_request_endpoint": format!("{}/oidc/par", state.issuer),
        "password_reset_endpoint": format!("{}/oidc/password-reset/request", state.issuer),
        "email_verification_endpoint": format!("{}/oidc/email-verification/request", state.issuer),
        "registration_endpoint": format!("{}/oidc/register", state.issuer),
        "end_session_endpoint": format!("{}/oidc/logout", state.issuer),
        "check_session_iframe": format!("{}/oidc/session/check", state.issuer),
        "frontchannel_logout_supported": true,
        "frontchannel_logout_session_supported": true,
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
        "scopes_supported": ["openid", "profile", "email", "phone", "offline_access"],
        "response_types_supported": response_types,
        "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt"],
        "subject_types_supported": ["public", "pairwise"],
        "id_token_signing_alg_values_supported": ["RS256", "EdDSA"],
        "dpop_signing_alg_values_supported": ["RS256", "EdDSA"],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash", "c_hash",
            "sid", "acr", "amr",
            "name", "given_name", "family_name", "middle_name", "nickname", "preferred_username",
            "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale",
            "email", "email_verified",
            "phone_number", "phone_number_verified",
            "updated_at"
        ],
        "acr_values_supported": ["urn:mace:incommon:iap:bronze", "urn:mace:incommon:iap:silver"],
        "amr_values_supported": ["pwd"],
        "display_values_supported": ["page", "popup", "touch", "wap"],
        "claims_parameter_supported": true,
        "request_parameter_supported": true,
        "request_object_signing_alg_values_supported": ["RS256", "EdDSA"],
        "code_challenge_methods_supported": ["S256"],
    }))
}

/// Per-realm OIDC Discovery document handler.
///
/// Returns a discovery document scoped to a specific realm.
/// This is the Keycloak-compatible path: `/realms/{realm}/.well-known/openid-configuration`
pub async fn realm_discovery_handler(state: OidcState, realm: String) -> Json<Value> {
    let realm_base = format!("{}/realms/{}", state.issuer, realm);
    let response_types: Vec<String> = ResponseType::ALL_SUPPORTED
        .iter()
        .map(|rt| rt.to_string())
        .collect();
    Json(json!({
        "issuer": realm_base,
        "authorization_endpoint": format!("{}/protocol/openid-connect/auth", realm_base),
        "token_endpoint": format!("{}/protocol/openid-connect/token", realm_base),
        "userinfo_endpoint": format!("{}/protocol/openid-connect/userinfo", realm_base),
        "jwks_uri": format!("{}/oidc/jwks", state.issuer),
        "pushed_authorization_request_endpoint": format!("{}/protocol/openid-connect/par", realm_base),
        "password_reset_endpoint": format!("{}/protocol/openid-connect/password-reset/request", realm_base),
        "email_verification_endpoint": format!("{}/protocol/openid-connect/email-verification/request", realm_base),
        "registration_endpoint": format!("{}/protocol/openid-connect/register", realm_base),
        "end_session_endpoint": format!("{}/protocol/openid-connect/logout", realm_base),
        "check_session_iframe": format!("{}/protocol/openid-connect/session/check", realm_base),
        "frontchannel_logout_supported": true,
        "frontchannel_logout_session_supported": true,
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
        "scopes_supported": ["openid", "profile", "email", "phone", "offline_access"],
        "response_types_supported": response_types,
        "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt"],
        "subject_types_supported": ["public", "pairwise"],
        "id_token_signing_alg_values_supported": ["RS256", "EdDSA"],
        "dpop_signing_alg_values_supported": ["RS256", "EdDSA"],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash", "c_hash",
            "sid", "acr", "amr",
            "name", "given_name", "family_name", "middle_name", "nickname", "preferred_username",
            "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale",
            "email", "email_verified",
            "phone_number", "phone_number_verified",
            "updated_at"
        ],
        "acr_values_supported": ["urn:mace:incommon:iap:bronze", "urn:mace:incommon:iap:silver"],
        "amr_values_supported": ["pwd"],
        "display_values_supported": ["page", "popup", "touch", "wap"],
        "claims_parameter_supported": true,
        "request_parameter_supported": true,
        "request_object_signing_alg_values_supported": ["RS256", "EdDSA"],
        "code_challenge_methods_supported": ["S256"],
    }))
}
