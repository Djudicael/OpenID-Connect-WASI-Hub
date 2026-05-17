use axum::Json;
use serde_json::{Map, Value, json};

use oidc_core::models::ResponseType;

use crate::state::OidcState;

/// Build a `serde_json::Map<String, Value>` from key-value pairs.
///
/// This helper avoids the deep macro recursion of a single `json!({ ... })`
/// call with dozens of fields, which would otherwise require
/// `#![recursion_limit = "512"]`.
macro_rules! discovery_map {
    ($($key:expr => $val:expr),* $(,)?) => {{
        let mut m = Map::new();
        $(
            m.insert($key.into(), $val);
        )*
        m
    }};
}

/// OIDC Discovery document handler.
/// Returns a complete discovery document per OpenID Connect Discovery 1.0.
pub async fn discovery_handler(state: OidcState) -> Json<Value> {
    let response_types: Vec<String> = ResponseType::ALL_SUPPORTED
        .iter()
        .map(|rt| rt.to_string())
        .collect();
    let issuer = &state.issuer;

    let m = discovery_map! {
        "issuer" => json!(issuer),
        "authorization_endpoint" => json!(format!("{issuer}/oidc/authorize")),
        "token_endpoint" => json!(format!("{issuer}/oidc/token")),
        "userinfo_endpoint" => json!(format!("{issuer}/oidc/userinfo")),
        "jwks_uri" => json!(format!("{issuer}/oidc/jwks")),
        "pushed_authorization_request_endpoint" => json!(format!("{issuer}/oidc/par")),
        "device_authorization_endpoint" => json!(format!("{issuer}/oidc/device/authorize")),
        "password_reset_endpoint" => json!(format!("{issuer}/oidc/password-reset/request")),
        "email_verification_endpoint" => json!(format!("{issuer}/oidc/email-verification/request")),
        "registration_endpoint" => json!(format!("{issuer}/oidc/register")),
        "end_session_endpoint" => json!(format!("{issuer}/oidc/logout")),
        "frontchannel_logout_supported" => json!(true),
        "frontchannel_logout_session_supported" => json!(true),
        "backchannel_logout_supported" => json!(true),
        "backchannel_logout_session_supported" => json!(true),
        "scopes_supported" => json!(["openid", "profile", "email", "phone", "address", "offline_access"]),
        "response_types_supported" => json!(response_types),
        "grant_types_supported" => json!([
            "authorization_code", "client_credentials", "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "urn:ietf:params:oauth:grant-type:token-exchange"
        ]),
        "token_endpoint_auth_methods_supported" => json!([
            "client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt"
        ]),
        "token_endpoint_auth_signing_alg_values_supported" => json!(["HS256", "HS384", "HS512", "RS256", "EdDSA"]),
        "subject_types_supported" => json!(["public", "pairwise"]),
        "id_token_signing_alg_values_supported" => json!(["RS256", "EdDSA"]),
        "id_token_encryption_alg_values_supported" => json!(["dir", "RSA-OAEP-256"]),
        "id_token_encryption_enc_values_supported" => json!(["A256GCM"]),
        "dpop_signing_alg_values_supported" => json!(["RS256", "EdDSA"]),
        "account_recovery_endpoint" => json!(format!("{issuer}/oidc/account-recovery/confirm")),
        "claims_supported" => json!([
            "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash", "c_hash",
            "sid", "acr", "amr", "azp", "roles", "groups",
            "name", "given_name", "family_name", "middle_name", "nickname", "preferred_username",
            "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale",
            "email", "email_verified",
            "phone_number", "phone_number_verified",
            "address",
            "updated_at"
        ]),
        "acr_values_supported" => json!(["urn:mace:incommon:iap:bronze", "urn:mace:incommon:iap:silver"]),
        "amr_values_supported" => json!(["pwd", "mfa", "otp", "sms", "device_code", "token_exchange", "social"]),
        "claims_locales_supported" => json!(["en", "fr", "de", "es"]),
        "display_values_supported" => json!(["page", "popup", "touch", "wap"]),
        "claims_parameter_supported" => json!(true),
        "request_parameter_supported" => json!(true),
        "request_object_signing_alg_values_supported" => json!(["RS256", "EdDSA"]),
        "request_object_encryption_alg_values_supported" => json!(["dir", "RSA-OAEP-256"]),
        "request_object_encryption_enc_values_supported" => json!(["A256GCM"]),
        "token_exchange_endpoint" => json!(format!("{issuer}/oidc/token")),
        "token_exchange_subject_token_types_supported" => json!([
            "urn:ietf:params:oauth:token-type:access_token",
            "urn:ietf:params:oauth:token-type:refresh_token",
            "urn:ietf:params:oauth:token-type:id_token"
        ]),
        "code_challenge_methods_supported" => json!(["S256"]),
        "resource_parameter_supported" => json!(true),
        "response_modes_supported" => json!([
            "query", "fragment", "form_post", "jwt", "query.jwt", "fragment.jwt", "form_post.jwt"
        ]),
        "authorization_details_types_supported" => json!(["payment_initiation", "account_information", "custom"]),
    };

    Json(Value::Object(m))
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

    let m = discovery_map! {
        "issuer" => json!(realm_base),
        "authorization_endpoint" => json!(format!("{realm_base}/protocol/openid-connect/auth")),
        "token_endpoint" => json!(format!("{realm_base}/protocol/openid-connect/token")),
        "userinfo_endpoint" => json!(format!("{realm_base}/protocol/openid-connect/userinfo")),
        "jwks_uri" => json!(format!("{}/oidc/jwks", state.issuer)),
        "pushed_authorization_request_endpoint" => json!(format!("{realm_base}/protocol/openid-connect/par")),
        "device_authorization_endpoint" => json!(format!("{realm_base}/protocol/openid-connect/device/authorize")),
        "password_reset_endpoint" => json!(format!("{realm_base}/protocol/openid-connect/password-reset/request")),
        "email_verification_endpoint" => json!(format!("{realm_base}/protocol/openid-connect/email-verification/request")),
        "registration_endpoint" => json!(format!("{realm_base}/protocol/openid-connect/register")),
        "end_session_endpoint" => json!(format!("{realm_base}/protocol/openid-connect/logout")),
        "frontchannel_logout_supported" => json!(true),
        "frontchannel_logout_session_supported" => json!(true),
        "backchannel_logout_supported" => json!(true),
        "backchannel_logout_session_supported" => json!(true),
        "scopes_supported" => json!(["openid", "profile", "email", "phone", "address", "offline_access"]),
        "response_types_supported" => json!(response_types),
        "grant_types_supported" => json!([
            "authorization_code", "client_credentials", "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "urn:ietf:params:oauth:grant-type:token-exchange"
        ]),
        "token_endpoint_auth_methods_supported" => json!([
            "client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt"
        ]),
        "token_endpoint_auth_signing_alg_values_supported" => json!(["HS256", "HS384", "HS512", "RS256", "EdDSA"]),
        "subject_types_supported" => json!(["public", "pairwise"]),
        "id_token_signing_alg_values_supported" => json!(["RS256", "EdDSA"]),
        "id_token_encryption_alg_values_supported" => json!(["dir", "RSA-OAEP-256"]),
        "id_token_encryption_enc_values_supported" => json!(["A256GCM"]),
        "dpop_signing_alg_values_supported" => json!(["RS256", "EdDSA"]),
        "account_recovery_endpoint" => json!(format!("{realm_base}/protocol/openid-connect/account-recovery/confirm")),
        "claims_supported" => json!([
            "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash", "c_hash",
            "sid", "acr", "amr", "azp", "roles", "groups",
            "name", "given_name", "family_name", "middle_name", "nickname", "preferred_username",
            "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale",
            "email", "email_verified",
            "phone_number", "phone_number_verified",
            "address",
            "updated_at"
        ]),
        "acr_values_supported" => json!(["urn:mace:incommon:iap:bronze", "urn:mace:incommon:iap:silver"]),
        "amr_values_supported" => json!(["pwd", "mfa", "otp", "sms", "device_code", "token_exchange", "social"]),
        "claims_locales_supported" => json!(["en", "fr", "de", "es"]),
        "display_values_supported" => json!(["page", "popup", "touch", "wap"]),
        "claims_parameter_supported" => json!(true),
        "request_parameter_supported" => json!(true),
        "request_object_signing_alg_values_supported" => json!(["RS256", "EdDSA"]),
        "request_object_encryption_alg_values_supported" => json!(["dir", "RSA-OAEP-256"]),
        "request_object_encryption_enc_values_supported" => json!(["A256GCM"]),
        "token_exchange_endpoint" => json!(format!("{realm_base}/protocol/openid-connect/token")),
        "token_exchange_subject_token_types_supported" => json!([
            "urn:ietf:params:oauth:token-type:access_token",
            "urn:ietf:params:oauth:token-type:refresh_token",
            "urn:ietf:params:oauth:token-type:id_token"
        ]),
        "code_challenge_methods_supported" => json!(["S256"]),
        "resource_parameter_supported" => json!(true),
        "response_modes_supported" => json!([
            "query", "fragment", "form_post", "jwt", "query.jwt", "fragment.jwt", "form_post.jwt"
        ]),
        "authorization_details_types_supported" => json!(["payment_initiation", "account_information", "custom"]),
    };

    Json(Value::Object(m))
}
