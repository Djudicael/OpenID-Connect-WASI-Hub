use axum::Json;
use base64::Engine;
use serde_json::{Value, json};
use uuid::Uuid;

use oidc_core::OidcError;
use oidc_core::models::{Client, ClientType};
use oidc_repository::mapper::pg_err;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::with_transaction;

use crate::state::OidcState;

/// Supported grant types per RFC 7591.
const SUPPORTED_GRANT_TYPES: &[&str] =
    &["authorization_code", "client_credentials", "refresh_token"];

/// Supported token endpoint authentication methods per RFC 7591.
const SUPPORTED_AUTH_METHODS: &[&str] = &["client_secret_basic", "client_secret_post", "none"];

/// Request body for dynamic client registration (RFC 7591).
#[derive(Debug, serde::Deserialize)]
pub struct RegisterClientRequest {
    /// Human-readable client name. Must be non-empty.
    pub client_name: String,
    /// Redirect URIs. Must be non-empty; each must be a valid HTTPS URL
    /// (or http://localhost for development).
    pub redirect_uris: Vec<String>,
    /// Grant types requested. Must be from the supported set.
    pub grant_types: Vec<String>,
    /// Space-separated scope string.
    pub scope: String,
    /// Token endpoint authentication method. Must be from the supported set.
    pub token_endpoint_auth_method: String,
    /// The realm this client belongs to. Required — the caller must
    /// explicitly specify the target realm.
    pub realm_id: Uuid,
}

/// Validate a single redirect URI per RFC 7591 §2:
/// - Must be a valid absolute URL
/// - Must use HTTPS, **or** http with loopback host (localhost / 127.0.0.1)
fn validate_redirect_uri(uri: &str) -> Result<(), OidcError> {
    let parsed = url::Url::parse(uri)
        .map_err(|_| OidcError::InvalidInput(format!("invalid redirect URI: {uri}")))?;

    let scheme = parsed.scheme();
    if scheme == "https" {
        return Ok(());
    }

    // Allow http://localhost and http://127.0.0.1 for development
    if scheme == "http" {
        if let Some(host) = parsed.host_str() {
            if host == "localhost" || host == "127.0.0.1" || host == "[::1]" {
                return Ok(());
            }
        }
    }

    Err(OidcError::InvalidInput(format!(
        "redirect URI must use HTTPS (or http://localhost for development): {uri}"
    )))
}

/// Validate the full `RegisterClientRequest` payload.
fn validate_registration_request(req: &RegisterClientRequest) -> Result<(), OidcError> {
    // client_name must be non-empty
    if req.client_name.trim().is_empty() {
        return Err(OidcError::InvalidInput(
            "client_name must not be empty".into(),
        ));
    }

    // redirect_uris must be non-empty
    if req.redirect_uris.is_empty() {
        return Err(OidcError::InvalidInput(
            "redirect_uris must not be empty".into(),
        ));
    }
    for uri in &req.redirect_uris {
        validate_redirect_uri(uri)?;
    }

    // grant_types must be non-empty and from supported set
    if req.grant_types.is_empty() {
        return Err(OidcError::InvalidInput(
            "grant_types must not be empty".into(),
        ));
    }
    for gt in &req.grant_types {
        if !SUPPORTED_GRANT_TYPES.contains(&gt.as_str()) {
            return Err(OidcError::InvalidInput(format!(
                "unsupported grant_type: {gt}. Supported: {}",
                SUPPORTED_GRANT_TYPES.join(", ")
            )));
        }
    }

    // token_endpoint_auth_method must be from supported set
    if !SUPPORTED_AUTH_METHODS.contains(&req.token_endpoint_auth_method.as_str()) {
        return Err(OidcError::InvalidInput(format!(
            "unsupported token_endpoint_auth_method: {}. Supported: {}",
            req.token_endpoint_auth_method,
            SUPPORTED_AUTH_METHODS.join(", ")
        )));
    }

    Ok(())
}

/// Register a new OAuth2/OIDC client (RFC 7591).
///
/// **Authentication is required.** The caller must present a valid admin
/// API key or an OIDC access token with the `admin` scope. This is enforced
/// at the router layer via the `AdminAuth` extractor.
///
/// The `admin_realm_id` parameter is provided by the `AdminAuth` extractor
/// (populated from the API key's realm). If the authenticated admin is an
/// API key, the client's `realm_id` must match the API key's realm unless
/// the key has wildcard scope. For JWT-based auth, `realm_id` must be
/// specified in the request body.
pub async fn register_handler(
    state: OidcState,
    admin_realm_id: Option<Uuid>,
    Json(req): Json<RegisterClientRequest>,
) -> Result<Json<Value>, OidcError> {
    // ── Input validation ────────────────────────────────────────────────
    validate_registration_request(&req)?;

    // ── Realm authorization ─────────────────────────────────────────────
    // If the admin authenticated via API key, enforce that the requested
    // realm matches the key's realm (unless the key has wildcard scope,
    // which is checked by the caller at the router level if needed).
    // For now, if admin_realm_id is present, we use it as the authoritative
    // realm and ignore the request body's realm_id to prevent cross-realm
    // client creation.
    let realm_id = admin_realm_id.unwrap_or(req.realm_id);
    let client_id = format!("client_{}", Uuid::new_v4().to_string().replace("-", ""));

    let (client_type, client_secret, client_secret_hash) =
        match req.token_endpoint_auth_method.as_str() {
            "client_secret_basic" | "client_secret_post" => {
                let mut secret_bytes = [0u8; 32];
                getrandom::fill(&mut secret_bytes)
                    .map_err(|e| OidcError::Internal(e.to_string()))?;
                let secret = base64::engine::general_purpose::STANDARD.encode(&secret_bytes);
                let hash = state.hasher.hash(&secret)?;
                (ClientType::Confidential, Some(secret), Some(hash))
            }
            _ => (ClientType::Public, None, None),
        };

    // ── Persist client ──────────────────────────────────────────────────
    let mut conn = state.connect().await?;
    let client = Client {
        id: Uuid::new_v4(),
        realm_id,
        client_id: client_id.clone(),
        client_type,
        client_secret_hash,
        name: req.client_name,
        redirect_uris: req.redirect_uris,
        allowed_scopes: req
            .scope
            .split_whitespace()
            .map(|s| s.to_string())
            .collect(),
        allowed_grant_types: req.grant_types,
        pkce_required: true,
        enabled: true,
        deleted_at: None,
    };

    with_transaction!(conn, pg_err, {
        ClientRepo.create(&mut conn, &client).await
    })?;

    // ── Response (RFC 7591 §3.2) ────────────────────────────────────────
    let mut response = json!({
        "client_id": client_id,
        "client_name": client.name,
        "redirect_uris": client.redirect_uris,
        "grant_types": client.allowed_grant_types,
        "scope": client.allowed_scopes.join(" "),
        "token_endpoint_auth_method": req.token_endpoint_auth_method,
    });

    if let Some(secret) = client_secret {
        response["client_secret"] = json!(secret);
    }

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_request() -> RegisterClientRequest {
        RegisterClientRequest {
            client_name: "Test Client".into(),
            redirect_uris: vec!["https://example.com/callback".into()],
            grant_types: vec!["authorization_code".into()],
            scope: "openid profile".into(),
            token_endpoint_auth_method: "client_secret_basic".into(),
            realm_id: Uuid::new_v4(),
        }
    }

    #[test]
    fn test_validate_valid_request() {
        let req = valid_request();
        assert!(validate_registration_request(&req).is_ok());
    }

    #[test]
    fn test_validate_empty_client_name() {
        let mut req = valid_request();
        req.client_name = "  ".into();
        let err = validate_registration_request(&req).unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("client_name")));
    }

    #[test]
    fn test_validate_empty_redirect_uris() {
        let mut req = valid_request();
        req.redirect_uris = vec![];
        let err = validate_registration_request(&req).unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("redirect_uris")));
    }

    #[test]
    fn test_validate_http_redirect_uri_rejected() {
        let mut req = valid_request();
        req.redirect_uris = vec!["http://evil.com/callback".into()];
        let err = validate_registration_request(&req).unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("HTTPS")));
    }

    #[test]
    fn test_validate_localhost_redirect_uri_allowed() {
        let mut req = valid_request();
        req.redirect_uris = vec!["http://localhost:3000/callback".into()];
        assert!(validate_registration_request(&req).is_ok());
    }

    #[test]
    fn test_validate_loopback_ipv4_redirect_uri_allowed() {
        let mut req = valid_request();
        req.redirect_uris = vec!["http://127.0.0.1:3000/callback".into()];
        assert!(validate_registration_request(&req).is_ok());
    }

    #[test]
    fn test_validate_loopback_ipv6_redirect_uri_allowed() {
        let mut req = valid_request();
        req.redirect_uris = vec!["http://[::1]:3000/callback".into()];
        assert!(validate_registration_request(&req).is_ok());
    }

    #[test]
    fn test_validate_empty_grant_types() {
        let mut req = valid_request();
        req.grant_types = vec![];
        let err = validate_registration_request(&req).unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("grant_types")));
    }

    #[test]
    fn test_validate_unsupported_grant_type() {
        let mut req = valid_request();
        req.grant_types = vec!["implicit".into()];
        let err = validate_registration_request(&req).unwrap_err();
        assert!(
            matches!(err, OidcError::InvalidInput(ref s) if s.contains("unsupported grant_type"))
        );
    }

    #[test]
    fn test_validate_unsupported_auth_method() {
        let mut req = valid_request();
        req.token_endpoint_auth_method = "client_secret_jwt".into();
        let err = validate_registration_request(&req).unwrap_err();
        assert!(
            matches!(err, OidcError::InvalidInput(ref s) if s.contains("unsupported token_endpoint_auth_method"))
        );
    }

    #[test]
    fn test_validate_supported_auth_methods() {
        for method in &["client_secret_basic", "client_secret_post", "none"] {
            let mut req = valid_request();
            req.token_endpoint_auth_method = method.to_string();
            if *method == "none" {
                req.grant_types = vec!["authorization_code".into()];
            }
            assert!(validate_registration_request(&req).is_ok());
        }
    }

    #[test]
    fn test_validate_all_supported_grant_types() {
        for gt in &["authorization_code", "client_credentials", "refresh_token"] {
            let mut req = valid_request();
            req.grant_types = vec![gt.to_string()];
            assert!(validate_registration_request(&req).is_ok());
        }
    }

    #[test]
    fn test_validate_invalid_url_redirect_uri() {
        let mut req = valid_request();
        req.redirect_uris = vec!["not-a-url".into()];
        let err = validate_registration_request(&req).unwrap_err();
        assert!(
            matches!(err, OidcError::InvalidInput(ref s) if s.contains("invalid redirect URI"))
        );
    }

    #[test]
    fn test_validate_realm_id_required() {
        let req = valid_request();
        // realm_id is now a required field — it's always present
        assert!(validate_registration_request(&req).is_ok());
    }

    #[test]
    fn test_validate_realm_id_explicit() {
        let mut req = valid_request();
        req.realm_id = Uuid::new_v4();
        assert!(validate_registration_request(&req).is_ok());
    }
}
