//! Back-Channel Logout (OIDC Back-Channel Logout §7).
//!
//! When a session is terminated, the OP sends a signed logout token via
//! HTTP POST to each RP's `backchannel_logout_uri`. The logout token is
//! a JWT with the following claims:
//!
//! - `iss`: The OP issuer URL
//! - `sub`: The subject (user ID)
//! - `aud`: The client_id of the RP
//! - `iat`: Issued at timestamp
//! - `jti`: Unique token ID (for replay protection)
//! - `events`: `{"http://schemas.openid.net/event/backchannel-logout": {}}`
//! - `sid`: The OIDC session ID (if `backchannel_logout_session_required` is true)
//!
//! The RP must validate the token signature, verify the `events` claim,
//! and log out the user session identified by `sub` and/or `sid`.

use oidc_core::OidcError;
use oidc_core::models::Client;
use oidc_core::utils::generate_uuid_v7;
use serde::Serialize;

use crate::tokens::JwtTokenService;

/// Logout token claims per Back-Channel Logout §2.1.
#[derive(Debug, Serialize)]
pub struct LogoutTokenClaims {
    /// Issuer — the OP's issuer URL.
    pub iss: String,
    /// Subject — the user's identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Audience — the client_id of the RP.
    pub aud: String,
    /// Issued at timestamp (seconds since epoch).
    pub iat: i64,
    /// JWT ID — unique identifier for replay protection.
    pub jti: String,
    /// Events claim — must contain the backchannel-logout event type.
    pub events: serde_json::Value,
    /// Session ID — the OIDC session ID (optional, per client config).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
}

/// Result of a back-channel logout attempt for a single client.
#[derive(Debug)]
pub struct BackchannelLogoutResult {
    /// The client_id of the RP.
    pub client_id: String,
    /// The backchannel_logout_uri that was called.
    pub uri: String,
    /// Whether the logout token was successfully delivered.
    pub success: bool,
    /// HTTP status code from the RP (if the request was made).
    pub status: Option<u16>,
    /// Error message (if the delivery failed).
    pub error: Option<String>,
}

/// Issue a signed logout token for a client.
///
/// The logout token is a JWT signed with the OP's signing key (RS256 or EdDSA).
/// Per Back-Channel Logout §2.1, it MUST contain:
/// - `iss`, `aud`, `iat`, `jti`, `events`
/// - `sid` if `backchannel_logout_session_required` is true
/// - `sub` if the subject is known
pub fn issue_logout_token(
    token_service: &JwtTokenService,
    issuer: &str,
    subject: &str,
    audience: &str,
    sid: &str,
    include_sid: bool,
) -> Result<String, OidcError> {
    let now = chrono::Utc::now().timestamp();
    let claims = LogoutTokenClaims {
        iss: issuer.to_string(),
        sub: Some(subject.to_string()),
        aud: audience.to_string(),
        iat: now,
        jti: generate_uuid_v7().to_string(),
        events: serde_json::json!({
            "http://schemas.openid.net/event/backchannel-logout": {}
        }),
        sid: if include_sid {
            Some(sid.to_string())
        } else {
            None
        },
    };

    // Encode and sign the logout token using the same JWT infrastructure
    token_service.encode_logout_token(&claims)
}

/// Send a back-channel logout token to a client's `backchannel_logout_uri`.
///
/// Per Back-Channel Logout §7, the OP sends the logout token via HTTP POST
/// with `Content-Type: application/x-www-form-urlencoded` and the token
/// in the `logout_token` form parameter.
///
/// In WASI Preview 2, we use `wstd::http::Client` for outbound HTTP.
/// If the HTTP client is not available (e.g., in test environments),
/// the delivery is skipped and logged as a warning.
pub async fn send_backchannel_logout(uri: &str, logout_token: &str) -> BackchannelLogoutResult {
    // Send the logout token via HTTP POST
    // In WASI P2, we use wstd's HTTP client for outbound requests
    let result = send_logout_token_http(uri, logout_token).await;

    match result {
        Ok(status) => BackchannelLogoutResult {
            client_id: String::new(), // filled in by caller
            uri: uri.to_string(),
            success: status == 200 || status == 204,
            status: Some(status),
            error: if status == 200 || status == 204 {
                None
            } else {
                Some(format!("RP returned HTTP {}", status))
            },
        },
        Err(e) => BackchannelLogoutResult {
            client_id: String::new(), // filled in by caller
            uri: uri.to_string(),
            success: false,
            status: None,
            error: Some(e),
        },
    }
}

/// Send a logout token via HTTP POST to the RP's backchannel_logout_uri.
///
/// The request uses `Content-Type: application/x-www-form-urlencoded`
/// with the `logout_token` parameter per Back-Channel Logout §7.
///
/// On native targets, uses `reqwest`. On WASI, uses `wstd` HTTP client.
async fn send_logout_token_http(uri: &str, logout_token: &str) -> Result<u16, String> {
    // Build the form body
    let body = format!("logout_token={}", urlencoding::encode(logout_token));

    #[cfg(not(target_arch = "wasm32"))]
    {
        let client = reqwest::Client::new();
        let response = client
            .post(uri)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {e}"))?;
        Ok(response.status().as_u16())
    }

    #[cfg(target_arch = "wasm32")]
    {
        let request = wstd::http::Request::post(uri)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(wstd::http::Body::from(body))
            .map_err(|e| format!("Failed to build request: {e}"))?;

        let client = wstd::http::Client::new();
        let response = client
            .send(request)
            .await
            .map_err(|e| format!("HTTP request failed: {e}"))?;

        Ok(response.status().as_u16())
    }
}

/// Perform back-channel logout for all clients of a user session.
///
/// For each client that has a `backchannel_logout_uri` configured:
/// 1. Issue a signed logout token
/// 2. Send it via HTTP POST to the client's `backchannel_logout_uri`
///
/// Returns the results for each client.
pub async fn perform_backchannel_logout(
    token_service: &JwtTokenService,
    issuer: &str,
    subject: &str,
    sid: &str,
    clients: &[&Client],
) -> Vec<BackchannelLogoutResult> {
    let mut results = Vec::new();

    for client in clients {
        if let Some(ref uri) = client.backchannel_logout_uri {
            let include_sid = client.backchannel_logout_session_required;

            match issue_logout_token(
                token_service,
                issuer,
                subject,
                &client.client_id,
                sid,
                include_sid,
            ) {
                Ok(logout_token) => {
                    let mut result = send_backchannel_logout(uri, &logout_token).await;
                    result.client_id = client.client_id.clone();
                    results.push(result);
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to issue logout token for client {}: {e}",
                        client.client_id
                    );
                    results.push(BackchannelLogoutResult {
                        client_id: client.client_id.clone(),
                        uri: uri.clone(),
                        success: false,
                        status: None,
                        error: Some(format!("Token issuance failed: {e}")),
                    });
                }
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logout_token_claims_serialization() {
        let claims = LogoutTokenClaims {
            iss: "https://op.example.com".to_string(),
            sub: Some("user123".to_string()),
            aud: "client456".to_string(),
            iat: 1700000000,
            jti: "unique-jti-123".to_string(),
            events: serde_json::json!({
                "http://schemas.openid.net/event/backchannel-logout": {}
            }),
            sid: Some("sid789".to_string()),
        };

        let json = serde_json::to_value(&claims).unwrap();
        assert_eq!(json["iss"], "https://op.example.com");
        assert_eq!(json["sub"], "user123");
        assert_eq!(json["aud"], "client456");
        assert_eq!(json["iat"], 1700000000);
        assert_eq!(json["jti"], "unique-jti-123");
        assert!(json["events"]["http://schemas.openid.net/event/backchannel-logout"].is_object());
        assert_eq!(json["sid"], "sid789");
    }

    #[test]
    fn test_logout_token_claims_without_sid() {
        let claims = LogoutTokenClaims {
            iss: "https://op.example.com".to_string(),
            sub: Some("user123".to_string()),
            aud: "client456".to_string(),
            iat: 1700000000,
            jti: "unique-jti-123".to_string(),
            events: serde_json::json!({
                "http://schemas.openid.net/event/backchannel-logout": {}
            }),
            sid: None,
        };

        let json = serde_json::to_value(&claims).unwrap();
        assert!(json.get("sid").is_none(), "sid should be omitted when None");
    }

    #[test]
    fn test_logout_token_events_claim_structure() {
        let claims = LogoutTokenClaims {
            iss: "https://op.example.com".to_string(),
            sub: None,
            aud: "client456".to_string(),
            iat: 1700000000,
            jti: "unique-jti-123".to_string(),
            events: serde_json::json!({
                "http://schemas.openid.net/event/backchannel-logout": {}
            }),
            sid: None,
        };

        let json = serde_json::to_value(&claims).unwrap();
        let events = &json["events"];
        assert!(
            events["http://schemas.openid.net/event/backchannel-logout"].is_object(),
            "events claim must contain the backchannel-logout event type"
        );
    }
}
