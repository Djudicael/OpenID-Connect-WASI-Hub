//! OIDC request validation helpers.

use oidc_core::OidcError;
use url::Url;

/// Validate a redirect URI is a valid URL and matches one of the allowed URIs.
pub fn validate_redirect_uri(uri: &str, allowed_uris: &[String]) -> Result<(), OidcError> {
    if uri.is_empty() {
        return Err(OidcError::InvalidRequest);
    }

    // Must be a valid URL
    let _ = Url::parse(uri).map_err(|_| OidcError::InvalidRequest)?;

    // Must match one of the allowed URIs exactly
    if !allowed_uris.contains(&uri.to_string()) {
        return Err(OidcError::InvalidRequest);
    }

    Ok(())
}

/// Validate a scope string against allowed scopes.
pub fn validate_scope(scope: &str, allowed: &[String]) -> Result<Vec<String>, OidcError> {
    if scope.is_empty() {
        return Ok(vec!["openid".to_string()]);
    }

    let requested: Vec<String> = scope.split(' ').map(|s| s.to_string()).collect();

    for s in &requested {
        if !allowed.contains(s) {
            return Err(OidcError::InvalidScope(format!("scope '{s}' is not allowed")));
        }
    }

    Ok(requested)
}

/// Validate a response type.
pub fn validate_response_type(response_type: &str) -> Result<(), OidcError> {
    match response_type {
        "code" | "id_token" | "code id_token" | "token" | "code token" | "id_token token" | "code id_token token" => Ok(()),
        _ => Err(OidcError::InvalidRequest),
    }
}

/// Validate a grant type.
pub fn validate_grant_type(grant_type: &str) -> Result<(), OidcError> {
    match grant_type {
        "authorization_code" | "client_credentials" | "refresh_token" => Ok(()),
        _ => Err(OidcError::UnsupportedGrantType),
    }
}

/// Validate PKCE code challenge format.
pub fn validate_code_challenge(challenge: &str) -> Result<(), OidcError> {
    if challenge.len() < 43 || challenge.len() > 128 {
        return Err(OidcError::InvalidRequest);
    }
    // Must be base64url-safe characters
    if !challenge.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' ) {
        return Err(OidcError::InvalidRequest);
    }
    Ok(())
}

/// Validate PKCE code challenge method.
pub fn validate_code_challenge_method(method: &str) -> Result<(), OidcError> {
    match method {
        "S256" | "plain" => Ok(()),
        _ => Err(OidcError::InvalidRequest),
    }
}
