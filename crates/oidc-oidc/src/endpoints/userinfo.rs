//! UserInfo endpoint handler.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use oidc_core::traits::TokenService;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::repositories::user_repo::UserRepo;

use crate::state::OidcState;
use crate::tokens::dpop::verify_dpop_proof;

/// UserInfo endpoint handler.
/// Returns claims scoped to the access token's granted scopes.
/// Per RFC 6750, returns 401 with `WWW-Authenticate: Bearer error="invalid_token"`
/// when the token is missing or invalid.
///
/// When the access token is DPoP-bound (has a `cnf.jkt` claim), the `DPoP`
/// header must be present and valid per RFC 9449. The proof's `jwk_thumbprint`
/// must match the `cnf.jkt` in the token, and the `ath` must match the
/// SHA-256 hash of the access token.
pub async fn userinfo_handler(
    State(state): State<OidcState>,
    authorization: Option<axum::http::HeaderValue>,
    dpop_header: Option<axum::http::HeaderValue>,
) -> Response {
    let token = match extract_bearer_token(authorization) {
        Ok(t) => t,
        Err(()) => return unauthorized_response(None),
    };

    // Verify the access token and extract full claims (including cnf for DPoP)
    let claims = match state
        .token_service
        .verify_access_token_with_claims(&token)
        .await
    {
        Ok(c) => c,
        Err(_) => return unauthorized_response(None),
    };

    // ── DPoP validation for sender-constrained tokens (RFC 9449) ──────────
    if let Some(ref cnf) = claims.cnf {
        // Token is DPoP-bound — the DPoP proof is required
        let jkt = cnf.get("jkt").and_then(|v| v.as_str()).unwrap_or("");

        if jkt.is_empty() {
            return unauthorized_response(Some("DPoP-bound token has no jkt"));
        }

        let dpop_value = match dpop_header {
            Some(ref h) => match h.to_str() {
                Ok(v) => v,
                Err(_) => return unauthorized_response(Some("DPoP header is not valid UTF-8")),
            },
            None => return unauthorized_response(Some("DPoP proof required for DPoP-bound token")),
        };

        let userinfo_endpoint = format!("{}/oidc/userinfo", state.issuer);
        let now = chrono::Utc::now().timestamp();

        let proof =
            match verify_dpop_proof(dpop_value, "GET", &userinfo_endpoint, Some(&token), now) {
                Ok(p) => p,
                Err(_) => return unauthorized_response(Some("Invalid DPoP proof")),
            };

        // The thumbprint in the proof must match the cnf.jkt in the token
        if proof.jwk_thumbprint != jkt {
            return unauthorized_response(Some("DPoP proof key does not match token binding"));
        }
    }

    let user_id = match claims.sub.parse() {
        Ok(id) => id,
        Err(_) => return unauthorized_response(None),
    };

    let mut conn = match state.connect().await {
        Ok(c) => c,
        Err(_) => return internal_error_response(),
    };

    // Look up the session to get granted scopes
    let access_hash = oidc_core::utils::sha2_256_hex(&token);
    let session = match SessionRepo
        .find_by_access_token_hash(&mut conn, &access_hash)
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => return unauthorized_response(None),
        Err(_) => return internal_error_response(),
    };

    if session.revoked {
        return unauthorized_response(None);
    }

    let user = match UserRepo.find_by_id(&mut conn, user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return unauthorized_response(None),
        Err(_) => return internal_error_response(),
    };

    let scopes: std::collections::HashSet<String> = session.scope.into_iter().collect();

    let mut claims = json!({
        "sub": user.id.to_string(),
    });

    if scopes.contains("email") {
        if let Some(obj) = claims.as_object_mut() {
            obj.insert("email".to_string(), json!(user.email));
            obj.insert("email_verified".to_string(), json!(user.email_verified));
        }
    }

    if scopes.contains("profile") {
        if let Some(obj) = claims.as_object_mut() {
            if let Some(ref name) = user.given_name {
                obj.insert("given_name".to_string(), json!(name));
            }
            if let Some(ref name) = user.family_name {
                obj.insert("family_name".to_string(), json!(name));
            }
            if let Some(ref name) = user.middle_name {
                obj.insert("middle_name".to_string(), json!(name));
            }
            if let Some(ref name) = user.username {
                obj.insert("name".to_string(), json!(name));
            }
            if let Some(ref v) = user.nickname {
                obj.insert("nickname".to_string(), json!(v));
            }
            if let Some(ref v) = user.preferred_username {
                obj.insert("preferred_username".to_string(), json!(v));
            }
            if let Some(ref v) = user.profile {
                obj.insert("profile".to_string(), json!(v));
            }
            if let Some(ref v) = user.picture {
                obj.insert("picture".to_string(), json!(v));
            }
            if let Some(ref v) = user.website {
                obj.insert("website".to_string(), json!(v));
            }
            if let Some(ref v) = user.gender {
                obj.insert("gender".to_string(), json!(v));
            }
            if let Some(ref v) = user.birthdate {
                obj.insert("birthdate".to_string(), json!(v));
            }
            if let Some(ref v) = user.zoneinfo {
                obj.insert("zoneinfo".to_string(), json!(v));
            }
            obj.insert("locale".to_string(), json!(user.locale));
            obj.insert("updated_at".to_string(), json!(user.updated_at.timestamp()));
        }
    }

    if scopes.contains("phone") {
        if let Some(obj) = claims.as_object_mut() {
            if let Some(ref v) = user.phone_number {
                obj.insert("phone_number".to_string(), json!(v));
            }
            if let Some(v) = user.phone_number_verified {
                obj.insert("phone_number_verified".to_string(), json!(v));
            }
        }
    }

    Json(claims).into_response()
}

/// Build a 401 Unauthorized response with the required `WWW-Authenticate` header.
///
/// Per RFC 6750 §3, the error response MUST include:
/// `WWW-Authenticate: Bearer error="invalid_token"`
///
/// When `detail` is provided, it is included as `error_description`.
fn unauthorized_response(detail: Option<&str>) -> Response {
    let error_description = detail.unwrap_or("The access token is missing, invalid, or expired.");

    let mut response = (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({
            "error": "invalid_token",
            "error_description": error_description,
        })),
    )
        .into_response();

    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer error=\"invalid_token\""),
    );

    response
}

/// Build a 500 Internal Server Error response.
fn internal_error_response() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(json!({
            "error": "server_error",
            "error_description": "An internal error occurred."
        })),
    )
        .into_response()
}

fn extract_bearer_token(header: Option<axum::http::HeaderValue>) -> Result<String, ()> {
    let header = header.ok_or(())?;
    let header_str = header.to_str().map_err(|_| ())?;
    let token = header_str
        .strip_prefix("Bearer ")
        .or_else(|| header_str.strip_prefix("bearer "))
        .ok_or(())?;
    Ok(token.to_string())
}
