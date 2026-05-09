//! Direct username/password login endpoint (first-party apps).

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};

use oidc_core::models::Session;
use oidc_core::models::audit_event::{ActorType, AuditEvent};
use oidc_core::traits::hasher::{Argon2idHasher, Hasher};
use oidc_core::traits::token_service::{IdTokenExtraClaims, TokenService};
use oidc_core::utils::{generate_opaque_token, generate_uuid_v7, sha2_256_hex};
use oidc_repository::repositories::audit_event_repo::AuditEventRepo;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::realm_repo::RealmRepo;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::repositories::user_repo::UserRepo;

use crate::errors::OidcErrorResponse;
use crate::state::OidcState;

/// Login request body.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub client_id: Option<String>,
}

/// Successful login response.
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub id_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub user: UserInfo,
}

/// Public user info.
#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub username: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
}

/// Direct login handler — validates credentials and returns tokens.
pub async fn login_handler(
    State(state): State<OidcState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, OidcErrorResponse> {
    // --- Input validation ---
    if req.email.is_empty() || !req.email.contains('@') {
        return Err(OidcErrorResponse::invalid_grant("Invalid credentials"));
    }
    if req.password.is_empty() || req.password.len() < 8 {
        return Err(OidcErrorResponse::invalid_grant("Invalid credentials"));
    }

    let mut conn = state.connect().await.map_err(|e| {
        tracing::error!("Internal error: {}", e);
        OidcErrorResponse::server_error("An internal error occurred")
    })?;

    // Find master realm
    let realm = RealmRepo
        .find_by_name(&mut conn, "master")
        .await
        .map_err(|e| {
            tracing::error!("Internal error: {}", e);
            OidcErrorResponse::server_error("An internal error occurred")
        })?
        .ok_or_else(|| OidcErrorResponse::server_error("Master realm not found"))?;

    if !realm.enabled {
        return Err(OidcErrorResponse::access_denied("Realm disabled"));
    }

    // --- Brute-force protection: check failed attempts ---
    let failure_count = AuditEventRepo
        .count_recent_failures(&mut conn, &req.email, realm.id)
        .await
        .map_err(|e| {
            tracing::error!("Internal error: {}", e);
            OidcErrorResponse::server_error("An internal error occurred")
        })?;
    if failure_count >= 5 {
        return Err(OidcErrorResponse::access_denied(
            "Too many failed attempts. Please try again later.",
        ));
    }

    // Find user by email
    let user = match UserRepo
        .find_by_email(&mut conn, realm.id, &req.email)
        .await
        .map_err(|e| {
            tracing::error!("Internal error: {}", e);
            OidcErrorResponse::server_error("An internal error occurred")
        })? {
        Some(u) => u,
        None => {
            // Perform dummy hash verification to prevent timing oracle
            let _ = state.hasher.verify(
                "dummy",
                "$argon2id$v=19$m=19456,t=2,p=1$dummysalt$dummyhash",
            );
            return Err(OidcErrorResponse::invalid_grant("Invalid credentials"));
        }
    };

    if !user.enabled {
        return Err(OidcErrorResponse::access_denied("Account disabled"));
    }

    // Verify password
    let password_hash = user
        .password_hash
        .as_ref()
        .ok_or_else(|| OidcErrorResponse::invalid_grant("Invalid credentials"))?;

    let hasher = Argon2idHasher::new();
    let valid = hasher.verify(&req.password, password_hash).map_err(|e| {
        tracing::error!("Internal error: verify failed: {}", e);
        OidcErrorResponse::server_error("An internal error occurred")
    })?;

    if !valid {
        // Log failed attempt for brute-force tracking via the repository
        let audit = AuditEvent {
            id: generate_uuid_v7(),
            realm_id: Some(realm.id),
            event_type: "LOGIN_FAILURE".to_string(),
            actor_id: None, // Will be resolved by the user lookup in the SQL
            actor_type: ActorType::User,
            target_type: None,
            target_id: None,
            details: serde_json::json!({"email": req.email}),
            ip_address: None,
            user_agent: None,
            created_at: chrono::Utc::now(),
        };
        let _ = AuditEventRepo.create(&mut conn, &audit).await;
        return Err(OidcErrorResponse::invalid_grant("Invalid credentials"));
    }

    // Find client
    let client_id_str = req.client_id.as_deref().unwrap_or("admin-ui");
    let client = ClientRepo
        .find_by_client_id(&mut conn, client_id_str)
        .await
        .map_err(|e| {
            tracing::error!("Internal error: {}", e);
            OidcErrorResponse::server_error("An internal error occurred")
        })?
        .ok_or_else(|| OidcErrorResponse::invalid_client("Client not found"))?;

    if !client.enabled {
        return Err(OidcErrorResponse::invalid_client("Client disabled"));
    }

    // Issue tokens
    let subject = user.id.to_string();
    let audience = client.client_id.clone();
    let scopes = vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
    ];

    let access_token = state
        .token_service
        .issue_access_token(&subject, &audience, &scopes)
        .await
        .map_err(|e| {
            tracing::error!("Internal error: token generation failed: {}", e);
            OidcErrorResponse::server_error("An internal error occurred")
        })?;

    let at_hash = oidc_core::utils::compute_at_hash(&access_token);

    let id_token_extra = IdTokenExtraClaims {
        nonce: None,
        at_hash: Some(at_hash),
        c_hash: None,
        auth_time: Some(chrono::Utc::now().timestamp()),
        email: Some(user.email.clone()),
        email_verified: Some(user.email_verified),
        name: user.username.clone(),
        given_name: user.given_name.clone(),
        family_name: user.family_name.clone(),
    };

    let id_token = state
        .token_service
        .issue_id_token(&subject, &audience, Some(id_token_extra))
        .await
        .map_err(|e| {
            tracing::error!("Internal error: id_token generation failed: {}", e);
            OidcErrorResponse::server_error("An internal error occurred")
        })?;

    let refresh_token = generate_opaque_token().map_err(|e| {
        tracing::error!("Internal error: {}", e);
        OidcErrorResponse::server_error("An internal error occurred")
    })?;

    // Store session
    let now = chrono::Utc::now();
    let session = Session {
        id: generate_uuid_v7(),
        user_id: user.id,
        realm_id: user.realm_id,
        client_id: client.id,
        grant_type: "password".to_string(),
        access_token_hash: sha2_256_hex(&access_token),
        refresh_token_hash: Some(sha2_256_hex(&refresh_token)),
        id_token_jti: None,
        scope: scopes.clone(),
        revoked: false,
        expires_at: now + chrono::Duration::minutes(15),
        refresh_expires_at: Some(now + chrono::Duration::days(7)),
        created_at: now,
        last_used_at: None,
        token_family_id: Some(generate_uuid_v7()),
        previous_session_id: None,
        rotated_at: None,
        reused_at: None,
        family_revoked: false,
    };

    SessionRepo.create(&mut conn, &session).await.map_err(|e| {
        tracing::error!("Internal error: {}", e);
        OidcErrorResponse::server_error("An internal error occurred")
    })?;

    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
        id_token,
        token_type: "Bearer".to_string(),
        expires_in: 900,
        user: UserInfo {
            id: user.id.to_string(),
            email: user.email,
            username: user.username,
            given_name: user.given_name,
            family_name: user.family_name,
        },
    }))
}
