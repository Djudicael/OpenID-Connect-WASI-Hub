//! OpenID Connect Client-Initiated Backchannel Authentication (CIBA Core 1.0).

use axum::{Json, http::HeaderMap};
use oidc_core::utils::{generate_opaque_token, generate_uuid_v7, sha2_256_hex};
use oidc_core::{
    OidcError,
    models::{CIBA_GRANT_TYPE, CibaAuthenticationRequest},
};
use oidc_repository::repositories::{
    audit_event_repo::AuditEventRepo, ciba_repo::CibaRepo, realm_repo::RealmRepo,
    scope_repo::ScopeRepo, user_consent_repo::UserConsentRepo, user_repo::UserRepo,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use uuid::Uuid;

use crate::endpoints::client_auth::{
    authenticate_client_for_endpoint, detect_presented_client_auth_method,
    inject_basic_auth_credentials,
};
use crate::{errors::OidcErrorResponse, state::OidcState};

pub async fn authentication_request(
    state: OidcState,
    headers: HeaderMap,
    mut params: HashMap<String, String>,
    realm_name: Option<&str>,
) -> Result<Json<Value>, OidcErrorResponse> {
    let method = detect_presented_client_auth_method(&headers, &params)?;
    inject_basic_auth_credentials(&headers, &mut params)?;
    let endpoint = state.backchannel_authentication_endpoint_uri();
    let mut conn = state
        .connect()
        .await
        .map_err(OidcErrorResponse::from_internal)?;
    let client =
        authenticate_client_for_endpoint(&state, &params, &mut conn, method, &endpoint).await?;
    if !client
        .allowed_grant_types
        .iter()
        .any(|v| v == CIBA_GRANT_TYPE)
    {
        return Err(OidcErrorResponse::unauthorized_client(
            "CIBA is not enabled for this client",
        ));
    }
    if let Some(name) = realm_name {
        let realm = RealmRepo
            .find_by_name(&mut conn, name)
            .await
            .map_err(OidcErrorResponse::from_internal)?
            .ok_or_else(|| OidcErrorResponse::invalid_request("Unknown realm"))?;
        if realm.id != client.realm_id {
            return Err(OidcErrorResponse::invalid_client(
                "Client does not belong to this realm",
            ));
        }
    }
    let config = CibaRepo
        .config(&mut conn, client.id)
        .await
        .map_err(OidcErrorResponse::from_internal)?
        .ok_or_else(|| {
            OidcErrorResponse::unauthorized_client("CIBA client settings are not configured")
        })?;

    let hints = ["login_hint", "id_token_hint", "login_hint_token"]
        .iter()
        .filter(|key| params.get(**key).is_some_and(|v| !v.is_empty()))
        .count();
    if hints != 1 {
        return Err(OidcErrorResponse::invalid_request(
            "Provide exactly one user hint",
        ));
    }
    if params.contains_key("login_hint_token") {
        return Err(OidcErrorResponse::invalid_request(
            "login_hint_token is not supported; use login_hint or id_token_hint",
        ));
    }
    if params.contains_key("user_code") {
        return Err(OidcErrorResponse::invalid_request(
            "The user_code parameter is not supported",
        ));
    }

    let user = if let Some(hint) = params.get("login_hint") {
        let by_email = UserRepo
            .find_by_email(&mut conn, client.realm_id, &hint.to_lowercase())
            .await
            .map_err(OidcErrorResponse::from_internal)?;
        match by_email {
            Some(user) => Some(user),
            None => UserRepo
                .find_by_username(&mut conn, client.realm_id, hint)
                .await
                .map_err(OidcErrorResponse::from_internal)?,
        }
    } else {
        let hint = params.get("id_token_hint").expect("hint checked");
        let subject = state
            .verify_id_token_any_issuer(hint)
            .await
            .map_err(|_| OidcErrorResponse::invalid_request("Invalid id_token_hint"))?;
        let claims: Value = OidcState::decode_jwt_payload_unverified(hint)
            .map_err(|_| OidcErrorResponse::invalid_request("Invalid id_token_hint"))?;
        let audience_matches = match claims.get("aud") {
            Some(Value::String(audience)) => audience == &client.client_id,
            Some(Value::Array(audiences)) => audiences
                .iter()
                .any(|audience| audience.as_str() == Some(&client.client_id)),
            _ => false,
        };
        if !audience_matches {
            return Err(OidcErrorResponse::invalid_request(
                "id_token_hint was not issued to this client",
            ));
        }
        let id = Uuid::parse_str(&subject)
            .map_err(|_| OidcErrorResponse::invalid_request("Invalid id_token_hint subject"))?;
        UserRepo
            .find_by_id(&mut conn, id)
            .await
            .map_err(OidcErrorResponse::from_internal)?
    }
    .filter(|u| u.enabled && u.realm_id == client.realm_id)
    .ok_or_else(|| OidcErrorResponse {
        error: "unknown_user_id".into(),
        error_description: Some("The supplied user hint does not identify an active user".into()),
        error_uri: None,
    })?;

    let requested: Vec<String> = params
        .get("scope")
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or_else(|| vec!["openid".into()]);
    if !requested.iter().any(|v| v == "openid") {
        return Err(OidcErrorResponse::invalid_scope(
            "CIBA requires the openid scope",
        ));
    }
    let scopes = ScopeRepo
        .resolve_names_for_client(&mut conn, client.id, &requested, &client.allowed_scopes)
        .await
        .map_err(|e| crate::errors::from_oidc_error(&e))?;
    if scopes.iter().any(|v| v == "offline_access") {
        return Err(OidcErrorResponse::invalid_scope(
            "offline_access is not available through CIBA",
        ));
    }

    let binding_message = params
        .get("binding_message")
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    if binding_message
        .as_ref()
        .is_some_and(|v| v.chars().count() > 20)
    {
        return Err(OidcErrorResponse {
            error: "invalid_binding_message".into(),
            error_description: Some("binding_message must be 20 characters or fewer".into()),
            error_uri: None,
        });
    }
    let requested_expiry = params
        .get("requested_expiry")
        .map(|v| v.parse::<i32>())
        .transpose()
        .map_err(|_| OidcErrorResponse::invalid_request("requested_expiry must be an integer"))?;
    let lifetime = requested_expiry.unwrap_or(config.request_lifetime_seconds);
    if !(1..=config.request_lifetime_seconds).contains(&lifetime) {
        return Err(OidcErrorResponse::invalid_request(
            "requested_expiry exceeds the configured lifetime",
        ));
    }

    let notification_token = params.get("client_notification_token").cloned();
    if config.delivery_mode == "ping" {
        if notification_token
            .as_ref()
            .is_none_or(|v| v.as_bytes().len() < 16)
        {
            return Err(OidcErrorResponse::invalid_request(
                "ping mode requires a high-entropy client_notification_token",
            ));
        }
    } else if notification_token.is_some() {
        return Err(OidcErrorResponse::invalid_request(
            "client_notification_token is only valid in ping mode",
        ));
    }
    let encrypted_notification = notification_token
        .as_deref()
        .map(|v| state.encrypt_sensitive_value(v.as_bytes()))
        .transpose()
        .map_err(OidcErrorResponse::from_internal)?;
    let auth_req_id = generate_opaque_token().map_err(OidcErrorResponse::from_internal)?;
    let encrypted_auth_req_id = state
        .encrypt_sensitive_value(auth_req_id.as_bytes())
        .map_err(OidcErrorResponse::from_internal)?;
    let now = chrono::Utc::now();
    let request = CibaAuthenticationRequest {
        id: generate_uuid_v7(),
        auth_req_id_hash: sha2_256_hex(&auth_req_id),
        auth_req_id_encrypted: encrypted_auth_req_id,
        client_id: client.id,
        realm_id: client.realm_id,
        user_id: user.id,
        scope: scopes,
        binding_message,
        request_context: params.get("request_context").cloned(),
        client_notification_token_encrypted: encrypted_notification,
        delivery_mode: config.delivery_mode,
        client_notification_endpoint: config.client_notification_endpoint,
        status: "pending".into(),
        interval_seconds: config.polling_interval_seconds,
        last_polled_at: None,
        requested_acr: params
            .get("acr_values")
            .map(|v| v.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default(),
        auth_time: None,
        acr: None,
        amr: vec![],
        expires_at: now + chrono::Duration::seconds(lifetime as i64),
        created_at: now,
        updated_at: now,
    };
    CibaRepo
        .create(&mut conn, &request)
        .await
        .map_err(OidcErrorResponse::from_internal)?;
    audit(&mut conn, request.realm_id, request.client_id, request.id, oidc_core::models::ActorType::System, "CIBA_REQUEST_CREATED", json!({"user_id":request.user_id,"delivery_mode":request.delivery_mode,"scopes":request.scope})).await;
    Ok(Json(
        json!({"auth_req_id":auth_req_id,"expires_in":lifetime,"interval":request.interval_seconds}),
    ))
}

pub async fn pending_requests(
    state: OidcState,
    headers: HeaderMap,
) -> Result<Json<Value>, OidcError> {
    let account = crate::endpoints::account::current_account(&state, &headers).await?;
    let mut conn = state.connect().await?;
    let rows = CibaRepo
        .list_pending_for_user(&mut conn, account.user.id)
        .await?;
    Ok(Json(
        json!({"items":rows.into_iter().map(|(r,name,client_id)| json!({"id":r.id,"client_name":name,"client_id":client_id,"scopes":r.scope,"binding_message":r.binding_message,"request_context":r.request_context,"expires_at":r.expires_at,"created_at":r.created_at})).collect::<Vec<_>>() }),
    ))
}

#[derive(Debug, Deserialize)]
pub struct CibaDecision {
    pub decision: String,
}

pub async fn decide_request(
    state: OidcState,
    headers: HeaderMap,
    id: Uuid,
    decision: CibaDecision,
) -> Result<Json<Value>, OidcError> {
    if decision.decision != "approve" && decision.decision != "deny" {
        return Err(OidcError::InvalidInput(
            "decision must be approve or deny".into(),
        ));
    }
    let account = crate::endpoints::account::current_account(&state, &headers).await?;
    let mut conn = state.connect().await?;
    let request = CibaRepo
        .find_user_request(&mut conn, id, account.user.id)
        .await?
        .ok_or_else(|| OidcError::NotFound("CIBA request".into()))?;
    if request.status != "pending" || request.expires_at <= chrono::Utc::now() {
        return Err(OidcError::Conflict(
            "This request is no longer pending".into(),
        ));
    }
    if decision.decision == "approve"
        && !request.requested_acr.is_empty()
        && !request
            .requested_acr
            .iter()
            .any(|v| acr_satisfies(&account.session.acr, v))
    {
        return Err(OidcError::AuthorizationDenied(
            "Sign in with a stronger authentication method before approving this request".into(),
        ));
    }
    let status = if decision.decision == "approve" {
        "approved"
    } else {
        "denied"
    };
    if status == "approved" {
        UserConsentRepo
            .grant(
                &mut conn,
                account.user.id,
                account.user.realm_id,
                request.client_id,
                &request.scope,
            )
            .await?;
    }
    if CibaRepo
        .decide(
            &mut conn,
            id,
            account.user.id,
            status,
            chrono::Utc::now(),
            &account.session.acr,
            &account.session.amr,
        )
        .await?
        == 0
    {
        return Err(OidcError::Conflict(
            "This request was already handled".into(),
        ));
    }
    let mut notification_delivered = request.delivery_mode != "ping";
    if request.delivery_mode == "ping" {
        let uri = request
            .client_notification_endpoint
            .as_deref()
            .ok_or_else(|| OidcError::Internal("ping endpoint missing".into()))?;
        let encrypted = request
            .client_notification_token_encrypted
            .as_deref()
            .ok_or_else(|| OidcError::Internal("notification token missing".into()))?;
        let token = state.decrypt_sensitive_string(encrypted)?;
        let auth_req_id = state.decrypt_sensitive_string(&request.auth_req_id_encrypted)?;
        match send_ping(uri, &token, &auth_req_id).await {
            Ok(()) => notification_delivered = true,
            Err(error) => tracing::warn!(
                "CIBA ping delivery failed for request {}: {error}",
                request.id
            ),
        }
    }
    audit(
        &mut conn,
        request.realm_id,
        account.user.id,
        request.id,
        oidc_core::models::ActorType::User,
        if status == "approved" {
            "CIBA_REQUEST_APPROVED"
        } else {
            "CIBA_REQUEST_DENIED"
        },
        json!({"client_id":request.client_id,"notification_delivered":notification_delivered}),
    )
    .await;
    Ok(Json(
        json!({"status":status,"notification_delivered":notification_delivered}),
    ))
}

async fn audit(
    conn: &mut oidc_repository::Connection,
    realm_id: Uuid,
    actor_id: Uuid,
    target_id: Uuid,
    actor_type: oidc_core::models::ActorType,
    event_type: &str,
    details: Value,
) {
    let event = oidc_core::models::AuditEvent {
        id: generate_uuid_v7(),
        realm_id: Some(realm_id),
        event_type: event_type.into(),
        actor_id: Some(actor_id),
        actor_type,
        target_type: Some("ciba_request".into()),
        target_id: Some(target_id),
        details,
        ip_address: None,
        user_agent: None,
        created_at: chrono::Utc::now(),
    };
    if let Err(error) = AuditEventRepo.create(conn, &event).await {
        tracing::warn!("failed to record CIBA event: {error}");
    }
}

fn acr_satisfies(actual: &str, requested: &str) -> bool {
    actual == requested
        || (actual == oidc_core::utils::ACR_SILVER && requested == oidc_core::utils::ACR_BRONZE)
}

async fn send_ping(uri: &str, token: &str, auth_req_id: &str) -> Result<(), String> {
    let body =
        serde_json::to_vec(&json!({"auth_req_id": auth_req_id})).map_err(|e| e.to_string())?;
    #[cfg(not(target_arch = "wasm32"))]
    {
        let response = reqwest::Client::new()
            .post(uri)
            .bearer_auth(token)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(format!(
                "notification endpoint returned {}",
                response.status()
            ));
        }
    }
    #[cfg(target_arch = "wasm32")]
    {
        let request = wstd::http::Request::post(uri)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(wstd::http::Body::from(body))
            .map_err(|e| e.to_string())?;
        let response = wstd::http::Client::new()
            .send(request)
            .await
            .map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(format!(
                "notification endpoint returned {}",
                response.status()
            ));
        }
    }
    Ok(())
}

pub fn validate_config(config: &oidc_core::models::CibaClientConfig) -> Result<(), OidcError> {
    if config.delivery_mode != "poll" && config.delivery_mode != "ping" {
        return Err(OidcError::InvalidInput(
            "delivery mode must be poll or ping".into(),
        ));
    }
    if config.delivery_mode == "ping" {
        let endpoint = config
            .client_notification_endpoint
            .as_deref()
            .ok_or_else(|| {
                OidcError::InvalidInput("ping mode requires a notification endpoint".into())
            })?;
        let url = url::Url::parse(endpoint)
            .map_err(|_| OidcError::InvalidInput("invalid notification endpoint".into()))?;
        if url.scheme() != "https" {
            return Err(OidcError::InvalidInput(
                "notification endpoint must use HTTPS".into(),
            ));
        }
    }
    if !(60..=900).contains(&config.request_lifetime_seconds)
        || !(2..=60).contains(&config.polling_interval_seconds)
    {
        return Err(OidcError::InvalidInput(
            "CIBA lifetime or interval is outside the allowed range".into(),
        ));
    }
    Ok(())
}
