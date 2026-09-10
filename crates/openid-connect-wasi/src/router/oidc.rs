//! OIDC protocol routes.

use axum::Json;
use axum::Router;
use axum::extract::{Form, OriginalUri, Path, Query, State};
use axum::response::{Html, IntoResponse};
use axum::routing::{delete, get, post, put};
use std::collections::HashMap;

use crate::middleware::admin_auth::AdminAuth;
use crate::state::AppState;

/// Build the OIDC sub-router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/.well-known/openid-configuration", get(|State(state): State<AppState>| async move {
            oidc_oidc::discovery_handler(state.oidc_state()).await
        }))
        .route("/.well-known/webfinger", get(|State(state): State<AppState>, Query(params): Query<oidc_oidc::endpoints::webfinger::WebFingerQuery>| async move {
            match oidc_oidc::endpoints::webfinger::webfinger_handler(State(state.oidc_state()), Query(params)).await {
                Ok(json) => json.into_response(),
                Err(e) => oidc_oidc::errors::from_oidc_error(&e).into_response(),
            }
        }))
        .route("/oidc/jwks", get(|State(state): State<AppState>| async move {
            oidc_oidc::endpoints::jwks::jwks_handler(state.oidc_state())
                .await
                .unwrap()
        }))
        .route("/oidc/authorize", get(|State(state): State<AppState>, headers: axum::http::HeaderMap, Query(params): Query<HashMap<String, String>>| async move {
            oidc_oidc::endpoints::authorize::authorize_handler(state.oidc_state(), headers, Query(params)).await
        }))
        .route("/oidc/token", post(|State(state): State<AppState>, headers: axum::http::HeaderMap, Form(params): Form<HashMap<String, String>>| async move {
            let oidc_state = state.oidc_state();
            match oidc_oidc::endpoints::token::token_handler(oidc_state, headers, params).await {
                Ok(json) => (axum::http::StatusCode::OK, json).into_response(),
                Err(e) => oidc_oidc::errors::from_oidc_error(&e).into_response(),
            }
        }))
        .route("/oidc/backchannel-authentication", post(|State(state): State<AppState>, headers: axum::http::HeaderMap, Form(params): Form<HashMap<String, String>>| async move {
            match oidc_oidc::endpoints::ciba::authentication_request(state.oidc_state(), headers, params, None).await {
                Ok(json) => json.into_response(), Err(error) => error.into_response()
            }
        }))
        .route("/oidc/userinfo", get(|State(state): State<AppState>, headers: axum::http::HeaderMap| async move {
            let auth = headers.get(axum::http::header::AUTHORIZATION).cloned();
            let dpop = headers.get("DPoP").cloned();
            oidc_oidc::endpoints::userinfo::userinfo_handler(State(state.oidc_state()), auth, dpop).await
        }))
        .route("/oidc/introspect", post(|State(state): State<AppState>, headers: axum::http::HeaderMap, form: Form<HashMap<String, String>>| async move {
            oidc_oidc::endpoints::introspect::introspect_handler(State(state.oidc_state()), headers, form).await
        }))
        .route("/oidc/revoke", post(|State(state): State<AppState>, headers: axum::http::HeaderMap, form: Form<HashMap<String, String>>| async move {
            oidc_oidc::endpoints::revoke::revoke_handler(State(state.oidc_state()), headers, form).await
        }))
        .route("/oidc/par", post(|State(state): State<AppState>, headers: axum::http::HeaderMap, Form(params): Form<HashMap<String, String>>| async move {
            let oidc_state = state.oidc_state();
            match oidc_oidc::endpoints::par::par_handler(oidc_state, headers, params).await {
                Ok(json) => (axum::http::StatusCode::CREATED, json).into_response(),
                Err(e) => oidc_oidc::errors::from_oidc_error(&e).into_response(),
            }
        }))
        .route("/oidc/logout", get(|State(state): State<AppState>, headers: axum::http::HeaderMap, Query(params): Query<HashMap<String, String>>| async move {
            oidc_oidc::endpoints::logout::logout_handler(state.oidc_state(), headers, Query(params)).await
        }))
        .route("/oidc/session/check", get(|State(state): State<AppState>, Query(params): Query<oidc_oidc::endpoints::session::check_session::CheckSessionParams>| async move {
            oidc_oidc::endpoints::session::check_session::check_session_handler(state.oidc_state(), Query(params)).await
        }))
        .route("/oidc/register", post(|State(state): State<AppState>, auth: AdminAuth, Json(req): Json<oidc_oidc::endpoints::registration::RegisterClientRequest>| async move {
            let restricted_realm = (!auth.is_global_admin()).then_some(auth.realm_id).flatten();
            match oidc_oidc::endpoints::registration::register_handler(state.oidc_state(), restricted_realm, Json(req)).await {
                Ok(json) => (axum::http::StatusCode::OK, json).into_response(),
                Err(e) => oidc_oidc::errors::from_oidc_error(&e).into_response(),
            }
        }))
        // Backward-compatible admin login
        .route("/oidc/login", post(|State(state): State<AppState>, json: Json<oidc_oidc::endpoints::login::LoginRequest>| async move {
            oidc_oidc::endpoints::login::login_handler(State(state.oidc_state()), json).await
        }))
        .route("/oidc/kerberos", post(|State(state): State<AppState>, headers: axum::http::HeaderMap, json: Json<oidc_oidc::endpoints::login::KerberosLoginRequest>| async move {
            oidc_oidc::endpoints::login::kerberos_login_handler(State(state.oidc_state()), headers, json).await
        }))
        .route("/oidc/required-actions/status", post(|State(state): State<AppState>, Json(req): Json<oidc_oidc::endpoints::required_actions::ActionTokenRequest>| async move {
            match oidc_oidc::endpoints::required_actions::status_handler(state.oidc_state(), req).await { Ok(v)=>v.into_response(), Err(e)=>oidc_oidc::errors::from_oidc_error(&e).into_response() }
        }))
        .route("/oidc/required-actions/password", post(|State(state): State<AppState>, Json(req): Json<oidc_oidc::endpoints::required_actions::PasswordRequest>| async move {
            match oidc_oidc::endpoints::required_actions::password_handler(state.oidc_state(), req).await { Ok(v)=>v.into_response(), Err(e)=>oidc_oidc::errors::from_oidc_error(&e).into_response() }
        }))
        .route("/oidc/required-actions/profile", post(|State(state): State<AppState>, Json(req): Json<oidc_oidc::endpoints::required_actions::ProfileRequest>| async move {
            match oidc_oidc::endpoints::required_actions::profile_handler(state.oidc_state(), req).await { Ok(v)=>v.into_response(), Err(e)=>oidc_oidc::errors::from_oidc_error(&e).into_response() }
        }))
        .route("/oidc/required-actions/terms", post(|State(state): State<AppState>, Json(req): Json<oidc_oidc::endpoints::required_actions::TermsRequest>| async move {
            match oidc_oidc::endpoints::required_actions::terms_handler(state.oidc_state(), req).await { Ok(v)=>v.into_response(), Err(e)=>oidc_oidc::errors::from_oidc_error(&e).into_response() }
        }))
        .route("/oidc/required-actions/mfa", post(|State(state): State<AppState>, Json(req): Json<oidc_oidc::endpoints::required_actions::ActionTokenRequest>| async move {
            match oidc_oidc::endpoints::required_actions::complete_mfa_handler(state.oidc_state(), req).await { Ok(v)=>v.into_response(), Err(e)=>oidc_oidc::errors::from_oidc_error(&e).into_response() }
        }))
        .route("/oidc/account/mfa", get(|State(state): State<AppState>, headers: axum::http::HeaderMap| async move {
            match oidc_oidc::endpoints::mfa::status_handler(state.oidc_state(), headers).await { Ok(v)=>v.into_response(), Err(e)=>oidc_oidc::errors::from_oidc_error(&e).into_response() }
        }))
        .route("/oidc/account/mfa/totp/start", post(|State(state): State<AppState>, headers: axum::http::HeaderMap| async move {
            match oidc_oidc::endpoints::mfa::totp_start_handler(state.oidc_state(), headers).await { Ok(v)=>v.into_response(), Err(e)=>oidc_oidc::errors::from_oidc_error(&e).into_response() }
        }))
        .route("/oidc/account/mfa/totp/finish", post(|State(state): State<AppState>, headers: axum::http::HeaderMap, Json(req): Json<oidc_oidc::endpoints::mfa::TotpFinishRequest>| async move {
            match oidc_oidc::endpoints::mfa::totp_finish_handler(state.oidc_state(), headers, req).await { Ok(v)=>v.into_response(), Err(e)=>oidc_oidc::errors::from_oidc_error(&e).into_response() }
        }))
        .route("/oidc/account/mfa/totp", delete(|State(state): State<AppState>, headers: axum::http::HeaderMap| async move {
            match oidc_oidc::endpoints::mfa::delete_totp_handler(state.oidc_state(), headers).await { Ok(v)=>v.into_response(), Err(e)=>oidc_oidc::errors::from_oidc_error(&e).into_response() }
        }))
        .route("/oidc/account/mfa/passkeys/start", post(|State(state): State<AppState>, headers: axum::http::HeaderMap| async move {
            match oidc_oidc::endpoints::mfa::webauthn_start_handler(state.oidc_state(), headers).await { Ok(v)=>v.into_response(), Err(e)=>oidc_oidc::errors::from_oidc_error(&e).into_response() }
        }))
        .route("/oidc/account/mfa/passkeys/finish", post(|State(state): State<AppState>, headers: axum::http::HeaderMap, Json(req): Json<oidc_oidc::endpoints::mfa::WebauthnFinishRequest>| async move {
            match oidc_oidc::endpoints::mfa::webauthn_finish_handler(state.oidc_state(), headers, req).await { Ok(v)=>v.into_response(), Err(e)=>oidc_oidc::errors::from_oidc_error(&e).into_response() }
        }))
        .route("/oidc/account/mfa/passkeys", delete(|State(state): State<AppState>, headers: axum::http::HeaderMap, Json(req): Json<oidc_oidc::endpoints::mfa::DeleteCredentialRequest>| async move {
            match oidc_oidc::endpoints::mfa::delete_webauthn_handler(state.oidc_state(), headers, req).await { Ok(v)=>v.into_response(), Err(e)=>oidc_oidc::errors::from_oidc_error(&e).into_response() }
        }))
        .route("/oidc/account/mfa/recovery-codes", post(|State(state): State<AppState>, headers: axum::http::HeaderMap| async move {
            match oidc_oidc::endpoints::mfa::recovery_regenerate_handler(state.oidc_state(), headers).await { Ok(v)=>v.into_response(), Err(e)=>oidc_oidc::errors::from_oidc_error(&e).into_response() }
        }))
        .route("/oidc/account", get(account_profile).put(account_update_profile))
        .route("/oidc/account/password", put(account_change_password))
        .route("/oidc/account/sessions", get(account_sessions))
        .route("/oidc/account/sessions/{id}", delete(account_revoke_session))
        .route("/oidc/account/linked-identities", get(account_linked_identities))
        .route("/oidc/account/linked-identities/{id}", delete(account_unlink_identity))
        .route("/oidc/account/applications", get(account_applications))
        .route("/oidc/account/applications/{id}", delete(account_revoke_application))
        .route("/oidc/account/ciba", get(|State(state): State<AppState>, headers: axum::http::HeaderMap| async move {
            account_result(oidc_oidc::endpoints::ciba::pending_requests(state.oidc_state(), headers).await)
        }))
        .route("/oidc/account/ciba/{id}", post(|State(state): State<AppState>, Path(id): Path<uuid::Uuid>, headers: axum::http::HeaderMap, Json(req): Json<oidc_oidc::endpoints::ciba::CibaDecision>| async move {
            account_result(oidc_oidc::endpoints::ciba::decide_request(state.oidc_state(), headers, id, req).await)
        }))
        // Password reset
        .route("/oidc/password-reset/request", post(|State(state): State<AppState>, Json(req): Json<oidc_oidc::endpoints::password_reset::PasswordResetRequestRequest>| async move {
            match oidc_oidc::endpoints::password_reset::password_reset_request_handler(State(state.oidc_state()), Json(req)).await {
                Ok(json) => json.into_response(),
                Err(e) => oidc_oidc::errors::from_oidc_error(&e).into_response(),
            }
        }))
        .route("/oidc/password-reset/confirm", post(|State(state): State<AppState>, Json(req): Json<oidc_oidc::endpoints::password_reset::PasswordResetConfirmRequest>| async move {
            match oidc_oidc::endpoints::password_reset::password_reset_confirm_handler(State(state.oidc_state()), Json(req)).await {
                Ok(json) => json.into_response(),
                Err(e) => oidc_oidc::errors::from_oidc_error(&e).into_response(),
            }
        }))
        // Email verification
        .route("/oidc/email-verification/request", post(|State(state): State<AppState>, Json(req): Json<oidc_oidc::endpoints::email_verification::EmailVerificationRequestRequest>| async move {
            match oidc_oidc::endpoints::email_verification::email_verification_request_handler(State(state.oidc_state()), Json(req)).await {
                Ok(json) => json.into_response(),
                Err(e) => oidc_oidc::errors::from_oidc_error(&e).into_response(),
            }
        }))
        .route("/oidc/email-verification/confirm", post(|State(state): State<AppState>, Json(req): Json<oidc_oidc::endpoints::email_verification::EmailVerificationConfirmRequest>| async move {
            match oidc_oidc::endpoints::email_verification::email_verification_confirm_handler(State(state.oidc_state()), Json(req)).await {
                Ok(json) => json.into_response(),
                Err(e) => oidc_oidc::errors::from_oidc_error(&e).into_response(),
            }
        }))
        .route("/oidc/organization-invitations/accept", post(|State(state): State<AppState>, headers: axum::http::HeaderMap, Json(req): Json<oidc_oidc::endpoints::organization_invitations::AcceptOrganizationInvitationRequest>| async move {
            match oidc_oidc::endpoints::organization_invitations::accept_organization_invitation(State(state.oidc_state()), headers, Json(req)).await {
                Ok(json) => json.into_response(),
                Err(e) => oidc_oidc::errors::from_oidc_error(&e).into_response(),
            }
        }))
        .route("/accept-invitation", get(organization_invitation_page_handler))
        // Account Recovery (public endpoint)
        .route("/oidc/account-recovery/confirm", post(|State(state): State<AppState>, Json(req): Json<oidc_oidc::endpoints::account_recovery::AccountRecoveryConfirmRequest>| async move {
            oidc_oidc::endpoints::account_recovery::confirm_account_recovery(State(state.oidc_state()), Json(req)).await
        }))
        // Device Authorization Grant (RFC 8628)
        .route("/oidc/device/authorize", post(|State(state): State<AppState>, headers: axum::http::HeaderMap, Form(params): Form<HashMap<String, String>>| async move {
            let oidc_state = state.oidc_state();
            match oidc_oidc::endpoints::device_authorization::device_authorization_handler(oidc_state, headers, params).await {
                Ok(json) => (axum::http::StatusCode::OK, json).into_response(),
                Err(e) => oidc_oidc::errors::from_oidc_error(&e).into_response(),
            }
        }))
        .route("/oidc/device", get(|State(state): State<AppState>, Query(params): Query<oidc_oidc::endpoints::device_authorization::DeviceVerifyParams>| async move {
            oidc_oidc::endpoints::device_authorization::device_authorization_verify_handler(State(state.oidc_state()), Query(params)).await
        }))
        .route("/oidc/device/confirm", post(|State(state): State<AppState>, headers: axum::http::HeaderMap, Form(req): Form<oidc_oidc::endpoints::device_authorization::DeviceConfirmRequest>| async move {
            match oidc_oidc::endpoints::device_authorization::device_authorization_confirm_handler(State(state.oidc_state()), headers, Form(req)).await {
                Ok(json) => json.into_response(),
                Err(e) => e.into_response(),
            }
        }))
        // Per-realm OIDC endpoints (Keycloak-compatible paths)
        .route("/realms/{realm}/protocol/openid-connect/token", post(per_realm_token_handler))
        .route("/realms/{realm}/protocol/openid-connect/auth", get(per_realm_authorize_handler))
        .route("/realms/{realm}/protocol/openid-connect/userinfo", get(per_realm_userinfo_handler))
        .route("/realms/{realm}/protocol/openid-connect/introspect", post(per_realm_introspect_handler))
        .route("/realms/{realm}/protocol/openid-connect/revoke", post(per_realm_revoke_handler))
        .route("/realms/{realm}/protocol/openid-connect/par", post(per_realm_par_handler))
        .route("/realms/{realm}/protocol/openid-connect/device/authorize", post(per_realm_device_authorization_handler))
        .route("/realms/{realm}/protocol/openid-connect/ext/ciba/auth", post(per_realm_ciba_handler))
        .route("/realms/{realm}/protocol/openid-connect/logout", get(per_realm_logout_handler))
        .route("/realms/{realm}/.well-known/openid-configuration", get(per_realm_discovery_handler))
        .route("/realms/{realm}/protocol/openid-connect/certs", get(per_realm_certs_handler))
        .route(
            "/realms/{realm}/.well-known/uma2-configuration",
            get(uma_discovery_handler),
        )
        .route(
            "/realms/{realm}/authz/protection/resource_set",
            get(uma_list_resources_handler).post(uma_create_resource_handler),
        )
        .route(
            "/realms/{realm}/authz/protection/resource_set/{resource_id}",
            get(uma_get_resource_handler)
                .put(uma_update_resource_handler)
                .delete(uma_delete_resource_handler),
        )
        .route(
            "/realms/{realm}/authz/protection/permission",
            post(uma_create_ticket_handler),
        )
        .route(
            "/realms/{realm}/authz/entitlement/{client_id}",
            post(uma_entitlement_handler),
        )
        .route(
            "/realms/{realm}/authz/protection/permission/evaluate/{client_id}",
            post(uma_evaluate_handler),
        )
        .route("/realms/{realm}/login", get(per_realm_login_page_handler))
        .route("/realms/{realm}/login", post(per_realm_login_handler))
        .route("/realms/{realm}/protocol/openid-connect/kerberos", post(per_realm_kerberos_login_handler))
        .route("/realms/{realm}/organization/identity-provider", get(|State(state): State<AppState>, Path(realm): Path<String>, Query(query): Query<oidc_oidc::endpoints::organizations::OrganizationIdentityProviderQuery>| async move {
            match oidc_oidc::endpoints::organizations::discover_identity_provider(State(state.oidc_state()), Path(realm), Query(query)).await {
                Ok(json) => json.into_response(),
                Err(error) => oidc_oidc::errors::from_oidc_error(&error).into_response(),
            }
        }))
        // Social login / federation
        .route("/realms/{realm}/protocol/openid-connect/social", get(per_realm_list_identity_providers_handler))
        .route("/realms/{realm}/protocol/openid-connect/social/{provider}", get(per_realm_social_login_initiate_handler))
        .route("/realms/{realm}/protocol/openid-connect/social/{provider}/callback", get(per_realm_social_login_callback_handler))
        .route("/realms/{realm}/protocol/saml/descriptor", get(saml_metadata_handler))
        .route("/realms/{realm}/protocol/saml", get(saml_sso_get_handler).post(saml_sso_post_handler))
        .route("/realms/{realm}/protocol/saml/logout", get(saml_logout_get_handler).post(saml_logout_post_handler))
        .route("/realms/{realm}/protocol/saml/broker/{provider}", get(saml_broker_start_handler))
        .route("/realms/{realm}/protocol/saml/broker/{provider}/metadata", get(saml_broker_metadata_handler))
        .route("/realms/{realm}/protocol/saml/broker/{provider}/endpoint", post(saml_broker_acs_handler))
        .route("/realms/{realm}/protocol/saml/broker/{provider}/logout", get(saml_broker_logout_get_handler).post(saml_broker_logout_post_handler))
        .route("/oidc/error", get(error_handler))
}

async fn saml_metadata_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
) -> axum::response::Response {
    oidc_oidc::endpoints::saml::idp_metadata(state.oidc_state(), realm).await
}

async fn saml_sso_get_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    headers: axum::http::HeaderMap,
    OriginalUri(uri): OriginalUri,
    Query(params): Query<HashMap<String, String>>,
) -> axum::response::Response {
    let resume = params.get("flow").cloned();
    let wire = uri.query().unwrap_or_default().to_string();
    oidc_oidc::endpoints::saml::idp_sso(
        state.oidc_state(),
        realm,
        headers,
        wire,
        saml::Binding::HttpRedirect,
        None,
        resume,
    )
    .await
}

async fn saml_sso_post_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    headers: axum::http::HeaderMap,
    Form(params): Form<HashMap<String, String>>,
) -> axum::response::Response {
    oidc_oidc::endpoints::saml::idp_sso(
        state.oidc_state(),
        realm,
        headers,
        params.get("SAMLRequest").cloned().unwrap_or_default(),
        saml::Binding::HttpPost,
        params.get("RelayState").cloned(),
        params.get("flow").cloned(),
    )
    .await
}

async fn saml_broker_start_handler(
    State(state): State<AppState>,
    Path((realm, provider)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> axum::response::Response {
    oidc_oidc::endpoints::saml::broker_start(
        state.oidc_state(),
        realm,
        provider,
        params.get("return_to").cloned().unwrap_or_default(),
    )
    .await
}
async fn saml_broker_metadata_handler(
    State(state): State<AppState>,
    Path((realm, provider)): Path<(String, String)>,
) -> axum::response::Response {
    oidc_oidc::endpoints::saml::broker_metadata(state.oidc_state(), realm, provider).await
}
async fn saml_broker_acs_handler(
    State(state): State<AppState>,
    Path((realm, provider)): Path<(String, String)>,
    Form(params): Form<HashMap<String, String>>,
) -> axum::response::Response {
    oidc_oidc::endpoints::saml::broker_acs(
        state.oidc_state(),
        realm,
        provider,
        params.get("SAMLResponse").cloned().unwrap_or_default(),
        params.get("RelayState").cloned().unwrap_or_default(),
    )
    .await
}
async fn saml_logout_get_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    OriginalUri(uri): OriginalUri,
    Query(params): Query<HashMap<String, String>>,
) -> axum::response::Response {
    oidc_oidc::endpoints::saml::idp_logout(
        state.oidc_state(),
        realm,
        uri.query().unwrap_or_default().to_string(),
        saml::Binding::HttpRedirect,
        params.get("RelayState").cloned(),
    )
    .await
}
async fn saml_logout_post_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    Form(params): Form<HashMap<String, String>>,
) -> axum::response::Response {
    oidc_oidc::endpoints::saml::idp_logout(
        state.oidc_state(),
        realm,
        params.get("SAMLRequest").cloned().unwrap_or_default(),
        saml::Binding::HttpPost,
        params.get("RelayState").cloned(),
    )
    .await
}
async fn saml_broker_logout_get_handler(
    State(state): State<AppState>,
    Path((realm, provider)): Path<(String, String)>,
    OriginalUri(uri): OriginalUri,
) -> axum::response::Response {
    oidc_oidc::endpoints::saml::broker_logout(
        state.oidc_state(),
        realm,
        provider,
        uri.query().unwrap_or_default().to_string(),
        saml::Binding::HttpRedirect,
    )
    .await
}
async fn saml_broker_logout_post_handler(
    State(state): State<AppState>,
    Path((realm, provider)): Path<(String, String)>,
    Form(params): Form<HashMap<String, String>>,
) -> axum::response::Response {
    oidc_oidc::endpoints::saml::broker_logout(
        state.oidc_state(),
        realm,
        provider,
        params.get("SAMLRequest").cloned().unwrap_or_default(),
        saml::Binding::HttpPost,
    )
    .await
}

async fn uma_server_from_token(
    state: &oidc_oidc::state::OidcState,
    headers: &axum::http::HeaderMap,
) -> Result<String, oidc_core::OidcError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| {
            oidc_core::OidcError::AuthenticationFailed("Bearer token required".into())
        })?;
    Ok(state
        .verify_access_token_with_claims_any_issuer(token)
        .await?
        .sub)
}

fn uma_result(
    result: Result<Json<serde_json::Value>, oidc_core::OidcError>,
) -> axum::response::Response {
    match result {
        Ok(value) => value.into_response(),
        Err(error) => oidc_oidc::errors::from_oidc_error(&error).into_response(),
    }
}

async fn uma_discovery_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
) -> Json<serde_json::Value> {
    let issuer = format!(
        "{}/realms/{}",
        state.config.issuer.trim_end_matches('/'),
        realm
    );
    Json(serde_json::json!({
        "issuer": issuer,
        "grant_types_supported": [oidc_oidc::endpoints::authorization_services::UMA_GRANT_TYPE],
        "response_types_supported": ["token"],
        "token_endpoint": format!("{issuer}/protocol/openid-connect/token"),
        "resource_registration_endpoint": format!("{issuer}/authz/protection/resource_set"),
        "permission_endpoint": format!("{issuer}/authz/protection/permission"),
        "uma_profiles_supported": ["http://docs.kantarainitiative.org/uma/profiles/uma-token-bearer-1.0"]
    }))
}

async fn uma_create_resource_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    headers: axum::http::HeaderMap,
    Json(req): Json<oidc_oidc::endpoints::authorization_services::ResourceRegistrationRequest>,
) -> axum::response::Response {
    let oidc_state = state
        .oidc_state()
        .with_issuer(format!("{}/realms/{}", state.config.issuer, realm));
    let server = match uma_server_from_token(&oidc_state, &headers).await {
        Ok(value) => value,
        Err(error) => return uma_result(Err(error)),
    };
    uma_result(
        oidc_oidc::endpoints::authorization_services::register_resource(
            oidc_state, realm, server, headers, req,
        )
        .await,
    )
}

async fn uma_list_resources_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let oidc_state = state
        .oidc_state()
        .with_issuer(format!("{}/realms/{}", state.config.issuer, realm));
    let server = match uma_server_from_token(&oidc_state, &headers).await {
        Ok(value) => value,
        Err(error) => return uma_result(Err(error)),
    };
    uma_result(
        oidc_oidc::endpoints::authorization_services::list_registered_resources(
            oidc_state, realm, server, headers,
        )
        .await,
    )
}

async fn uma_get_resource_handler(
    State(state): State<AppState>,
    Path((realm, resource_id)): Path<(String, uuid::Uuid)>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let oidc_state = state
        .oidc_state()
        .with_issuer(format!("{}/realms/{}", state.config.issuer, realm));
    let server = match uma_server_from_token(&oidc_state, &headers).await {
        Ok(value) => value,
        Err(error) => return uma_result(Err(error)),
    };
    uma_result(
        oidc_oidc::endpoints::authorization_services::get_registered_resource(
            oidc_state,
            realm,
            server,
            resource_id,
            headers,
        )
        .await,
    )
}

async fn uma_update_resource_handler(
    State(state): State<AppState>,
    Path((realm, resource_id)): Path<(String, uuid::Uuid)>,
    headers: axum::http::HeaderMap,
    Json(req): Json<oidc_oidc::endpoints::authorization_services::ResourceRegistrationRequest>,
) -> axum::response::Response {
    let oidc_state = state
        .oidc_state()
        .with_issuer(format!("{}/realms/{}", state.config.issuer, realm));
    let server = match uma_server_from_token(&oidc_state, &headers).await {
        Ok(value) => value,
        Err(error) => return uma_result(Err(error)),
    };
    uma_result(
        oidc_oidc::endpoints::authorization_services::update_registered_resource(
            oidc_state,
            realm,
            server,
            resource_id,
            headers,
            req,
        )
        .await,
    )
}

async fn uma_delete_resource_handler(
    State(state): State<AppState>,
    Path((realm, resource_id)): Path<(String, uuid::Uuid)>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let oidc_state = state
        .oidc_state()
        .with_issuer(format!("{}/realms/{}", state.config.issuer, realm));
    let server = match uma_server_from_token(&oidc_state, &headers).await {
        Ok(value) => value,
        Err(error) => return uma_result(Err(error)),
    };
    uma_result(
        oidc_oidc::endpoints::authorization_services::delete_registered_resource(
            oidc_state,
            realm,
            server,
            resource_id,
            headers,
        )
        .await,
    )
}

async fn uma_create_ticket_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    headers: axum::http::HeaderMap,
    Json(req): Json<oidc_oidc::endpoints::authorization_services::PermissionTicketRequest>,
) -> axum::response::Response {
    let oidc_state = state
        .oidc_state()
        .with_issuer(format!("{}/realms/{}", state.config.issuer, realm));
    let server = match uma_server_from_token(&oidc_state, &headers).await {
        Ok(value) => value,
        Err(error) => return uma_result(Err(error)),
    };
    uma_result(
        oidc_oidc::endpoints::authorization_services::create_permission_ticket(
            oidc_state, realm, server, headers, req,
        )
        .await,
    )
}

async fn uma_entitlement_handler(
    State(state): State<AppState>,
    Path((realm, client_id)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let oidc_state = state
        .oidc_state()
        .with_issuer(format!("{}/realms/{}", state.config.issuer, realm));
    uma_result(
        oidc_oidc::endpoints::authorization_services::entitlement(
            oidc_state, realm, client_id, headers,
        )
        .await,
    )
}

async fn uma_evaluate_handler(
    State(state): State<AppState>,
    Path((realm, client_id)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
    Json(req): Json<oidc_oidc::endpoints::authorization_services::DecisionRequest>,
) -> axum::response::Response {
    let oidc_state = state
        .oidc_state()
        .with_issuer(format!("{}/realms/{}", state.config.issuer, realm));
    uma_result(
        oidc_oidc::endpoints::authorization_services::evaluate_rpt(
            oidc_state, realm, client_id, headers, req,
        )
        .await,
    )
}

async fn account_profile(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    account_result(
        oidc_oidc::endpoints::account::profile_handler(state.oidc_state(), headers).await,
    )
}

async fn account_update_profile(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<oidc_oidc::endpoints::account::UpdateProfileRequest>,
) -> axum::response::Response {
    account_result(
        oidc_oidc::endpoints::account::update_profile_handler(state.oidc_state(), headers, req)
            .await,
    )
}

async fn account_change_password(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<oidc_oidc::endpoints::account::ChangePasswordRequest>,
) -> axum::response::Response {
    account_result(
        oidc_oidc::endpoints::account::change_password_handler(state.oidc_state(), headers, req)
            .await,
    )
}

async fn account_sessions(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    account_result(
        oidc_oidc::endpoints::account::sessions_handler(state.oidc_state(), headers).await,
    )
}

async fn account_revoke_session(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> axum::response::Response {
    account_result(
        oidc_oidc::endpoints::account::revoke_session_handler(state.oidc_state(), headers, id)
            .await,
    )
}

async fn account_linked_identities(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    account_result(
        oidc_oidc::endpoints::account::linked_identities_handler(state.oidc_state(), headers).await,
    )
}

async fn account_unlink_identity(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> axum::response::Response {
    account_result(
        oidc_oidc::endpoints::account::unlink_identity_handler(state.oidc_state(), headers, id)
            .await,
    )
}

async fn account_applications(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    account_result(
        oidc_oidc::endpoints::account::applications_handler(state.oidc_state(), headers).await,
    )
}

async fn account_revoke_application(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> axum::response::Response {
    account_result(
        oidc_oidc::endpoints::account::revoke_application_handler(state.oidc_state(), headers, id)
            .await,
    )
}

fn account_result(
    result: Result<Json<serde_json::Value>, oidc_core::OidcError>,
) -> axum::response::Response {
    match result {
        Ok(value) => value.into_response(),
        Err(
            oidc_core::OidcError::AuthenticationFailed(_)
            | oidc_core::OidcError::InvalidTokenSignature
            | oidc_core::OidcError::TokenExpired,
        ) => (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "unauthorized",
                "error_description": "A valid account access token is required"
            })),
        )
            .into_response(),
        Err(error) => oidc_oidc::errors::from_oidc_error(&error).into_response(),
    }
}

/// Per-realm token endpoint (Keycloak-compatible).
///
/// Accepts standard OAuth2 form-encoded token requests and uses the realm-scoped
/// issuer context implied by the URL path.
async fn per_realm_token_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    headers: axum::http::HeaderMap,
    Form(params): Form<HashMap<String, String>>,
) -> axum::response::Response {
    let realm_state = state
        .oidc_state()
        .with_issuer(format!("{}/realms/{}", state.config.issuer, realm));

    match oidc_oidc::endpoints::token::token_handler(realm_state, headers, params).await {
        Ok(json) => (axum::http::StatusCode::OK, json).into_response(),
        Err(err) => oidc_oidc::errors::from_oidc_error(&err).into_response(),
    }
}

async fn per_realm_ciba_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    headers: axum::http::HeaderMap,
    Form(params): Form<HashMap<String, String>>,
) -> axum::response::Response {
    let realm_state = state
        .oidc_state()
        .with_issuer(format!("{}/realms/{}", state.config.issuer, realm));
    match oidc_oidc::endpoints::ciba::authentication_request(
        realm_state,
        headers,
        params,
        Some(&realm),
    )
    .await
    {
        Ok(json) => json.into_response(),
        Err(error) => error.into_response(),
    }
}

/// Per-realm login endpoint (convenience path).
///
/// Accepts `email` + `password` as JSON, uses the realm from the URL path.
async fn per_realm_login_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    Json(req): Json<oidc_oidc::endpoints::login::LoginRequest>,
) -> axum::response::Response {
    let mut request = req;
    request.realm = Some(realm);

    match oidc_oidc::endpoints::login::login_handler(State(state.oidc_state()), Json(request)).await
    {
        Ok(response) => response,
        Err(err) => err.into_response(),
    }
}

async fn per_realm_kerberos_login_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    headers: axum::http::HeaderMap,
    Json(mut request): Json<oidc_oidc::endpoints::login::KerberosLoginRequest>,
) -> axum::response::Response {
    request.realm = Some(realm.clone());
    let realm_state = state
        .oidc_state()
        .with_issuer(format!("{}/realms/{}", state.config.issuer, realm));
    oidc_oidc::endpoints::login::kerberos_login_handler(State(realm_state), headers, Json(request))
        .await
}

/// Per-realm authorize handler (Keycloak-compatible).
async fn per_realm_authorize_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    headers: axum::http::HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> axum::response::Response {
    let realm_state = state
        .oidc_state()
        .with_issuer(format!("{}/realms/{}", state.config.issuer, realm));
    oidc_oidc::endpoints::authorize::realm_authorize_handler(
        realm_state,
        realm,
        headers,
        Query(params),
    )
    .await
}

/// Per-realm userinfo handler (Keycloak-compatible).
async fn per_realm_userinfo_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let realm_state = state
        .oidc_state()
        .with_issuer(format!("{}/realms/{}", state.config.issuer, realm));
    let auth = headers.get(axum::http::header::AUTHORIZATION).cloned();
    let dpop = headers.get("DPoP").cloned();
    oidc_oidc::endpoints::userinfo::userinfo_handler(State(realm_state), auth, dpop).await
}

/// Per-realm introspection handler (Keycloak-compatible).
async fn per_realm_introspect_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    headers: axum::http::HeaderMap,
    form: Form<HashMap<String, String>>,
) -> axum::response::Response {
    let realm_state = state
        .oidc_state()
        .with_issuer(format!("{}/realms/{}", state.config.issuer, realm));
    match oidc_oidc::endpoints::introspect::introspect_handler(State(realm_state), headers, form)
        .await
    {
        Ok(json) => json.into_response(),
        Err(err) => err.into_response(),
    }
}

/// Per-realm revocation handler (Keycloak-compatible).
async fn per_realm_revoke_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    headers: axum::http::HeaderMap,
    form: Form<HashMap<String, String>>,
) -> axum::response::Response {
    let realm_state = state
        .oidc_state()
        .with_issuer(format!("{}/realms/{}", state.config.issuer, realm));
    match oidc_oidc::endpoints::revoke::revoke_handler(State(realm_state), headers, form).await {
        Ok(json) => json.into_response(),
        Err(err) => err.into_response(),
    }
}

/// Per-realm PAR handler (Keycloak-compatible).
async fn per_realm_par_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    headers: axum::http::HeaderMap,
    Form(params): Form<HashMap<String, String>>,
) -> axum::response::Response {
    let realm_state = state
        .oidc_state()
        .with_issuer(format!("{}/realms/{}", state.config.issuer, realm));
    match oidc_oidc::endpoints::par::par_handler(realm_state, headers, params).await {
        Ok(json) => (axum::http::StatusCode::CREATED, json).into_response(),
        Err(err) => oidc_oidc::errors::from_oidc_error(&err).into_response(),
    }
}

/// Per-realm device authorization handler (Keycloak-compatible).
async fn per_realm_device_authorization_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    headers: axum::http::HeaderMap,
    Form(params): Form<HashMap<String, String>>,
) -> axum::response::Response {
    let realm_state = state
        .oidc_state()
        .with_issuer(format!("{}/realms/{}", state.config.issuer, realm));
    match oidc_oidc::endpoints::device_authorization::device_authorization_handler(
        realm_state,
        headers,
        params,
    )
    .await
    {
        Ok(json) => (axum::http::StatusCode::OK, json).into_response(),
        Err(err) => oidc_oidc::errors::from_oidc_error(&err).into_response(),
    }
}

/// Per-realm logout handler (Keycloak-compatible).
async fn per_realm_logout_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    headers: axum::http::HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> axum::response::Response {
    let realm_state = state
        .oidc_state()
        .with_issuer(format!("{}/realms/{}", state.config.issuer, realm));
    oidc_oidc::endpoints::logout::logout_handler(realm_state, headers, Query(params)).await
}

/// Per-realm discovery handler (Keycloak-compatible).
async fn per_realm_discovery_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
) -> Json<serde_json::Value> {
    oidc_oidc::realm_discovery_handler(state.oidc_state(), realm).await
}

/// Per-realm JWKS (certs) handler.
async fn per_realm_certs_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
) -> axum::response::Response {
    match oidc_oidc::endpoints::jwks::realm_jwks_handler(state.oidc_state(), realm).await {
        Ok(json) => json.into_response(),
        Err(e) => {
            let status = match e {
                oidc_core::OidcError::NotFound(_) => axum::http::StatusCode::NOT_FOUND,
                _ => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            };
            let body = serde_json::json!({"error": e.to_string()});
            (status, axum::Json(body)).into_response()
        }
    }
}

/// Per-realm social login: list available identity providers.
async fn per_realm_list_identity_providers_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
) -> axum::response::Response {
    oidc_oidc::endpoints::social_login::list_identity_providers_handler(
        State(state.oidc_state()),
        Path(realm),
    )
    .await
}

/// Per-realm social login: initiate login with an upstream IdP.
async fn per_realm_social_login_initiate_handler(
    State(state): State<AppState>,
    Path((realm, provider)): Path<(String, String)>,
    Query(params): Query<oidc_oidc::endpoints::social_login::SocialLoginParams>,
) -> axum::response::Response {
    oidc_oidc::endpoints::social_login::social_login_initiate_handler(
        State(state.oidc_state()),
        Path((realm, provider)),
        Query(params),
    )
    .await
}

/// Per-realm social login: callback from the upstream IdP.
async fn per_realm_social_login_callback_handler(
    State(state): State<AppState>,
    Path((realm, provider)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
    Query(params): Query<oidc_oidc::endpoints::social_login::SocialLoginCallbackParams>,
) -> axum::response::Response {
    oidc_oidc::endpoints::social_login::social_login_callback_handler(
        State(state.oidc_state()),
        Path((realm, provider)),
        headers,
        Query(params),
    )
    .await
}

/// Simple error page for OIDC authorization failures.
async fn error_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let error = params
        .get("error")
        .cloned()
        .unwrap_or_else(|| "server_error".to_string());
    let description = params
        .get("error_description")
        .cloned()
        .unwrap_or_else(|| "An error occurred during authentication.".to_string());

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Error</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            background: #f5f5f5;
        }}
        .error-box {{
            background: white;
            padding: 2.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            max-width: 28rem;
            text-align: center;
        }}
        .error-icon {{
            font-size: 3rem;
            margin-bottom: 1rem;
        }}
        h1 {{
            font-size: 1.25rem;
            color: #dc2626;
            margin: 0 0 0.5rem 0;
        }}
        .error-code {{
            font-family: monospace;
            background: #fef2f2;
            color: #dc2626;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.875rem;
        }}
        p {{
            color: #6b7280;
            margin: 1rem 0 0 0;
            line-height: 1.5;
        }}
        a {{
            color: #2563eb;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="error-box">
        <div class="error-icon">&#x26A0;&#xFE0F;</div>
        <h1>Authentication Error</h1>
        <div class="error-code">{}</div>
        <p>{}</p>
        <p><a href="/">&larr; Back to Home</a></p>
    </div>
</body>
</html>"#,
        html_escape(&error),
        html_escape(&description)
    );

    Html(html)
}

async fn organization_invitation_page_handler(
    Query(params): Query<HashMap<String, String>>,
) -> axum::response::Response {
    let Some(token) = params.get("token").filter(|token| !token.is_empty()) else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "Invitation token is required",
        )
            .into_response();
    };
    let token_json = serde_json::to_string(token).unwrap_or_else(|_| "null".into());
    Html(format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Accept invitation</title><style>
body{{font-family:system-ui,sans-serif;background:#f8fafc;min-height:100vh;margin:0;display:grid;place-items:center}}
main{{background:white;width:min(26rem,calc(100% - 2rem));padding:2rem;border-radius:.75rem;box-shadow:0 4px 18px #0001}}
h1{{margin-top:0}}label{{display:block;margin-top:1rem;font-weight:600}}input{{box-sizing:border-box;width:100%;padding:.7rem;margin-top:.3rem;border:1px solid #cbd5e1;border-radius:.4rem}}
button{{width:100%;margin-top:1.25rem;padding:.75rem;border:0;border-radius:.4rem;background:#2563eb;color:white;font-weight:600;cursor:pointer}}
#message{{margin-top:1rem}}.error{{color:#b91c1c}}.success{{color:#166534}}
</style></head><body><main><h1>Accept organization invitation</h1>
<p>If you are already signed in, confirm the invitation. Otherwise enter your password. For a new account, choose a strong password.</p>
<form id="form"><label for="username">Username (optional for new accounts)</label><input id="username" autocomplete="username">
<label for="password">Password (optional when signed in)</label><input id="password" type="password" autocomplete="current-password">
<button id="submit" type="submit">Accept invitation</button></form><div id="message" role="status"></div></main>
<script>const invitationToken={token_json};const form=document.getElementById('form');const message=document.getElementById('message');
form.addEventListener('submit',async(event)=>{{event.preventDefault();const button=document.getElementById('submit');button.disabled=true;message.textContent='';
try{{const response=await fetch('/oidc/organization-invitations/accept',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{token:invitationToken,password:document.getElementById('password').value||null,username:document.getElementById('username').value||null}})}});const data=await response.json();if(!response.ok)throw new Error(data.error_description||'Unable to accept invitation');form.hidden=true;message.className='success';message.textContent='Invitation accepted.';if(data.redirect_url)setTimeout(()=>location.assign(data.redirect_url),800);}}
catch(error){{message.className='error';message.textContent=error.message;button.disabled=false;}}}});</script></body></html>"#
    ))
    .into_response()
}

/// Serve a branded HTML login page for a realm.
///
/// Reads theme configuration from `realm.config.theme` and renders
/// a self-contained login form that POSTs JSON to the token endpoint.
async fn per_realm_login_page_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    headers: axum::http::HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> axum::response::Response {
    let mut conn = match wasi_pg_client::Connection::connect(&state.db_config).await {
        Ok(c) => oidc_repository::Connection::from_pg_client(c),
        Err(e) => {
            tracing::error!("DB connection failed for login page: {e}");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            )
                .into_response();
        }
    };

    let realm_entity = match oidc_repository::repositories::realm_repo::RealmRepo
        .find_by_name(&mut conn, &realm)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                "Realm not found".to_string(),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("DB error fetching realm for login page: {e}");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            )
                .into_response();
        }
    };

    if !realm_entity.enabled {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Realm is disabled".to_string(),
        )
            .into_response();
    }

    let presentation =
        oidc_core::models::RealmPresentation::from_realm_config(&realm_entity.config);
    let requested_locales = params.get("ui_locales").map(String::as_str);
    let accept_language = headers
        .get(axum::http::header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok());
    let locale = presentation.resolve_locale(requested_locales, accept_language);
    let theme = &presentation.theme;
    let login_title = if theme.login_title.is_empty() {
        &realm_entity.display_name
    } else {
        &theme.login_title
    };

    let return_to = params.get("return_to").cloned().unwrap_or_default();
    let state_param = params.get("state").cloned().unwrap_or_default();
    let script_nonce = uuid::Uuid::new_v4().simple().to_string();

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="{locale}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - {page_title}</title>
    {favicon}
    <style>
        :root {{ --primary: {primary}; --bg: {background}; --card: {card}; --text: {text}; --font: {font}; }}
        * {{ box-sizing: border-box; }}
        body {{
            font-family: var(--font);
            display: flex; align-items: center; justify-content: center;
            min-height: 100vh; margin: 0; background: var(--bg);
        }}
        .login-box {{
            background: var(--card); color: var(--text); padding: 2.5rem; border-radius: 12px;
            box-shadow: 0 4px 16px rgba(0,0,0,0.08); width: 100%; max-width: 24rem;
            text-align: center;
        }}
        .logo {{ max-height: 3rem; margin-bottom: 1rem; }}
        h1 {{ font-size: 1.5rem; font-weight: 600; margin: 0 0 0.25rem 0; color: var(--text); }}
        .subtitle {{ color: #6b7280; margin-bottom: 1.5rem; font-size: 0.875rem; }}
        .form {{ display: flex; flex-direction: column; gap: 1rem; text-align: left; }}
        label {{ display: block; font-size: 0.875rem; font-weight: 500; margin-bottom: 0.25rem; color: #374151; }}
        input {{
            width: 100%; padding: 0.625rem; border: 1px solid #d1d5db;
            border-radius: 6px; font-size: 0.875rem; background: #fff; color: #111;
        }}
        input:focus {{ outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(37,99,235,0.1); }}
        .pw-wrap {{ position: relative; }}
        .pw-wrap input {{ padding-right: 2.5rem; }}
        .toggle-pw {{
            position: absolute; right: 0.5rem; top: 50%; transform: translateY(-50%);
            display: grid; place-items: center; width: 2rem; height: 2rem; padding: 0;
            background: none; border: none; border-radius: 4px; cursor: pointer; color: #6b7280;
        }}
        .toggle-pw:hover {{ color: var(--text); background: rgba(107,114,128,0.08); }}
        .toggle-pw:focus-visible {{ outline: 2px solid var(--primary); outline-offset: 1px; }}
        .toggle-pw svg {{ display: block; width: 1.125rem; height: 1.125rem; fill: none; stroke: currentColor; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round; }}
        .toggle-pw svg[hidden] {{ display: none; }}
        button[type="submit"] {{
            width: 100%; padding: 0.75rem; font-size: 1rem; font-weight: 500;
            background: var(--primary); color: #fff; border: none; border-radius: 6px;
            cursor: pointer; margin-top: 0.5rem;
        }}
        button[type="submit"]:hover {{ opacity: 0.92; }}
        button[type="submit"]:disabled {{ opacity: 0.6; cursor: not-allowed; }}
        .error {{
            color: #dc2626; font-size: 0.875rem; margin-top: 0.75rem;
            padding: 0.75rem; background: #fef2f2; border-radius: 6px; display: none;
        }}
        .footer {{ margin-top: 1.25rem; font-size: 0.75rem; color: #9ca3af; }}
    </style>
</head>
<body>
    <div class="login-box">
        {logo}
        <h1>{title}</h1>
        <p class="subtitle">{subtitle}</p>
        <form class="form" id="loginForm" action="/realms/{realm_path}/login" method="post">
            <div>
                <label for="email">{email_label}</label>
                <input id="email" type="email" placeholder="{email_placeholder}" required autofocus />
            </div>
            <div>
                <label for="password">{password_label}</label>
                <div class="pw-wrap">
                    <input id="password" type="password" placeholder="••••••••" required />
                    <button type="button" class="toggle-pw" id="togglePw" aria-label="{toggle_password}" aria-pressed="false">
                        <svg id="showPasswordIcon" viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg>
                        <svg id="hidePasswordIcon" viewBox="0 0 24 24" aria-hidden="true" hidden><path d="m3 3 18 18"/><path d="M10.6 10.7a2 2 0 0 0 2.7 2.7"/><path d="M9.9 4.2A10.8 10.8 0 0 1 12 4c6.5 0 10 8 10 8a18.5 18.5 0 0 1-2.1 3.2"/><path d="M6.6 6.6C3.5 8.7 2 12 2 12s3.5 8 10 8a9.8 9.8 0 0 0 4.2-.9"/></svg>
                    </button>
                </div>
            </div>
            <button type="submit" id="submitBtn">{sign_in}</button>
            <div class="error" id="errorBox"></div>
        </form>
        <div class="footer">{footer}</div>
    </div>
    <script nonce="{script_nonce}">
        (function() {{
            const form = document.getElementById('loginForm');
            const btn = document.getElementById('submitBtn');
            const errorBox = document.getElementById('errorBox');
            const togglePw = document.getElementById('togglePw');
            const pwInput = document.getElementById('password');
            const showPasswordIcon = document.getElementById('showPasswordIcon');
            const hidePasswordIcon = document.getElementById('hidePasswordIcon');
            const returnTo = {return_to};
            const stateParam = {state_param};
            const realmName = {realm_json};
            const signingIn = {signing_in_json};
            const signIn = {sign_in_json};
            const loginFailed = {login_failed_json};

            togglePw.addEventListener('click', function() {{
                const isPw = pwInput.type === 'password';
                pwInput.type = isPw ? 'text' : 'password';
                togglePw.setAttribute('aria-pressed', String(isPw));
                showPasswordIcon.hidden = isPw;
                hidePasswordIcon.hidden = !isPw;
            }});

            form.addEventListener('submit', async function(e) {{
                e.preventDefault();
                btn.disabled = true;
                btn.textContent = signingIn;
                errorBox.style.display = 'none';

                try {{
                    const email = document.getElementById('email').value;
                    const discoveryResponse = await fetch('/realms/' + encodeURIComponent(realmName) +
                        '/organization/identity-provider?email=' + encodeURIComponent(email));
                    if (discoveryResponse.ok) {{
                        const discovery = await discoveryResponse.json();
                        if (discovery.identity_provider) {{
                            const isSaml = discovery.identity_provider.provider_type === 'saml';
                            const social = new URL('/realms/' + encodeURIComponent(realmName) +
                                (isSaml ? '/protocol/saml/broker/' : '/protocol/openid-connect/social/') + encodeURIComponent(discovery.identity_provider.alias), window.location.origin);
                            if (returnTo) {{
                                if (isSaml) social.searchParams.set('return_to', decodeURIComponent(returnTo));
                                const authorize = new URL(decodeURIComponent(returnTo), window.location.origin);
                                if (!isSaml) ['client_id', 'redirect_uri', 'state', 'nonce', 'code_challenge',
                                 'code_challenge_method', 'scope'].forEach(function(name) {{
                                    const value = authorize.searchParams.get(name);
                                    if (value) social.searchParams.set(name, value);
                                }});
                            }}
                            window.location.href = social.toString();
                            return;
                        }}
                    }}
                    const res = await fetch('/realms/' + encodeURIComponent(realmName) + '/login', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{
                            email: document.getElementById('email').value,
                            password: pwInput.value,
                            realm: realmName
                        }})
                    }});
                    const data = await res.json();
                    if (!res.ok) {{
                        throw new Error(data.error_description || data.error || loginFailed);
                    }}
                    if (data.mfa_required || data.required_actions_pending) {{
                        const login = new URL('/login', window.location.origin);
                        login.searchParams.set('realm', realmName);
                        if (returnTo) login.searchParams.set('return_to', decodeURIComponent(returnTo));
                        window.location.href = login.toString();
                        return;
                    }}
                    // Store tokens in sessionStorage for SPA usage
                    sessionStorage.setItem('access_token', data.access_token);
                    sessionStorage.setItem('refresh_token', data.refresh_token);
                    if (returnTo) {{
                        let url = decodeURIComponent(returnTo);
                        if (stateParam) url += (url.includes('?') ? '&' : '?') + 'state=' + encodeURIComponent(stateParam);
                        window.location.href = url;
                    }} else {{
                        window.location.href = '/';
                    }}
                }} catch (err) {{
                    errorBox.textContent = err.message;
                    errorBox.style.display = 'block';
                    btn.disabled = false;
                    btn.textContent = signIn;
                }}
            }});
        }})();
    </script>
</body>
</html>"##,
        locale = oidc_core::models::realm_presentation::escape_html(&locale),
        title = html_escape(login_title),
        page_title = html_escape(&presentation.message(&locale, "page_title")),
        favicon = if theme.favicon_url.is_empty() {
            String::new()
        } else {
            format!(
                r#"<link rel="icon" href="{}">"#,
                html_escape(&theme.favicon_url)
            )
        },
        primary = theme.primary_color,
        background = theme.background_color,
        card = theme.card_color,
        text = theme.text_color,
        font = html_escape(&theme.font_family),
        logo = if theme.logo_url.is_empty() {
            String::new()
        } else {
            format!(
                r#"<img src="{}" alt="Logo" class="logo" />"#,
                html_escape(&theme.logo_url)
            )
        },
        subtitle = html_escape(&presentation.message(&locale, "subtitle")),
        email_label = html_escape(&presentation.message(&locale, "email")),
        email_placeholder = html_escape(&presentation.message(&locale, "email_placeholder")),
        password_label = html_escape(&presentation.message(&locale, "password")),
        toggle_password = html_escape(&presentation.message(&locale, "toggle_password")),
        sign_in = html_escape(&presentation.message(&locale, "sign_in")),
        footer = html_escape(&theme.footer_text),
        realm_path = html_escape(&realm),
        return_to = if return_to.is_empty() {
            "null".to_string()
        } else {
            serde_json::to_string(&return_to).unwrap_or_else(|_| "null".into())
        },
        state_param = if state_param.is_empty() {
            "null".to_string()
        } else {
            serde_json::to_string(&state_param).unwrap_or_else(|_| "null".into())
        },
        realm_json = serde_json::to_string(&realm).unwrap_or_else(|_| "null".into()),
        signing_in_json =
            serde_json::to_string(&presentation.message(&locale, "signing_in")).unwrap(),
        sign_in_json = serde_json::to_string(&presentation.message(&locale, "sign_in")).unwrap(),
        login_failed_json =
            serde_json::to_string(&presentation.message(&locale, "login_failed")).unwrap(),
        script_nonce = script_nonce,
    );

    let mut response = Html(html).into_response();
    let policy = format!(
        "default-src 'self'; script-src 'nonce-{script_nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    );
    if let Ok(value) = axum::http::HeaderValue::from_str(&policy) {
        response
            .headers_mut()
            .insert(axum::http::header::CONTENT_SECURITY_POLICY, value);
    }
    response
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
