use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use oidc_core::models::SamlServiceProvider;
use oidc_repository::repositories::saml_repo::SamlRepo;
use saml::SpDescriptor;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    admin_or_forbidden, bad_request, conflict, connect, internal_error, not_found,
    realm_or_forbidden, scoped_realm,
};
use crate::{middleware::admin_auth::AdminAuth, state::AppState};

#[derive(Deserialize)]
pub struct ListQuery {
    realm_id: Option<Uuid>,
}
#[derive(Deserialize)]
pub struct CreateRequest {
    realm_id: Uuid,
    name: String,
    metadata_xml: String,
    enabled: Option<bool>,
    require_signed_requests: Option<bool>,
    sign_responses: Option<bool>,
    sign_assertions: Option<bool>,
    encrypt_assertions: Option<bool>,
    attribute_mapping: Option<Value>,
}
#[derive(Deserialize)]
pub struct UpdateRequest {
    name: Option<String>,
    metadata_xml: Option<String>,
    enabled: Option<bool>,
    require_signed_requests: Option<bool>,
    sign_responses: Option<bool>,
    sign_assertions: Option<bool>,
    encrypt_assertions: Option<bool>,
    attribute_mapping: Option<Value>,
}

fn view(sp: &SamlServiceProvider) -> Value {
    json!({"id":sp.id,"realm_id":sp.realm_id,"name":sp.name,"entity_id":sp.entity_id,"metadata_xml":sp.metadata_xml,"enabled":sp.enabled,"require_signed_requests":sp.require_signed_requests,"sign_responses":sp.sign_responses,"sign_assertions":sp.sign_assertions,"encrypt_assertions":sp.encrypt_assertions,"attribute_mapping":sp.attribute_mapping})
}
fn invalid(message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error":"invalid_saml_metadata","error_description":message.into()})),
    )
        .into_response()
}

pub async fn list(
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let realm = match scoped_realm(&auth, q.realm_id) {
        Ok(Some(v)) => v,
        Ok(None) => return bad_request(),
        Err(r) => return r,
    };
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match SamlRepo.list_service_providers(&mut c, realm).await {
        Ok(items) => {
            let rows: Vec<_> = items.iter().map(view).collect();
            Json(json!({"items":rows,"total":rows.len()})).into_response()
        }
        Err(e) => {
            tracing::error!("list SAML clients: {e}");
            internal_error()
        }
    }
}
pub async fn create(
    State(state): State<AppState>,
    auth: AdminAuth,
    Json(req): Json<CreateRequest>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    if let Some(r) = realm_or_forbidden(&auth, req.realm_id) {
        return r;
    }
    if req.name.trim().is_empty() {
        return invalid("Name is required");
    }
    let descriptor = match SpDescriptor::from_metadata_xml(req.metadata_xml.as_bytes()) {
        Ok(v) => v,
        Err(e) => return invalid(format!("Service provider metadata is invalid: {e}")),
    };
    if descriptor.assertion_consumer_services.is_empty() {
        return invalid("Metadata must contain an Assertion Consumer Service");
    }
    let now = chrono::Utc::now();
    let sp=SamlServiceProvider{id:Uuid::now_v7(),realm_id:req.realm_id,name:req.name.trim().into(),entity_id:descriptor.entity_id,metadata_xml:req.metadata_xml,enabled:req.enabled.unwrap_or(true),require_signed_requests:req.require_signed_requests.unwrap_or(true),sign_responses:req.sign_responses.unwrap_or(false),sign_assertions:req.sign_assertions.unwrap_or(true),encrypt_assertions:req.encrypt_assertions.unwrap_or(false),attribute_mapping:req.attribute_mapping.unwrap_or_else(||json!({"email":"email","given_name":"firstName","family_name":"lastName","groups":"groups"})),created_at:now,updated_at:now,deleted_at:None};
    if sp.encrypt_assertions && descriptor.encryption_certs.is_empty() {
        return invalid("Encryption is enabled but the metadata has no encryption certificate");
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match SamlRepo.create_service_provider(&mut c, &sp).await {
        Ok(()) => (StatusCode::CREATED, Json(view(&sp))).into_response(),
        Err(oidc_core::OidcError::Conflict(_)) => conflict(),
        Err(e) => {
            tracing::error!("create SAML client: {e}");
            internal_error()
        }
    }
}
pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: AdminAuth,
    Json(req): Json<UpdateRequest>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut sp = match SamlRepo.find_service_provider(&mut c, id).await {
        Ok(Some(v)) => v,
        Ok(None) => return not_found(),
        Err(_) => return internal_error(),
    };
    if let Some(r) = realm_or_forbidden(&auth, sp.realm_id) {
        return r;
    }
    if let Some(v) = req.name {
        if v.trim().is_empty() {
            return invalid("Name is required");
        }
        sp.name = v.trim().into()
    }
    if let Some(v) = req.metadata_xml {
        let d = match SpDescriptor::from_metadata_xml(v.as_bytes()) {
            Ok(v) => v,
            Err(e) => return invalid(format!("Service provider metadata is invalid: {e}")),
        };
        if d.entity_id != sp.entity_id {
            return invalid("The entity ID cannot be changed; create a new client");
        };
        sp.metadata_xml = v
    }
    if let Some(v) = req.enabled {
        sp.enabled = v
    }
    if let Some(v) = req.require_signed_requests {
        sp.require_signed_requests = v
    }
    if let Some(v) = req.sign_responses {
        sp.sign_responses = v
    }
    if let Some(v) = req.sign_assertions {
        sp.sign_assertions = v
    }
    if let Some(v) = req.encrypt_assertions {
        sp.encrypt_assertions = v
    }
    if let Some(v) = req.attribute_mapping {
        sp.attribute_mapping = v
    }
    if sp.encrypt_assertions {
        let d = match SpDescriptor::from_metadata_xml(sp.metadata_xml.as_bytes()) {
            Ok(v) => v,
            Err(e) => return invalid(format!("Service provider metadata is invalid: {e}")),
        };
        if d.encryption_certs.is_empty() {
            return invalid("Encryption is enabled but the metadata has no encryption certificate");
        }
    }
    match SamlRepo.update_service_provider(&mut c, &sp).await {
        Ok(()) => Json(view(&sp)).into_response(),
        Err(oidc_core::OidcError::Conflict(_)) => conflict(),
        Err(_) => internal_error(),
    }
}
pub async fn delete_client(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let sp = match SamlRepo.find_service_provider(&mut c, id).await {
        Ok(Some(v)) => v,
        Ok(None) => return not_found(),
        Err(_) => return internal_error(),
    };
    if let Some(r) = realm_or_forbidden(&auth, sp.realm_id) {
        return r;
    }
    match SamlRepo.delete_service_provider(&mut c, id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => internal_error(),
    }
}
