use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use oidc_core::OidcError;
use oidc_core::models::{
    Organization, OrganizationDomain, OrganizationDomainKind, OrganizationInvitation,
    OrganizationInvitationStatus, OrganizationMembership, OrganizationMembershipKind,
};
use oidc_core::utils::{generate_opaque_token, generate_uuid_v7, is_valid_email, sha2_256_hex};
use oidc_repository::Connection;
use oidc_repository::mapper::pg_err;
use oidc_repository::repositories::group_repo::GroupRepo;
use oidc_repository::repositories::identity_provider_repo::IdentityProviderRepo;
use oidc_repository::repositories::organization_repo::OrganizationRepo;
use oidc_repository::repositories::user_repo::UserRepo;
use oidc_repository::with_transaction;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::middleware::admin_auth::AdminAuth;
use crate::router::admin::{admin_or_forbidden, connect, internal_error, not_found};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct ListQuery {
    realm_id: Uuid,
    search: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 {
    20
}

#[derive(Deserialize)]
pub struct CreateRequest {
    realm_id: Uuid,
    name: String,
    alias: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
    #[serde(default = "empty_object")]
    attributes: Value,
    #[serde(default)]
    claim_attribute_names: Vec<String>,
    redirect_url: Option<String>,
}

fn default_enabled() -> bool {
    true
}

fn empty_object() -> Value {
    json!({})
}

#[derive(Deserialize)]
pub struct UpdateRequest {
    name: Option<String>,
    alias: Option<String>,
    enabled: Option<bool>,
    attributes: Option<Value>,
    claim_attribute_names: Option<Vec<String>>,
    redirect_url: Option<String>,
}

#[derive(Deserialize)]
pub struct AddDomainRequest {
    domain: String,
    #[serde(default)]
    wildcard: bool,
}

#[derive(Deserialize)]
pub struct AddMemberRequest {
    user_id: Uuid,
}

#[derive(Deserialize)]
pub struct LinkIdentityProviderRequest {
    identity_provider_id: Uuid,
    #[serde(default)]
    redirect_on_email_domain: bool,
}

#[derive(Deserialize)]
pub struct LinkGroupRequest {
    group_id: Uuid,
}

pub async fn list_groups(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    if let Err(response) = load_authorized_organization(&mut conn, id, &auth).await {
        return response;
    }
    match OrganizationRepo.list_groups(&mut conn, id).await {
        Ok(groups) => Json(json!({"items": groups})).into_response(),
        Err(error) => repository_error("list organization groups", error),
    }
}

pub async fn link_group(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: AdminAuth,
    Json(request): Json<LinkGroupRequest>,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    let organization = match load_authorized_organization(&mut conn, id, &auth).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let group = match GroupRepo.find_by_id(&mut conn, request.group_id).await {
        Ok(Some(value)) => value,
        Ok(None) => return invalid("group does not exist"),
        Err(error) => return repository_error("get organization group", error),
    };
    if group.realm_id != organization.realm_id {
        return invalid("group and organization must belong to the same realm");
    }
    match OrganizationRepo.link_group(&mut conn, id, group.id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => repository_error("link organization group", error),
    }
}

pub async fn unlink_group(
    State(state): State<AppState>,
    Path((id, group_id)): Path<(Uuid, Uuid)>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    if let Err(response) = load_authorized_organization(&mut conn, id, &auth).await {
        return response;
    }
    match OrganizationRepo.unlink_group(&mut conn, id, group_id).await {
        Ok(0) => not_found(),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => repository_error("unlink organization group", error),
    }
}

#[derive(Deserialize)]
pub struct CreateInvitationRequest {
    email: String,
    first_name: Option<String>,
    last_name: Option<String>,
    #[serde(default = "default_invitation_ttl_hours")]
    expires_in_hours: i64,
}

fn default_invitation_ttl_hours() -> i64 {
    72
}

pub async fn list(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    if !(1..=100).contains(&query.limit) || query.offset < 0 {
        return invalid("limit must be 1..=100 and offset must be non-negative");
    }
    if auth.realm_id.is_some() && auth.realm_id != Some(query.realm_id) {
        return forbidden();
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    let (items, total) = if auth.has_permission("organizations:view") {
        let items = match OrganizationRepo
            .list(
                &mut conn,
                query.realm_id,
                query.search.as_deref(),
                query.limit,
                query.offset,
            )
            .await
        {
            Ok(items) => items,
            Err(error) => return repository_error("list organizations", error),
        };
        let total = match OrganizationRepo.count(&mut conn, query.realm_id).await {
            Ok(total) => total,
            Err(error) => return repository_error("count organizations", error),
        };
        (items, total)
    } else {
        let search = query.search.as_deref().map(str::to_ascii_lowercase);
        let mut authorized = Vec::new();
        for id in auth.organization_ids_with_permission("view") {
            match OrganizationRepo.find_by_id(&mut conn, id).await {
                Ok(Some(value))
                    if value.realm_id == query.realm_id
                        && search.as_ref().is_none_or(|term| {
                            value.name.to_ascii_lowercase().contains(term)
                                || value.alias.to_ascii_lowercase().contains(term)
                        }) =>
                {
                    authorized.push(value)
                }
                Ok(_) => {}
                Err(error) => return repository_error("list authorized organizations", error),
            }
        }
        authorized.sort_by(|left, right| left.name.cmp(&right.name));
        let total = authorized.len() as i64;
        let items = authorized
            .into_iter()
            .skip(query.offset as usize)
            .take(query.limit as usize)
            .collect();
        (items, total)
    };
    Json(json!({"items": items, "total": total})).into_response()
}

pub async fn get(State(state): State<AppState>, Path(id): Path<Uuid>, auth: AdminAuth) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    match load_authorized_organization(&mut conn, id, &auth).await {
        Ok(organization) => Json(organization).into_response(),
        Err(response) => response,
    }
}

pub async fn create(
    State(state): State<AppState>,
    auth: AdminAuth,
    Json(request): Json<CreateRequest>,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    if auth.realm_id.is_some() && auth.realm_id != Some(request.realm_id) {
        return forbidden();
    }
    let now = Utc::now();
    let organization = Organization {
        id: generate_uuid_v7(),
        realm_id: request.realm_id,
        name: request.name.trim().to_string(),
        alias: request.alias.trim().to_ascii_lowercase(),
        enabled: request.enabled,
        attributes: request.attributes,
        claim_attribute_names: request.claim_attribute_names,
        redirect_url: request
            .redirect_url
            .filter(|value| !value.trim().is_empty()),
        created_at: now,
        updated_at: now,
    };
    if let Err(error) = organization.validate() {
        return invalid(&error.to_string());
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    match OrganizationRepo.create(&mut conn, &organization).await {
        Ok(()) => (StatusCode::CREATED, Json(organization)).into_response(),
        Err(error) => repository_error("create organization", error),
    }
}

pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: AdminAuth,
    Json(request): Json<UpdateRequest>,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    let mut organization = match OrganizationRepo.find_by_id(&mut conn, id).await {
        Ok(Some(organization)) => organization,
        Ok(None) => return not_found(),
        Err(error) => return repository_error("get organization for update", error),
    };
    if auth.realm_id.is_some() && auth.realm_id != Some(organization.realm_id) {
        return forbidden();
    }
    if let Some(name) = request.name {
        organization.name = name.trim().to_string();
    }
    if let Some(alias) = request.alias {
        if alias.trim().to_ascii_lowercase() != organization.alias {
            return invalid("organization alias is immutable");
        }
    }
    if let Some(enabled) = request.enabled {
        organization.enabled = enabled;
    }
    if let Some(attributes) = request.attributes {
        organization.attributes = attributes;
    }
    if let Some(names) = request.claim_attribute_names {
        organization.claim_attribute_names = names;
    }
    if let Some(redirect_url) = request.redirect_url {
        organization.redirect_url =
            (!redirect_url.trim().is_empty()).then(|| redirect_url.trim().to_string());
    }
    organization.updated_at = Utc::now();
    if let Err(error) = organization.validate() {
        return invalid(&error.to_string());
    }
    match OrganizationRepo.update(&mut conn, &organization).await {
        Ok(()) => Json(organization).into_response(),
        Err(error) => repository_error("update organization", error),
    }
}

pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    if let Err(response) = load_authorized_organization(&mut conn, id, &auth).await {
        return response;
    }
    match with_transaction!(conn, pg_err, {
        OrganizationRepo.delete(&mut conn, id).await?;
        Ok(())
    }) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => repository_error("delete organization", error),
    }
}

pub async fn list_domains(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    if let Err(response) = load_authorized_organization(&mut conn, id, &auth).await {
        return response;
    }
    match OrganizationRepo.list_domains(&mut conn, id).await {
        Ok(domains) => Json(json!({"items": domains})).into_response(),
        Err(error) => repository_error("list organization domains", error),
    }
}

pub async fn add_domain(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: AdminAuth,
    Json(request): Json<AddDomainRequest>,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let verification_token = match generate_opaque_token() {
        Ok(value) => value,
        Err(error) => return repository_error("generate domain verification token", error),
    };
    let domain = OrganizationDomain {
        id: generate_uuid_v7(),
        organization_id: id,
        domain: request.domain.trim().to_ascii_lowercase(),
        kind: if request.wildcard {
            OrganizationDomainKind::Wildcard
        } else {
            OrganizationDomainKind::Exact
        },
        verified: false,
        verification_token_hash: Some(sha2_256_hex(&verification_token)),
    };
    if let Err(error) = domain.validate() {
        return invalid(&error.to_string());
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    if let Err(response) = load_authorized_organization(&mut conn, id, &auth).await {
        return response;
    }
    match OrganizationRepo.add_domain(&mut conn, &domain).await {
        Ok(()) => (StatusCode::CREATED, Json(json!({
            "domain": domain,
            "verification_record": {"name": format!("_oidc-org.{}", domain.domain), "value": format!("oidc-org-verification={verification_token}")}
        }))).into_response(),
        Err(error) => repository_error("add organization domain", error),
    }
}

pub async fn verify_domain(
    State(state): State<AppState>,
    Path((id, domain_id)): Path<(Uuid, Uuid)>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    if let Err(response) = load_authorized_organization(&mut conn, id, &auth).await {
        return response;
    }
    let domain = match OrganizationRepo.list_domains(&mut conn, id).await {
        Ok(values) => match values.into_iter().find(|value| value.id == domain_id) {
            Some(value) => value,
            None => return not_found(),
        },
        Err(error) => return repository_error("get organization domain", error),
    };
    if domain.verified {
        return Json(domain).into_response();
    }
    let expected = match domain.verification_token_hash.as_deref() {
        Some(value) => value,
        None => return invalid("domain has no pending verification"),
    };
    let record_name = format!("_oidc-org.{}", domain.domain);
    let records = match crate::dns_verifier::txt_records(&record_name).await {
        Ok(values) => values,
        Err(error) => return repository_error("verify organization domain", error),
    };
    let matches = records.iter().any(|record| {
        record
            .strip_prefix("oidc-org-verification=")
            .is_some_and(|token| sha2_256_hex(token) == expected)
    });
    if !matches {
        return invalid("the expected DNS TXT verification record was not found");
    }
    match OrganizationRepo
        .verify_domain(&mut conn, id, domain_id, expected)
        .await
    {
        Ok(1) => {
            let mut verified = domain;
            verified.verified = true;
            verified.verification_token_hash = None;
            Json(verified).into_response()
        }
        Ok(_) => invalid("domain verification is no longer pending"),
        Err(error) => repository_error("save organization domain verification", error),
    }
}

pub async fn delete_domain(
    State(state): State<AppState>,
    Path((id, domain_id)): Path<(Uuid, Uuid)>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    if let Err(response) = load_authorized_organization(&mut conn, id, &auth).await {
        return response;
    }
    match OrganizationRepo
        .delete_domain(&mut conn, id, domain_id)
        .await
    {
        Ok(0) => not_found(),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => repository_error("delete organization domain", error),
    }
}

pub async fn list_members(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    if let Err(response) = load_authorized_organization(&mut conn, id, &auth).await {
        return response;
    }
    match OrganizationRepo.list_members(&mut conn, id).await {
        Ok(members) => Json(json!({"items": members, "total": members.len()})).into_response(),
        Err(error) => repository_error("list organization members", error),
    }
}

pub async fn add_member(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: AdminAuth,
    Json(request): Json<AddMemberRequest>,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let membership = OrganizationMembership {
        organization_id: id,
        user_id: request.user_id,
        kind: OrganizationMembershipKind::Unmanaged,
        joined_at: Utc::now(),
    };
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    let organization = match load_authorized_organization(&mut conn, id, &auth).await {
        Ok(organization) => organization,
        Err(response) => return response,
    };
    let user = match UserRepo.find_by_id(&mut conn, request.user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return invalid("user does not exist"),
        Err(error) => return repository_error("get organization member", error),
    };
    if user.realm_id != organization.realm_id {
        return invalid("user and organization must belong to the same realm");
    }
    match OrganizationRepo.add_member(&mut conn, &membership).await {
        Ok(()) => (StatusCode::CREATED, Json(membership)).into_response(),
        Err(error) => repository_error("add organization member", error),
    }
}

pub async fn remove_member(
    State(state): State<AppState>,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    if let Err(response) = load_authorized_organization(&mut conn, id, &auth).await {
        return response;
    }
    match with_transaction!(conn, pg_err, {
        OrganizationRepo
            .remove_member(&mut conn, id, user_id)
            .await?;
        Ok(())
    }) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => repository_error("remove organization member", error),
    }
}

pub async fn list_identity_providers(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    if let Err(response) = load_authorized_organization(&mut conn, id, &auth).await {
        return response;
    }
    match OrganizationRepo
        .list_identity_providers(&mut conn, id)
        .await
    {
        Ok(providers) => Json(json!({"items": providers})).into_response(),
        Err(error) => repository_error("list organization identity providers", error),
    }
}

pub async fn link_identity_provider(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: AdminAuth,
    Json(request): Json<LinkIdentityProviderRequest>,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    let organization = match load_authorized_organization(&mut conn, id, &auth).await {
        Ok(organization) => organization,
        Err(response) => return response,
    };
    let provider = match IdentityProviderRepo
        .find_by_id(&mut conn, request.identity_provider_id)
        .await
    {
        Ok(Some(provider)) => provider,
        Ok(None) => return invalid("identity provider does not exist"),
        Err(error) => return repository_error("get identity provider for organization", error),
    };
    if provider.realm_id != organization.realm_id {
        return invalid("identity provider and organization must belong to the same realm");
    }
    match OrganizationRepo
        .link_identity_provider(
            &mut conn,
            id,
            request.identity_provider_id,
            request.redirect_on_email_domain,
        )
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => repository_error("link organization identity provider", error),
    }
}

pub async fn unlink_identity_provider(
    State(state): State<AppState>,
    Path((id, identity_provider_id)): Path<(Uuid, Uuid)>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    if let Err(response) = load_authorized_organization(&mut conn, id, &auth).await {
        return response;
    }
    match OrganizationRepo
        .unlink_identity_provider(&mut conn, id, identity_provider_id)
        .await
    {
        Ok(0) => not_found(),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => repository_error("unlink organization identity provider", error),
    }
}

pub async fn list_invitations(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    if let Err(response) = load_authorized_organization(&mut conn, id, &auth).await {
        return response;
    }
    match OrganizationRepo.list_invitations(&mut conn, id).await {
        Ok(invitations) => {
            Json(json!({"items": invitations, "total": invitations.len()})).into_response()
        }
        Err(error) => repository_error("list organization invitations", error),
    }
}

pub async fn create_invitation(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: AdminAuth,
    Json(request): Json<CreateInvitationRequest>,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let email = request.email.trim().to_ascii_lowercase();
    if !is_valid_email(&email) {
        return invalid("a valid email address is required");
    }
    if !(1..=720).contains(&request.expires_in_hours) {
        return invalid("expires_in_hours must be between 1 and 720");
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    let organization = match load_authorized_organization(&mut conn, id, &auth).await {
        Ok(organization) => organization,
        Err(response) => return response,
    };
    let token = match generate_opaque_token() {
        Ok(token) => token,
        Err(error) => return repository_error("generate organization invitation", error),
    };
    let now = Utc::now();
    let invitation = OrganizationInvitation {
        id: generate_uuid_v7(),
        organization_id: id,
        email: email.clone(),
        first_name: request.first_name.filter(|value| !value.trim().is_empty()),
        last_name: request.last_name.filter(|value| !value.trim().is_empty()),
        token_hash: sha2_256_hex(&token),
        status: OrganizationInvitationStatus::Pending,
        invited_by: if auth.is_api_key {
            None
        } else {
            auth.subject.parse().ok()
        },
        expires_at: now + chrono::Duration::hours(request.expires_in_hours),
        created_at: now,
        accepted_at: None,
    };
    if let Err(error) = OrganizationRepo
        .create_invitation(&mut conn, &invitation)
        .await
    {
        return repository_error("create organization invitation", error);
    }

    let invitation_url = format!(
        "{}/accept-invitation?token={}",
        state.config.issuer.trim_end_matches('/'),
        urlencoding::encode(&token)
    );
    if let Err(error) = state
        .email_sender
        .send_organization_invitation(&email, &organization.name, &invitation_url)
        .await
    {
        tracing::warn!("failed to send organization invitation to {email}: {error}");
    }

    (StatusCode::CREATED, Json(invitation)).into_response()
}

pub async fn revoke_invitation(
    State(state): State<AppState>,
    Path((id, invitation_id)): Path<(Uuid, Uuid)>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    if let Err(response) = load_authorized_organization(&mut conn, id, &auth).await {
        return response;
    }
    match OrganizationRepo
        .revoke_invitation(&mut conn, id, invitation_id)
        .await
    {
        Ok(0) => not_found(),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => repository_error("revoke organization invitation", error),
    }
}

fn invalid(message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": "invalid_request", "error_description": message})),
    )
        .into_response()
}

fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, Json(json!({"error": "forbidden"}))).into_response()
}

async fn load_authorized_organization(
    conn: &mut Connection,
    id: Uuid,
    auth: &AdminAuth,
) -> Result<Organization, Response> {
    let organization = match OrganizationRepo.find_by_id(conn, id).await {
        Ok(Some(organization)) => organization,
        Ok(None) => return Err(not_found()),
        Err(error) => return Err(repository_error("get organization", error)),
    };
    if auth.realm_id.is_some() && auth.realm_id != Some(organization.realm_id) {
        return Err(forbidden());
    }
    Ok(organization)
}

fn repository_error(operation: &str, error: OidcError) -> Response {
    match error {
        OidcError::Conflict(_) => (
            StatusCode::CONFLICT,
            Json(json!({"error": "conflict", "error_description": "the organization resource already exists"})),
        )
            .into_response(),
        OidcError::NotFound(_) => not_found(),
        OidcError::InvalidInput(message) => invalid(&message),
        error => {
            tracing::error!(operation, "organization repository error: {error}");
            internal_error()
        }
    }
}
