use chrono::Utc;
use oidc_core::OidcError;
use oidc_core::models::{
    DirectoryUser, FederatedDirectoryUser, Group, User, UserFederationProvider,
};
use oidc_core::utils::generate_uuid_v7;
use oidc_repository::Connection;
use oidc_repository::repositories::group_repo::GroupRepo;
use oidc_repository::repositories::user_federation_repo::UserFederationRepo;
use oidc_repository::repositories::user_group_repo::UserGroupRepo;
use oidc_repository::repositories::user_repo::UserRepo;
use serde::{Deserialize, Serialize};

use crate::state::OidcState;

#[derive(Debug, Serialize)]
struct GatewayRequest<'a> {
    provider_type: String,
    config: &'a serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    identifier: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    negotiate_token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
pub struct GatewayTestResponse {
    pub ok: bool,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Deserialize)]
struct AuthenticationResponse {
    authenticated: bool,
    #[serde(default)]
    user: Option<DirectoryUser>,
}

#[derive(Debug, Deserialize)]
pub struct GatewayUsersResponse {
    #[serde(default)]
    pub users: Vec<DirectoryUser>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

pub async fn test_provider(
    state: &OidcState,
    provider: &UserFederationProvider,
) -> Result<GatewayTestResponse, OidcError> {
    if provider.uses_direct_directory() {
        let message = crate::direct_ldap::test_connection(state, provider).await?;
        return Ok(GatewayTestResponse { ok: true, message });
    }
    gateway_post(
        state,
        provider,
        "test",
        &GatewayRequest {
            provider_type: provider.provider_type.to_string(),
            config: &provider.config,
            identifier: None,
            password: None,
            negotiate_token: None,
            cursor: None,
        },
    )
    .await
}

pub async fn authenticate(
    state: &OidcState,
    provider: &UserFederationProvider,
    identifier: &str,
    password: &str,
) -> Result<Option<DirectoryUser>, OidcError> {
    if provider.uses_direct_directory() {
        return crate::direct_ldap::authenticate(state, provider, identifier, password).await;
    }
    let response: AuthenticationResponse = gateway_post(
        state,
        provider,
        "authenticate",
        &GatewayRequest {
            provider_type: provider.provider_type.to_string(),
            config: &provider.config,
            identifier: Some(identifier),
            password: Some(password),
            negotiate_token: None,
            cursor: None,
        },
    )
    .await?;
    if !response.authenticated {
        return Ok(None);
    }
    let user = response.user.ok_or_else(|| {
        OidcError::Internal("federation gateway omitted authenticated user".into())
    })?;
    user.validate()?;
    Ok(Some(user))
}

pub async fn authenticate_kerberos(
    state: &OidcState,
    provider: &UserFederationProvider,
    negotiate_token: &str,
) -> Result<Option<DirectoryUser>, OidcError> {
    let response: AuthenticationResponse = gateway_post(
        state,
        provider,
        "kerberos/verify",
        &GatewayRequest {
            provider_type: provider.provider_type.to_string(),
            config: &provider.config,
            identifier: None,
            password: None,
            negotiate_token: Some(negotiate_token),
            cursor: None,
        },
    )
    .await?;
    if !response.authenticated {
        return Ok(None);
    }
    let user = response.user.ok_or_else(|| {
        OidcError::Internal("federation gateway omitted authenticated user".into())
    })?;
    user.validate()?;
    Ok(Some(user))
}

pub async fn list_gateway_users(
    state: &OidcState,
    provider: &UserFederationProvider,
    cursor: Option<&str>,
) -> Result<GatewayUsersResponse, OidcError> {
    if provider.uses_direct_directory() {
        let (users, next_cursor) = crate::direct_ldap::list_users(state, provider, cursor).await?;
        return Ok(GatewayUsersResponse { users, next_cursor });
    }
    let response: GatewayUsersResponse = gateway_post(
        state,
        provider,
        "users",
        &GatewayRequest {
            provider_type: provider.provider_type.to_string(),
            config: &provider.config,
            identifier: None,
            password: None,
            negotiate_token: None,
            cursor,
        },
    )
    .await?;
    for user in &response.users {
        user.validate()?;
    }
    Ok(response)
}

pub async fn import_user(
    conn: &mut Connection,
    provider: &UserFederationProvider,
    directory: &DirectoryUser,
    login: bool,
) -> Result<User, OidcError> {
    if let Some(link) = UserFederationRepo
        .find_link_by_external_id(conn, provider.id, &directory.external_id)
        .await?
    {
        let mut user = UserRepo
            .find_by_id(conn, link.user_id)
            .await?
            .ok_or_else(|| OidcError::Internal("federated user link has no local user".into()))?;
        apply_directory_values(&mut user, directory);
        UserRepo.update(conn, &user).await?;
        store_link(conn, provider, &user, directory, login).await?;
        sync_groups(conn, provider, &user, directory).await?;
        return Ok(user);
    }

    let existing = UserRepo
        .find_by_email(conn, provider.realm_id, &directory.email)
        .await?;
    if existing.is_some()
        && !provider
            .config
            .get("link_existing_users")
            .and_then(|value| value.as_bool())
            .unwrap_or(false)
    {
        return Err(OidcError::AuthenticationFailed(
            "a local user already owns this email address".into(),
        ));
    }
    let mut user = existing.unwrap_or_else(|| new_user(provider.realm_id, directory));
    apply_directory_values(&mut user, directory);
    if UserRepo.find_by_id(conn, user.id).await?.is_some() {
        UserRepo.update(conn, &user).await?;
    } else if provider.import_users {
        UserRepo.create(conn, &user).await?;
    } else {
        return Err(OidcError::AuthenticationFailed(
            "user import is disabled".into(),
        ));
    }
    store_link(conn, provider, &user, directory, login).await?;
    sync_groups(conn, provider, &user, directory).await?;
    Ok(user)
}

async fn store_link(
    conn: &mut Connection,
    provider: &UserFederationProvider,
    user: &User,
    directory: &DirectoryUser,
    login: bool,
) -> Result<(), OidcError> {
    let now = Utc::now();
    UserFederationRepo
        .upsert_link(
            conn,
            &FederatedDirectoryUser {
                id: generate_uuid_v7(),
                provider_id: provider.id,
                user_id: user.id,
                external_id: directory.external_id.clone(),
                external_username: directory.username.clone(),
                external_dn: directory.dn.clone(),
                last_login_at: login.then_some(now),
                last_synced_at: now,
            },
        )
        .await
}

async fn sync_groups(
    conn: &mut Connection,
    provider: &UserFederationProvider,
    user: &User,
    directory: &DirectoryUser,
) -> Result<(), OidcError> {
    if !provider.sync_groups {
        return Ok(());
    }
    for name in &directory.groups {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let group = match GroupRepo
            .find_by_name(conn, provider.realm_id, name)
            .await?
        {
            Some(group) => group,
            None => {
                let now = Utc::now();
                let group = Group {
                    id: generate_uuid_v7(),
                    realm_id: provider.realm_id,
                    name: name.into(),
                    description: Some(format!("Synchronized from {}", provider.name)),
                    parent_id: None,
                    created_at: now,
                    updated_at: now,
                };
                GroupRepo.create(conn, &group).await?;
                group
            }
        };
        if !UserGroupRepo
            .find_groups_by_user(conn, user.id)
            .await?
            .iter()
            .any(|existing| existing.id == group.id)
        {
            UserGroupRepo.assign(conn, user.id, group.id).await?;
        }
    }
    Ok(())
}

fn new_user(realm_id: uuid::Uuid, directory: &DirectoryUser) -> User {
    User {
        id: generate_uuid_v7(),
        realm_id,
        email: directory.email.clone(),
        email_verified: true,
        username: Some(directory.username.clone()),
        password_hash: None,
        given_name: directory.given_name.clone(),
        family_name: directory.family_name.clone(),
        middle_name: None,
        nickname: None,
        preferred_username: Some(directory.username.clone()),
        profile: None,
        picture: None,
        website: None,
        gender: None,
        birthdate: None,
        zoneinfo: None,
        phone_number: None,
        phone_number_verified: None,
        street_address: None,
        locality: None,
        region: None,
        postal_code: None,
        country: None,
        locale: "en".into(),
        attributes: directory.attributes.clone(),
        enabled: directory.enabled,
        deleted_at: None,
        updated_at: Utc::now(),
    }
}

fn apply_directory_values(user: &mut User, directory: &DirectoryUser) {
    user.email = directory.email.clone();
    user.email_verified = true;
    user.username = Some(directory.username.clone());
    user.preferred_username = Some(directory.username.clone());
    user.given_name = directory.given_name.clone();
    user.family_name = directory.family_name.clone();
    user.attributes = directory.attributes.clone();
    user.enabled = directory.enabled;
    user.updated_at = Utc::now();
}

async fn gateway_post<T: for<'de> Deserialize<'de>>(
    state: &OidcState,
    provider: &UserFederationProvider,
    path: &str,
    body: &GatewayRequest<'_>,
) -> Result<T, OidcError> {
    let secret = state.decrypt_sensitive_string(&provider.gateway_secret)?;
    let url = format!("{}/v1/{path}", provider.gateway_url.trim_end_matches('/'));
    let payload =
        serde_json::to_vec(body).map_err(|error| OidcError::Internal(error.to_string()))?;

    #[cfg(not(target_arch = "wasm32"))]
    {
        let response = reqwest::Client::new()
            .post(url)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {secret}"))
            .body(payload)
            .send()
            .await
            .map_err(|error| {
                OidcError::Internal(format!("federation gateway request failed: {error}"))
            })?;
        if !response.status().is_success() {
            return Err(OidcError::Internal(format!(
                "federation gateway returned HTTP {}",
                response.status()
            )));
        }
        response.json().await.map_err(|error| {
            OidcError::Internal(format!("invalid federation gateway response: {error}"))
        })
    }

    #[cfg(target_arch = "wasm32")]
    {
        let request = wstd::http::Request::post(url)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {secret}"))
            .body(wstd::http::Body::from(payload))
            .map_err(|error| {
                OidcError::Internal(format!("federation gateway request build failed: {error}"))
            })?;
        let mut response = wstd::http::Client::new()
            .send(request)
            .await
            .map_err(|error| {
                OidcError::Internal(format!("federation gateway request failed: {error}"))
            })?;
        if !response.status().is_success() {
            return Err(OidcError::Internal(format!(
                "federation gateway returned HTTP {}",
                response.status()
            )));
        }
        let bytes = response.body_mut().contents().await.map_err(|error| {
            OidcError::Internal(format!("federation gateway response read failed: {error}"))
        })?;
        serde_json::from_slice(bytes).map_err(|error| {
            OidcError::Internal(format!("invalid federation gateway response: {error}"))
        })
    }
}
