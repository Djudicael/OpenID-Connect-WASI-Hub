use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use oidc_core::models::audit_event::{ActorType, AuditEvent};
use oidc_core::utils::generate_uuid_v7;
use oidc_repository::repositories::audit_event_repo::AuditEventRepo;
use oidc_repository::repositories::realm_transfer_repo::RealmTransferRepo;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::HashSet;
use uuid::Uuid;

use super::{admin_or_forbidden, connect, internal_error, realm_or_forbidden};
use crate::middleware::admin_auth::AdminAuth;
use crate::state::AppState;

const ARCHIVE_FORMAT: &str = "openid-connect-wasi-realm";
const ARCHIVE_VERSION: u32 = 1;
const MIN_PASSWORD_LEN: usize = 12;

#[derive(Deserialize)]
pub struct ExportRequest {
    password: String,
}

#[derive(Deserialize)]
pub struct ImportRequest {
    password: String,
    archive: RealmArchive,
    #[serde(default)]
    replace_existing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmArchive {
    format: String,
    version: u32,
    realm_name: String,
    exported_at: String,
    encryption: String,
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    format: String,
    version: u32,
    exported_at: String,
    realm: Value,
    tables: Map<String, Value>,
}

fn request_error(message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error":"invalid_realm_archive","error_description":message.into()})),
    )
        .into_response()
}

fn derive_archive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let params = Params::new(19 * 1024, 2, 1, Some(32)).map_err(|e| e.to_string())?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; 32];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| e.to_string())?;
    Ok(key)
}

fn seal(snapshot: &Snapshot, password: &str, realm_name: &str) -> Result<RealmArchive, String> {
    let plaintext = serde_json::to_vec(snapshot).map_err(|e| e.to_string())?;
    let mut salt = [0_u8; 16];
    let mut nonce = [0_u8; 12];
    getrandom::fill(&mut salt).map_err(|e| e.to_string())?;
    getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
    let key = derive_archive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
        .map_err(|e| e.to_string())?;
    Ok(RealmArchive {
        format: ARCHIVE_FORMAT.into(),
        version: ARCHIVE_VERSION,
        realm_name: realm_name.into(),
        exported_at: Utc::now().to_rfc3339(),
        encryption: "argon2id-aes-256-gcm".into(),
        salt: STANDARD.encode(salt),
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(ciphertext),
    })
}

fn open(archive: &RealmArchive, password: &str) -> Result<Snapshot, String> {
    if archive.format != ARCHIVE_FORMAT
        || archive.version != ARCHIVE_VERSION
        || archive.encryption != "argon2id-aes-256-gcm"
    {
        return Err("The archive format or version is not supported".into());
    }
    let salt = STANDARD
        .decode(&archive.salt)
        .map_err(|_| "Invalid archive salt")?;
    let nonce = STANDARD
        .decode(&archive.nonce)
        .map_err(|_| "Invalid archive nonce")?;
    let ciphertext = STANDARD
        .decode(&archive.ciphertext)
        .map_err(|_| "Invalid archive content")?;
    if salt.len() != 16 || nonce.len() != 12 {
        return Err("Invalid archive encryption parameters".into());
    }
    let key = derive_archive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_slice())
        .map_err(|_| "The password is incorrect or the archive was modified")?;
    let snapshot: Snapshot =
        serde_json::from_slice(&plaintext).map_err(|_| "The archive content is invalid")?;
    if snapshot.format != ARCHIVE_FORMAT || snapshot.version != ARCHIVE_VERSION {
        return Err("The archive content version is not supported".into());
    }
    Ok(snapshot)
}

fn transform_field(
    state: &AppState,
    tables: &mut Map<String, Value>,
    table: &str,
    field: &str,
    encrypt: bool,
) -> Result<(), String> {
    let Some(rows) = tables.get_mut(table).and_then(Value::as_array_mut) else {
        return Ok(());
    };
    for row in rows {
        let Some(value) = row.get_mut(field) else {
            continue;
        };
        let Some(secret) = value.as_str() else {
            continue;
        };
        if secret.is_empty() {
            continue;
        }
        *value = Value::String(if encrypt {
            state
                .encrypt_sensitive_value(secret.as_bytes())
                .map_err(|_| format!("Could not protect {table}.{field}"))?
        } else {
            match state.decrypt_sensitive_value(secret) {
                Ok(value) => String::from_utf8(value)
                    .map_err(|_| format!("Invalid text in {table}.{field}"))?,
                // Older installations may still contain values written before
                // encryption at rest was introduced. The archive itself is encrypted.
                Err(_) => secret.to_string(),
            }
        });
    }
    Ok(())
}

fn transform_secrets(
    state: &AppState,
    tables: &mut Map<String, Value>,
    encrypt: bool,
) -> Result<(), String> {
    for (table, fields) in [
        (
            "clients",
            &[
                "client_secret_encrypted",
                "id_token_encryption_key_encrypted",
                "request_object_encryption_key_encrypted",
            ][..],
        ),
        ("signing_keys", &["private_key_pem_encrypted"]),
        (
            "realm_signing_keys",
            &["rsa_private_pem", "ed25519_private_pem"],
        ),
        ("identity_providers", &["client_secret"]),
        ("user_totp_credentials", &["secret_encrypted"]),
        ("user_federation_providers", &["gateway_secret"]),
        ("saml_realm_keys", &["private_key_encrypted"]),
    ] {
        for field in fields {
            transform_field(state, tables, table, field, encrypt)?;
        }
    }
    Ok(())
}

fn remap_realm(snapshot: &mut Snapshot, target_id: Uuid) -> Result<(), String> {
    let source = snapshot
        .realm
        .get("id")
        .and_then(Value::as_str)
        .ok_or("The archive realm ID is missing")?;
    let source_id = Uuid::parse_str(source).map_err(|_| "The archive realm ID is invalid")?;
    let source_id_text = source_id.to_string();
    snapshot.realm["id"] = Value::String(target_id.to_string());
    for rows in snapshot.tables.values_mut() {
        if let Some(rows) = rows.as_array_mut() {
            for row in rows {
                if row.get("realm_id").and_then(Value::as_str) == Some(source_id_text.as_str()) {
                    row["realm_id"] = Value::String(target_id.to_string());
                }
            }
        }
    }
    Ok(())
}

fn table_ids(tables: &Map<String, Value>, table: &str) -> HashSet<String> {
    tables
        .get(table)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|row| row.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

fn validate_reference(
    tables: &Map<String, Value>,
    table: &str,
    field: &str,
    parent: &str,
) -> Result<(), String> {
    let ids = table_ids(tables, parent);
    for row in tables
        .get(table)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(id) = row.get(field).and_then(Value::as_str)
            && !ids.contains(id)
        {
            return Err(format!("{table}.{field} refers outside the archive"));
        }
    }
    Ok(())
}

fn validate_snapshot(snapshot: &Snapshot) -> Result<(), String> {
    let realm: oidc_core::models::Realm = serde_json::from_value(snapshot.realm.clone())
        .map_err(|_| "The archive realm record is invalid")?;
    realm.validate().map_err(|e| e.to_string())?;
    let realm_id = realm.id.to_string();
    let direct = [
        "users",
        "clients",
        "signing_keys",
        "scopes",
        "realm_signing_keys",
        "identity_providers",
        "federated_identities",
        "roles",
        "groups",
        "organizations",
        "user_consents",
        "api_keys",
        "authorization_resources",
        "authorization_policies",
        "authorization_permissions",
        "user_federation_providers",
        "saml_realm_keys",
        "saml_service_providers",
    ];
    for table in direct {
        let rows = snapshot
            .tables
            .get(table)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("The archive table {table} is missing or invalid"))?;
        if rows
            .iter()
            .any(|row| row.get("realm_id").and_then(Value::as_str) != Some(realm_id.as_str()))
        {
            return Err(format!("The archive table {table} contains another realm"));
        }
    }
    for table in [
        "client_scopes",
        "user_roles",
        "user_groups",
        "group_roles",
        "role_composites",
        "protocol_mappers",
        "organization_domains",
        "organization_memberships",
        "organization_identity_providers",
        "organization_invitations",
        "organization_groups",
        "user_totp_credentials",
        "user_webauthn_credentials",
        "user_recovery_codes",
        "user_required_actions",
        "user_terms_acceptances",
        "federated_directory_users",
    ] {
        if !snapshot.tables.get(table).is_some_and(Value::is_array) {
            return Err(format!("The archive table {table} is missing or invalid"));
        }
    }
    for (table, field, parent) in [
        ("client_scopes", "client_id", "clients"),
        ("client_scopes", "scope_id", "scopes"),
        ("federated_identities", "user_id", "users"),
        (
            "federated_identities",
            "identity_provider_id",
            "identity_providers",
        ),
        ("roles", "client_id", "clients"),
        ("groups", "parent_id", "groups"),
        ("user_roles", "user_id", "users"),
        ("user_roles", "role_id", "roles"),
        ("user_groups", "user_id", "users"),
        ("user_groups", "group_id", "groups"),
        ("group_roles", "group_id", "groups"),
        ("group_roles", "role_id", "roles"),
        ("role_composites", "parent_role_id", "roles"),
        ("role_composites", "child_role_id", "roles"),
        ("protocol_mappers", "scope_id", "scopes"),
        ("organization_domains", "organization_id", "organizations"),
        (
            "organization_memberships",
            "organization_id",
            "organizations",
        ),
        ("organization_memberships", "user_id", "users"),
        (
            "organization_identity_providers",
            "organization_id",
            "organizations",
        ),
        (
            "organization_identity_providers",
            "identity_provider_id",
            "identity_providers",
        ),
        (
            "organization_invitations",
            "organization_id",
            "organizations",
        ),
        ("organization_invitations", "invited_by", "users"),
        ("organization_groups", "organization_id", "organizations"),
        ("organization_groups", "group_id", "groups"),
        ("user_totp_credentials", "user_id", "users"),
        ("user_webauthn_credentials", "user_id", "users"),
        ("user_recovery_codes", "user_id", "users"),
        ("user_consents", "user_id", "users"),
        ("user_consents", "client_id", "clients"),
        ("user_required_actions", "user_id", "users"),
        ("user_terms_acceptances", "user_id", "users"),
        ("api_keys", "created_by", "users"),
        ("authorization_resources", "resource_server_id", "clients"),
        ("authorization_resources", "owner_id", "users"),
        ("authorization_policies", "resource_server_id", "clients"),
        ("authorization_permissions", "resource_server_id", "clients"),
        (
            "federated_directory_users",
            "provider_id",
            "user_federation_providers",
        ),
        ("federated_directory_users", "user_id", "users"),
    ] {
        validate_reference(&snapshot.tables, table, field, parent)?;
    }
    Ok(())
}

async fn write_audit(
    conn: &mut oidc_repository::Connection,
    auth: &AdminAuth,
    realm_id: Uuid,
    event_type: &str,
) {
    let event = AuditEvent {
        id: generate_uuid_v7(),
        realm_id: Some(realm_id),
        event_type: event_type.into(),
        actor_id: Uuid::parse_str(&auth.subject).ok(),
        actor_type: if auth.is_api_key {
            ActorType::ApiKey
        } else {
            ActorType::User
        },
        target_type: Some("realm".into()),
        target_id: Some(realm_id),
        details: json!({}),
        ip_address: None,
        user_agent: None,
        created_at: Utc::now(),
    };
    if let Err(error) = AuditEventRepo.create(conn, &event).await {
        tracing::warn!("realm transfer audit event failed: {error}");
    }
}

pub async fn export(
    State(state): State<AppState>,
    Path(realm_id): Path<Uuid>,
    auth: AdminAuth,
    Json(req): Json<ExportRequest>,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    if let Some(response) = realm_or_forbidden(&auth, realm_id) {
        return response;
    }
    if req.password.len() < MIN_PASSWORD_LEN {
        return request_error("Use an export password of at least 12 characters");
    }
    let mut conn = match connect(&state).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let raw = match RealmTransferRepo.export(&mut conn, realm_id).await {
        Ok(value) => value,
        Err(oidc_core::OidcError::NotFound(_)) => return super::not_found(),
        Err(error) => {
            tracing::error!("realm export failed: {error}");
            return internal_error();
        }
    };
    let realm = raw.get("realm").cloned().unwrap_or(Value::Null);
    let realm_name = realm
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("realm")
        .to_string();
    let mut tables = raw
        .get("tables")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if let Err(error) = transform_secrets(&state, &mut tables, false) {
        tracing::error!("realm export secret conversion failed: {error}");
        return internal_error();
    }
    let snapshot = Snapshot {
        format: ARCHIVE_FORMAT.into(),
        version: ARCHIVE_VERSION,
        exported_at: Utc::now().to_rfc3339(),
        realm,
        tables,
    };
    let archive = match seal(&snapshot, &req.password, &realm_name) {
        Ok(value) => value,
        Err(error) => {
            tracing::error!("realm export encryption failed: {error}");
            return internal_error();
        }
    };
    write_audit(&mut conn, &auth, realm_id, "realm.exported").await;
    let mut response = Json(archive).into_response();
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{realm_name}-realm.json\""))
            .unwrap_or_else(|_| HeaderValue::from_static("attachment; filename=\"realm.json\"")),
    );
    response
}

pub async fn import(
    State(state): State<AppState>,
    auth: AdminAuth,
    Json(req): Json<ImportRequest>,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    if req.password.len() < MIN_PASSWORD_LEN {
        return request_error("The export password must contain at least 12 characters");
    }
    let mut snapshot = match open(&req.archive, &req.password) {
        Ok(value) => value,
        Err(error) => return request_error(error),
    };
    if let Err(error) = validate_snapshot(&snapshot) {
        return request_error(error);
    }
    let source_id = match snapshot
        .realm
        .get("id")
        .and_then(Value::as_str)
        .and_then(|v| Uuid::parse_str(v).ok())
    {
        Some(value) => value,
        None => return request_error("The archive realm ID is invalid"),
    };
    let realm_name = match snapshot.realm.get("name").and_then(Value::as_str) {
        Some(value) if !value.is_empty() => value.to_string(),
        _ => return request_error("The archive realm name is missing"),
    };
    let mut conn = match connect(&state).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let existing = match RealmTransferRepo
        .find_realm_for_import(&mut conn, source_id, &realm_name)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::error!("realm import lookup failed: {error}");
            return internal_error();
        }
    };
    if let Some(id) = existing {
        if !req.replace_existing {
            return (StatusCode::CONFLICT, Json(json!({"error":"realm_exists","error_description":"A realm with this name or ID already exists"}))).into_response();
        }
        if let Some(response) = realm_or_forbidden(&auth, id) {
            return response;
        }
        if let Err(error) = remap_realm(&mut snapshot, id) {
            return request_error(error);
        }
    } else if !auth.is_global_admin() {
        return StatusCode::FORBIDDEN.into_response();
    }
    if let Err(error) = transform_secrets(&state, &mut snapshot.tables, true) {
        tracing::error!("realm import secret conversion failed: {error}");
        return request_error("The archive contains an invalid protected value");
    }
    let target_id = snapshot.realm["id"]
        .as_str()
        .and_then(|v| Uuid::parse_str(v).ok())
        .unwrap_or(source_id);
    if let Err(error) = conn.begin().await {
        tracing::error!("realm import transaction failed: {error}");
        return internal_error();
    }
    let result = async {
        if existing.is_some() {
            RealmTransferRepo.clear_realm(&mut conn, target_id).await?;
        }
        RealmTransferRepo
            .insert_snapshot(
                &mut conn,
                &snapshot.realm,
                &snapshot.tables,
                existing.is_some(),
            )
            .await
    }
    .await;
    if let Err(error) = result {
        let _ = conn.rollback().await;
        tracing::error!("realm import failed: {error}");
        return match error {
            oidc_core::OidcError::Conflict(_) => (StatusCode::CONFLICT, Json(json!({"error":"import_conflict","error_description":"The archive conflicts with an existing identifier"}))).into_response(),
            _ => request_error("The archive is incomplete or contains invalid data"),
        };
    }
    if let Err(error) = conn.commit().await {
        tracing::error!("realm import commit failed: {error}");
        return internal_error();
    }
    write_audit(&mut conn, &auth, target_id, "realm.imported").await;
    (
        StatusCode::CREATED,
        Json(json!({"id":target_id,"name":realm_name,"replaced":existing.is_some()})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_archive_round_trip_and_tamper_detection() {
        let snapshot = Snapshot {
            format: ARCHIVE_FORMAT.into(),
            version: ARCHIVE_VERSION,
            exported_at: Utc::now().to_rfc3339(),
            realm: json!({"id":Uuid::nil(),"name":"test"}),
            tables: Map::new(),
        };
        let archive = seal(&snapshot, "long-test-password", "test").unwrap();
        assert_eq!(
            open(&archive, "long-test-password").unwrap().realm["name"],
            "test"
        );
        assert!(open(&archive, "wrong-test-password").is_err());
        let mut tampered = archive;
        tampered.ciphertext.push('A');
        assert!(open(&tampered, "long-test-password").is_err());
    }
}
