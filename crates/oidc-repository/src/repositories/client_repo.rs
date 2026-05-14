use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::{Client, ClientType};
use uuid::Uuid;

/// Escape special LIKE pattern characters (`%`, `_`, `\`) in a search string.
fn escape_like(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '%' | '_' | '\\' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// PostgreSQL implementation of the Client repository.
pub struct ClientRepo;

/// Column list for client SELECT queries (order must match map_row indices).
const CLIENT_COLUMNS: &str = r#"
    id, realm_id, client_id, client_type, client_secret_hash,
    name, redirect_uris, allowed_scopes, allowed_grant_types,
    pkce_required, enabled, deleted_at,
    token_endpoint_auth_method, jwks_uri, jwks, request_uris,
    client_secret_encrypted
"#;

impl ClientRepo {
    /// Find a client by its primary key.
    pub async fn find_by_id(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<Client>, OidcError> {
        let sql =
            &format!("SELECT {CLIENT_COLUMNS} FROM clients WHERE id = $1 AND deleted_at IS NULL");
        let row = conn
            .query_one_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find a client by its globally unique client_id string.
    pub async fn find_by_client_id(
        &self,
        conn: &mut Connection,
        client_id: &str,
    ) -> Result<Option<Client>, OidcError> {
        let sql = &format!(
            "SELECT {CLIENT_COLUMNS} FROM clients WHERE client_id = $1 AND deleted_at IS NULL"
        );
        let row = conn
            .query_one_params(sql, &[&client_id])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find a client by its client_id within a specific realm.
    ///
    /// This is the **realm-scoped** variant used by per-realm login flows.
    /// A client with the same `client_id` can exist in multiple realms.
    pub async fn find_by_client_id_in_realm(
        &self,
        conn: &mut Connection,
        client_id: &str,
        realm_id: Uuid,
    ) -> Result<Option<Client>, OidcError> {
        let sql = &format!(
            "SELECT {CLIENT_COLUMNS} FROM clients WHERE client_id = $1 AND realm_id = $2 AND deleted_at IS NULL"
        );
        let row = conn
            .query_one_params(sql, &[&client_id, &realm_id])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Insert a new client.
    pub async fn create(&self, conn: &mut Connection, entity: &Client) -> Result<(), OidcError> {
        let sql = r#"
            INSERT INTO clients (
                id, realm_id, client_id, client_type, client_secret_hash,
                name, redirect_uris, allowed_scopes, allowed_grant_types,
                pkce_required, enabled,
                token_endpoint_auth_method, jwks_uri, jwks, request_uris,
                client_secret_encrypted
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
        "#;
        let client_type_str = match entity.client_type {
            ClientType::Confidential => "confidential",
            ClientType::Public => "public",
        };
        conn.execute_params(
            sql,
            &[
                &entity.id,
                &entity.realm_id,
                &entity.client_id,
                &client_type_str,
                &entity.client_secret_hash,
                &entity.name,
                &mapper::to_json_value_vec(&entity.redirect_uris),
                &mapper::to_json_value_vec(&entity.allowed_scopes),
                &mapper::to_json_value_vec(&entity.allowed_grant_types),
                &entity.pkce_required,
                &entity.enabled,
                &entity.token_endpoint_auth_method,
                &entity.jwks_uri,
                &entity.jwks,
                &mapper::to_json_value_vec(&entity.request_uris),
                &entity.client_secret_encrypted,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Update an existing client.
    pub async fn update(&self, conn: &mut Connection, entity: &Client) -> Result<(), OidcError> {
        let sql = r#"
            UPDATE clients SET
                client_id = $1,
                client_type = $2,
                client_secret_hash = $3,
                name = $4,
                redirect_uris = $5,
                allowed_scopes = $6,
                allowed_grant_types = $7,
                pkce_required = $8,
                enabled = $9,
                token_endpoint_auth_method = $10,
                jwks_uri = $11,
                jwks = $12,
                request_uris = $13,
                client_secret_encrypted = $14,
                updated_at = NOW()
            WHERE id = $15 AND deleted_at IS NULL
        "#;
        let client_type_str = match entity.client_type {
            ClientType::Confidential => "confidential",
            ClientType::Public => "public",
        };
        conn.execute_params(
            sql,
            &[
                &entity.client_id,
                &client_type_str,
                &entity.client_secret_hash,
                &entity.name,
                &mapper::to_json_value_vec(&entity.redirect_uris),
                &mapper::to_json_value_vec(&entity.allowed_scopes),
                &mapper::to_json_value_vec(&entity.allowed_grant_types),
                &entity.pkce_required,
                &entity.enabled,
                &entity.token_endpoint_auth_method,
                &entity.jwks_uri,
                &entity.jwks,
                &mapper::to_json_value_vec(&entity.request_uris),
                &entity.client_secret_encrypted,
                &entity.id,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Soft-delete a client by ID.
    pub async fn delete(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "UPDATE clients SET deleted_at = NOW() WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// List clients with optional realm filter, search, and pagination.
    pub async fn list(
        &self,
        conn: &mut Connection,
        realm_id: Option<Uuid>,
        search: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Client>, OidcError> {
        let mut where_clauses = vec!["deleted_at IS NULL".to_string()];
        let mut param_idx = 1usize;

        if realm_id.is_some() {
            where_clauses.push(format!("realm_id = ${}", param_idx));
            param_idx += 1;
        }
        if search.is_some() {
            where_clauses.push(format!(
                "(name ILIKE ${} OR client_id ILIKE ${})",
                param_idx, param_idx
            ));
            param_idx += 1;
        }

        let where_sql = where_clauses.join(" AND ");
        let limit_idx = param_idx;
        let offset_idx = param_idx + 1;

        let sql = format!(
            "SELECT {CLIENT_COLUMNS} FROM clients WHERE {where_sql} ORDER BY created_at DESC LIMIT ${limit_idx} OFFSET ${offset_idx}"
        );

        let realm_id_ref = realm_id.as_ref();
        let pattern = search.map(|s| format!("%{}%", escape_like(s)));

        let mut params: Vec<&dyn wasi_pg_client::pg_types::ToSql> = Vec::new();
        if let Some(rid) = realm_id_ref {
            params.push(rid);
        }
        if let Some(ref p) = pattern {
            params.push(p);
        }
        params.push(&limit);
        params.push(&offset);

        let result = conn
            .query_params(&sql, &params)
            .await
            .map_err(mapper::pg_err)?;
        result
            .into_rows()
            .iter()
            .map(|r| Self::map_row(r))
            .collect::<Result<Vec<_>, _>>()
    }

    /// Count clients with optional realm filter.
    pub async fn count(
        &self,
        conn: &mut Connection,
        realm_id: Option<Uuid>,
    ) -> Result<i64, OidcError> {
        let mut where_clauses = vec!["deleted_at IS NULL".to_string()];
        let param_idx = 1usize;

        if realm_id.is_some() {
            where_clauses.push(format!("realm_id = ${}", param_idx));
        }

        let where_sql = where_clauses.join(" AND ");
        let sql = format!("SELECT COUNT(*) FROM clients WHERE {where_sql}");

        let realm_id_ref = realm_id.as_ref();

        let result = match realm_id_ref {
            Some(rid) => conn
                .query_params(&sql, &[rid])
                .await
                .map_err(mapper::pg_err)?,
            None => conn.query(&sql).await.map_err(mapper::pg_err)?,
        };
        let row = result
            .into_rows()
            .into_iter()
            .next()
            .ok_or(OidcError::Internal("count returned no rows".into()))?;
        mapper::i64_(&row, 0)
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<Client, OidcError> {
        let client_type_str: String = mapper::string(row, 3)?;
        let client_type = match client_type_str.as_str() {
            "confidential" => ClientType::Confidential,
            _ => ClientType::Public,
        };
        Ok(Client {
            id: mapper::uuid(row, 0)?,
            realm_id: mapper::uuid(row, 1)?,
            client_id: mapper::string(row, 2)?,
            client_type,
            client_secret_hash: mapper::opt_string(row, 4)?,
            name: mapper::string(row, 5)?,
            redirect_uris: mapper::json_string_vec(row, 6)?,
            allowed_scopes: mapper::json_string_vec(row, 7)?,
            allowed_grant_types: mapper::json_string_vec(row, 8)?,
            pkce_required: mapper::bool_(row, 9)?,
            enabled: mapper::bool_(row, 10)?,
            deleted_at: mapper::opt_datetime(row, 11)?,
            token_endpoint_auth_method: mapper::string(row, 12)?,
            jwks_uri: mapper::opt_string(row, 13)?,
            jwks: row.get::<Option<serde_json::Value>>(14).ok().flatten(),
            request_uris: mapper::json_string_vec(row, 15)?,
            client_secret_encrypted: mapper::opt_string(row, 16)?,
        })
    }
}
