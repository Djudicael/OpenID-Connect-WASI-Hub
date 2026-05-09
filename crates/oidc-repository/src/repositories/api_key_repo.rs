use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::ApiKey;
use uuid::Uuid;

/// PostgreSQL implementation of the API Key repository.
pub struct ApiKeyRepo;

impl ApiKeyRepo {
    /// Find an API key by its primary key.
    pub async fn find_by_id(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<ApiKey>, OidcError> {
        let sql = r#"
            SELECT id, realm_id, name, prefix, hashed_secret,
                   scopes, revoked, request_count, expires_at,
                   last_used_at, created_at, created_by, rotated_at
            FROM api_keys
            WHERE id = $1
        "#;
        let row = conn
            .query_one_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find an active API key by its prefix.
    pub async fn find_by_prefix(
        &self,
        conn: &mut Connection,
        prefix: &str,
    ) -> Result<Option<ApiKey>, OidcError> {
        let sql = r#"
            SELECT id, realm_id, name, prefix, hashed_secret,
                   scopes, revoked, request_count, expires_at,
                   last_used_at, created_at, created_by, rotated_at
            FROM api_keys
            WHERE prefix = $1 AND NOT revoked AND (expires_at IS NULL OR expires_at > NOW())
        "#;
        let row = conn
            .query_one_params(sql, &[&prefix])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find all API keys for a realm.
    pub async fn find_by_realm(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
        include_revoked: bool,
    ) -> Result<Vec<ApiKey>, OidcError> {
        let sql = if include_revoked {
            r#"
            SELECT id, realm_id, name, prefix, hashed_secret,
                   scopes, revoked, request_count, expires_at,
                   last_used_at, created_at, created_by, rotated_at
            FROM api_keys
            WHERE realm_id = $1
            ORDER BY created_at DESC
            "#
        } else {
            r#"
            SELECT id, realm_id, name, prefix, hashed_secret,
                   scopes, revoked, request_count, expires_at,
                   last_used_at, created_at, created_by, rotated_at
            FROM api_keys
            WHERE realm_id = $1 AND NOT revoked
            ORDER BY created_at DESC
            "#
        };
        let result = conn
            .query_params(sql, &[&realm_id])
            .await
            .map_err(mapper::pg_err)?;
        result
            .into_rows()
            .iter()
            .map(|r| Self::map_row(r))
            .collect::<Result<Vec<_>, _>>()
    }

    /// Insert a new API key.
    pub async fn create(&self, conn: &mut Connection, entity: &ApiKey) -> Result<(), OidcError> {
        let sql = r#"
            INSERT INTO api_keys (
                id, realm_id, name, prefix, hashed_secret,
                scopes, revoked, request_count, expires_at,
                last_used_at, created_at, created_by, rotated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        "#;
        conn.execute_params(
            sql,
            &[
                &entity.id,
                &entity.realm_id,
                &entity.name,
                &entity.prefix,
                &entity.hashed_secret,
                &mapper::to_json_value_vec(&entity.scopes),
                &entity.revoked,
                &entity.request_count,
                &entity.expires_at,
                &entity.last_used_at,
                &entity.created_at,
                &entity.created_by,
                &entity.rotated_at,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Revoke an API key by ID.
    pub async fn revoke(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "UPDATE api_keys SET revoked = TRUE WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Mark an API key as rotated.
    pub async fn mark_rotated(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "UPDATE api_keys SET rotated_at = NOW() WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Increment the request count for an API key.
    pub async fn increment_count(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "UPDATE api_keys SET request_count = request_count + 1, last_used_at = NOW() WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<ApiKey, OidcError> {
        Ok(ApiKey {
            id: mapper::uuid(row, 0)?,
            realm_id: mapper::uuid(row, 1)?,
            name: mapper::string(row, 2)?,
            prefix: mapper::string(row, 3)?,
            hashed_secret: mapper::string(row, 4)?,
            scopes: mapper::json_string_vec(row, 5)?,
            revoked: mapper::bool_(row, 6)?,
            request_count: mapper::i64_(row, 7)?,
            expires_at: mapper::opt_datetime(row, 8)?,
            last_used_at: mapper::opt_datetime(row, 9)?,
            created_at: mapper::datetime(row, 10)?,
            created_by: mapper::opt_uuid(row, 11)?,
            rotated_at: mapper::opt_datetime(row, 12)?,
        })
    }
}
