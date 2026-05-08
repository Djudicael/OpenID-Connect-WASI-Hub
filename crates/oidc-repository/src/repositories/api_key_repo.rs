use crate::connection::Connection;
use crate::mapper;
use oidc_core::models::ApiKey;
use oidc_core::OidcError;
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
                   scopes, revoked, request_count
            FROM api_keys
            WHERE id = $1
        "#;
        let row = conn.query_one_params(sql, &[&id]).await.map_err(mapper::pg_err)?;
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
                   scopes, revoked, request_count
            FROM api_keys
            WHERE prefix = $1 AND NOT revoked
        "#;
        let row = conn
            .query_one_params(sql, &[&prefix])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Insert a new API key.
    pub async fn create(&self, conn: &mut Connection, entity: &ApiKey) -> Result<(), OidcError> {
        let sql = r#"
            INSERT INTO api_keys (
                id, realm_id, name, prefix, hashed_secret,
                scopes, revoked, request_count
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
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

    /// Increment the request count for an API key.
    pub async fn increment_count(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<(), OidcError> {
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
        })
    }
}
