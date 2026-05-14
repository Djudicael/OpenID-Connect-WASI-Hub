use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::PushedAuthorizationRequest;
use uuid::Uuid;

/// PostgreSQL implementation of the Pushed Authorization Request (PAR) repository.
pub struct ParRepo;

/// Column list for PAR SELECT queries (order must match map_row indices).
const PAR_COLUMNS: &str = r#"
    id, client_id, realm_id, request_uri_token, request_params,
    expires_at, used, created_at
"#;

impl ParRepo {
    /// Insert a new pushed authorization request.
    pub async fn create(
        &self,
        conn: &mut Connection,
        entity: &PushedAuthorizationRequest,
    ) -> Result<(), OidcError> {
        let sql = r#"
            INSERT INTO pushed_authorization_requests (
                id, client_id, realm_id, request_uri_token, request_params,
                expires_at, used, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#;
        conn.execute_params(
            sql,
            &[
                &entity.id,
                &entity.client_id,
                &entity.realm_id,
                &entity.request_uri_token,
                &entity.request_params,
                &entity.expires_at,
                &entity.used,
                &entity.created_at,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Find a PAR by its opaque request_uri_token.
    ///
    /// Only returns rows that are not yet used and have not expired.
    pub async fn find_by_request_uri_token(
        &self,
        conn: &mut Connection,
        token: &str,
    ) -> Result<Option<PushedAuthorizationRequest>, OidcError> {
        let sql = &format!(
            "SELECT {PAR_COLUMNS} FROM pushed_authorization_requests \
             WHERE request_uri_token = $1 AND NOT used AND expires_at > NOW()"
        );
        let row = conn
            .query_one_params(sql, &[&token])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Mark a PAR as used.
    pub async fn mark_used(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "UPDATE pushed_authorization_requests SET used = TRUE WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Delete expired pushed authorization requests.
    pub async fn cleanup_expired(&self, conn: &mut Connection) -> Result<u64, OidcError> {
        let sql = "DELETE FROM pushed_authorization_requests WHERE expires_at < NOW()";
        let affected = conn
            .execute_params(sql, &[])
            .await
            .map_err(mapper::pg_err)?;
        Ok(affected)
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<PushedAuthorizationRequest, OidcError> {
        Ok(PushedAuthorizationRequest {
            id: mapper::uuid(row, 0)?,
            client_id: mapper::uuid(row, 1)?,
            realm_id: mapper::uuid(row, 2)?,
            request_uri_token: mapper::string(row, 3)?,
            request_params: row.get::<serde_json::Value>(4).map_err(mapper::pg_err)?,
            expires_at: mapper::datetime(row, 5)?,
            used: mapper::bool_(row, 6)?,
            created_at: mapper::datetime(row, 7)?,
        })
    }
}
