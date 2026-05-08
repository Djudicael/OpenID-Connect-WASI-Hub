use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::Session;
use uuid::Uuid;

/// PostgreSQL implementation of the Session repository.
pub struct SessionRepo;

impl SessionRepo {
    /// Find a session by its primary key.
    pub async fn find_by_id(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<Session>, OidcError> {
        let sql = r#"
            SELECT id, user_id, realm_id, client_id, grant_type,
                   access_token_hash, refresh_token_hash, id_token_jti,
                   scope, revoked
            FROM sessions
            WHERE id = $1
        "#;
        let row = conn
            .query_one_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find a non-revoked session by access token hash.
    pub async fn find_by_access_token_hash(
        &self,
        conn: &mut Connection,
        hash: &str,
    ) -> Result<Option<Session>, OidcError> {
        let sql = r#"
            SELECT id, user_id, realm_id, client_id, grant_type,
                   access_token_hash, refresh_token_hash, id_token_jti,
                   scope, revoked
            FROM sessions
            WHERE access_token_hash = $1 AND NOT revoked
        "#;
        let row = conn
            .query_one_params(sql, &[&hash])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Insert a new session.
    pub async fn create(&self, conn: &mut Connection, entity: &Session) -> Result<(), OidcError> {
        let sql = r#"
            INSERT INTO sessions (
                id, user_id, realm_id, client_id, grant_type,
                access_token_hash, refresh_token_hash, id_token_jti,
                scope, revoked, expires_at, refresh_expires_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW() + INTERVAL '15 minutes', NOW() + INTERVAL '7 days')
        "#;
        conn.execute_params(
            sql,
            &[
                &entity.id,
                &entity.user_id,
                &entity.realm_id,
                &entity.client_id,
                &entity.grant_type,
                &entity.access_token_hash,
                &entity.refresh_token_hash,
                &entity.id_token_jti,
                &mapper::to_json_value_vec(&entity.scope),
                &entity.revoked,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Find a non-revoked session by refresh token hash.
    pub async fn find_by_refresh_token_hash(
        &self,
        conn: &mut Connection,
        hash: &str,
    ) -> Result<Option<Session>, OidcError> {
        let sql = r#"
            SELECT id, user_id, realm_id, client_id, grant_type,
                   access_token_hash, refresh_token_hash, id_token_jti,
                   scope, revoked
            FROM sessions
            WHERE refresh_token_hash = $1 AND NOT revoked
        "#;
        let row = conn
            .query_one_params(sql, &[&hash])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find a non-revoked, non-expired session by refresh token hash.
    pub async fn find_active_by_refresh_token_hash(
        &self,
        conn: &mut Connection,
        hash: &str,
    ) -> Result<Option<Session>, OidcError> {
        let sql = r#"
            SELECT id, user_id, realm_id, client_id, grant_type,
                   access_token_hash, refresh_token_hash, id_token_jti,
                   scope, revoked
            FROM sessions
            WHERE refresh_token_hash = $1 AND NOT revoked AND refresh_expires_at > NOW()
        "#;
        let row = conn
            .query_one_params(sql, &[&hash])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Revoke a session by ID.
    pub async fn revoke(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "UPDATE sessions SET revoked = TRUE WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<Session, OidcError> {
        Ok(Session {
            id: mapper::uuid(row, 0)?,
            user_id: mapper::uuid(row, 1)?,
            realm_id: mapper::uuid(row, 2)?,
            client_id: mapper::uuid(row, 3)?,
            grant_type: mapper::string(row, 4)?,
            access_token_hash: mapper::string(row, 5)?,
            refresh_token_hash: mapper::opt_string(row, 6)?,
            id_token_jti: mapper::opt_string(row, 7)?,
            scope: mapper::json_string_vec(row, 8)?,
            revoked: mapper::bool_(row, 9)?,
        })
    }
}
