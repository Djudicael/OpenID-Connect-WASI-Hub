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
                   scope, revoked,
                   token_family_id, previous_session_id, rotated_at, reused_at, family_revoked
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
                   scope, revoked,
                   token_family_id, previous_session_id, rotated_at, reused_at, family_revoked
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
                scope, revoked, expires_at, refresh_expires_at,
                token_family_id, previous_session_id, rotated_at, reused_at, family_revoked
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW() + INTERVAL '15 minutes', NOW() + INTERVAL '7 days',
                      $11, $12, $13, $14, $15)
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
                &entity.token_family_id,
                &entity.previous_session_id,
                &entity.rotated_at,
                &entity.reused_at,
                &entity.family_revoked,
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
                   scope, revoked,
                   token_family_id, previous_session_id, rotated_at, reused_at, family_revoked
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
                   scope, revoked,
                   token_family_id, previous_session_id, rotated_at, reused_at, family_revoked
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

    /// Mark a session as reused (token theft detection).
    pub async fn mark_reused(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "UPDATE sessions SET reused_at = NOW() WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Revoke all sessions in a token family.
    pub async fn revoke_family(
        &self,
        conn: &mut Connection,
        family_id: Uuid,
    ) -> Result<(), OidcError> {
        let sql =
            "UPDATE sessions SET revoked = TRUE, family_revoked = TRUE WHERE token_family_id = $1";
        conn.execute_params(sql, &[&family_id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// List sessions with optional filters and pagination.
    pub async fn list(
        &self,
        conn: &mut Connection,
        user_id: Option<Uuid>,
        realm_id: Option<Uuid>,
        revoked: Option<bool>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Session>, OidcError> {
        match (user_id, realm_id, revoked) {
            (Some(uid), Some(rid), Some(r)) => {
                let sql = r#"
                    SELECT id, user_id, realm_id, client_id, grant_type, access_token_hash, refresh_token_hash, id_token_jti, scope, revoked, token_family_id, previous_session_id, rotated_at, reused_at, family_revoked
                    FROM sessions
                    WHERE user_id = $1 AND realm_id = $2 AND revoked = $3
                    ORDER BY created_at DESC LIMIT $4 OFFSET $5
                "#;
                let result = conn
                    .query_params(sql, &[&uid, &rid, &r, &limit, &offset])
                    .await
                    .map_err(mapper::pg_err)?;
                result
                    .into_rows()
                    .iter()
                    .map(|row| Self::map_row(row))
                    .collect::<Result<Vec<_>, _>>()
            }
            (Some(uid), Some(rid), None) => {
                let sql = r#"
                    SELECT id, user_id, realm_id, client_id, grant_type, access_token_hash, refresh_token_hash, id_token_jti, scope, revoked, token_family_id, previous_session_id, rotated_at, reused_at, family_revoked
                    FROM sessions
                    WHERE user_id = $1 AND realm_id = $2
                    ORDER BY created_at DESC LIMIT $3 OFFSET $4
                "#;
                let result = conn
                    .query_params(sql, &[&uid, &rid, &limit, &offset])
                    .await
                    .map_err(mapper::pg_err)?;
                result
                    .into_rows()
                    .iter()
                    .map(|row| Self::map_row(row))
                    .collect::<Result<Vec<_>, _>>()
            }
            (Some(uid), None, Some(r)) => {
                let sql = r#"
                    SELECT id, user_id, realm_id, client_id, grant_type, access_token_hash, refresh_token_hash, id_token_jti, scope, revoked, token_family_id, previous_session_id, rotated_at, reused_at, family_revoked
                    FROM sessions
                    WHERE user_id = $1 AND revoked = $2
                    ORDER BY created_at DESC LIMIT $3 OFFSET $4
                "#;
                let result = conn
                    .query_params(sql, &[&uid, &r, &limit, &offset])
                    .await
                    .map_err(mapper::pg_err)?;
                result
                    .into_rows()
                    .iter()
                    .map(|row| Self::map_row(row))
                    .collect::<Result<Vec<_>, _>>()
            }
            (Some(uid), None, None) => {
                let sql = r#"
                    SELECT id, user_id, realm_id, client_id, grant_type, access_token_hash, refresh_token_hash, id_token_jti, scope, revoked, token_family_id, previous_session_id, rotated_at, reused_at, family_revoked
                    FROM sessions
                    WHERE user_id = $1
                    ORDER BY created_at DESC LIMIT $2 OFFSET $3
                "#;
                let result = conn
                    .query_params(sql, &[&uid, &limit, &offset])
                    .await
                    .map_err(mapper::pg_err)?;
                result
                    .into_rows()
                    .iter()
                    .map(|row| Self::map_row(row))
                    .collect::<Result<Vec<_>, _>>()
            }
            (None, Some(rid), Some(r)) => {
                let sql = r#"
                    SELECT id, user_id, realm_id, client_id, grant_type, access_token_hash, refresh_token_hash, id_token_jti, scope, revoked, token_family_id, previous_session_id, rotated_at, reused_at, family_revoked
                    FROM sessions
                    WHERE realm_id = $1 AND revoked = $2
                    ORDER BY created_at DESC LIMIT $3 OFFSET $4
                "#;
                let result = conn
                    .query_params(sql, &[&rid, &r, &limit, &offset])
                    .await
                    .map_err(mapper::pg_err)?;
                result
                    .into_rows()
                    .iter()
                    .map(|row| Self::map_row(row))
                    .collect::<Result<Vec<_>, _>>()
            }
            (None, Some(rid), None) => {
                let sql = r#"
                    SELECT id, user_id, realm_id, client_id, grant_type, access_token_hash, refresh_token_hash, id_token_jti, scope, revoked, token_family_id, previous_session_id, rotated_at, reused_at, family_revoked
                    FROM sessions
                    WHERE realm_id = $1
                    ORDER BY created_at DESC LIMIT $2 OFFSET $3
                "#;
                let result = conn
                    .query_params(sql, &[&rid, &limit, &offset])
                    .await
                    .map_err(mapper::pg_err)?;
                result
                    .into_rows()
                    .iter()
                    .map(|row| Self::map_row(row))
                    .collect::<Result<Vec<_>, _>>()
            }
            (None, None, Some(r)) => {
                let sql = r#"
                    SELECT id, user_id, realm_id, client_id, grant_type, access_token_hash, refresh_token_hash, id_token_jti, scope, revoked, token_family_id, previous_session_id, rotated_at, reused_at, family_revoked
                    FROM sessions
                    WHERE revoked = $1
                    ORDER BY created_at DESC LIMIT $2 OFFSET $3
                "#;
                let result = conn
                    .query_params(sql, &[&r, &limit, &offset])
                    .await
                    .map_err(mapper::pg_err)?;
                result
                    .into_rows()
                    .iter()
                    .map(|row| Self::map_row(row))
                    .collect::<Result<Vec<_>, _>>()
            }
            (None, None, None) => {
                let sql = r#"
                    SELECT id, user_id, realm_id, client_id, grant_type, access_token_hash, refresh_token_hash, id_token_jti, scope, revoked, token_family_id, previous_session_id, rotated_at, reused_at, family_revoked
                    FROM sessions
                    ORDER BY created_at DESC LIMIT $1 OFFSET $2
                "#;
                let result = conn
                    .query_params(sql, &[&limit, &offset])
                    .await
                    .map_err(mapper::pg_err)?;
                result
                    .into_rows()
                    .iter()
                    .map(|row| Self::map_row(row))
                    .collect::<Result<Vec<_>, _>>()
            }
        }
    }

    /// Count sessions with optional filters.
    pub async fn count(
        &self,
        conn: &mut Connection,
        user_id: Option<Uuid>,
        realm_id: Option<Uuid>,
        revoked: Option<bool>,
    ) -> Result<i64, OidcError> {
        match (user_id, realm_id, revoked) {
            (Some(uid), Some(rid), Some(r)) => {
                let sql = "SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND realm_id = $2 AND revoked = $3";
                let result = conn
                    .query_params(sql, &[&uid, &rid, &r])
                    .await
                    .map_err(mapper::pg_err)?;
                let row = result
                    .into_rows()
                    .into_iter()
                    .next()
                    .ok_or(OidcError::Internal("count returned no rows".into()))?;
                mapper::i64_(&row, 0)
            }
            (Some(uid), Some(rid), None) => {
                let sql = "SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND realm_id = $2";
                let result = conn
                    .query_params(sql, &[&uid, &rid])
                    .await
                    .map_err(mapper::pg_err)?;
                let row = result
                    .into_rows()
                    .into_iter()
                    .next()
                    .ok_or(OidcError::Internal("count returned no rows".into()))?;
                mapper::i64_(&row, 0)
            }
            (Some(uid), None, Some(r)) => {
                let sql = "SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND revoked = $2";
                let result = conn
                    .query_params(sql, &[&uid, &r])
                    .await
                    .map_err(mapper::pg_err)?;
                let row = result
                    .into_rows()
                    .into_iter()
                    .next()
                    .ok_or(OidcError::Internal("count returned no rows".into()))?;
                mapper::i64_(&row, 0)
            }
            (Some(uid), None, None) => {
                let sql = "SELECT COUNT(*) FROM sessions WHERE user_id = $1";
                let result = conn
                    .query_params(sql, &[&uid])
                    .await
                    .map_err(mapper::pg_err)?;
                let row = result
                    .into_rows()
                    .into_iter()
                    .next()
                    .ok_or(OidcError::Internal("count returned no rows".into()))?;
                mapper::i64_(&row, 0)
            }
            (None, Some(rid), Some(r)) => {
                let sql = "SELECT COUNT(*) FROM sessions WHERE realm_id = $1 AND revoked = $2";
                let result = conn
                    .query_params(sql, &[&rid, &r])
                    .await
                    .map_err(mapper::pg_err)?;
                let row = result
                    .into_rows()
                    .into_iter()
                    .next()
                    .ok_or(OidcError::Internal("count returned no rows".into()))?;
                mapper::i64_(&row, 0)
            }
            (None, Some(rid), None) => {
                let sql = "SELECT COUNT(*) FROM sessions WHERE realm_id = $1";
                let result = conn
                    .query_params(sql, &[&rid])
                    .await
                    .map_err(mapper::pg_err)?;
                let row = result
                    .into_rows()
                    .into_iter()
                    .next()
                    .ok_or(OidcError::Internal("count returned no rows".into()))?;
                mapper::i64_(&row, 0)
            }
            (None, None, Some(r)) => {
                let sql = "SELECT COUNT(*) FROM sessions WHERE revoked = $1";
                let result = conn
                    .query_params(sql, &[&r])
                    .await
                    .map_err(mapper::pg_err)?;
                let row = result
                    .into_rows()
                    .into_iter()
                    .next()
                    .ok_or(OidcError::Internal("count returned no rows".into()))?;
                mapper::i64_(&row, 0)
            }
            (None, None, None) => {
                let sql = "SELECT COUNT(*) FROM sessions";
                let result = conn.query(sql).await.map_err(mapper::pg_err)?;
                let row = result
                    .into_rows()
                    .into_iter()
                    .next()
                    .ok_or(OidcError::Internal("count returned no rows".into()))?;
                mapper::i64_(&row, 0)
            }
        }
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
            token_family_id: mapper::opt_uuid(row, 10)?,
            previous_session_id: mapper::opt_uuid(row, 11)?,
            rotated_at: mapper::opt_datetime(row, 12)?,
            reused_at: mapper::opt_datetime(row, 13)?,
            family_revoked: mapper::bool_(row, 14)?,
        })
    }
}
