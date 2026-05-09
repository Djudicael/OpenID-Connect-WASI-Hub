use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::User;
use uuid::Uuid;

/// PostgreSQL implementation of the User repository.
pub struct UserRepo;

impl UserRepo {
    /// Find a user by its primary key.
    pub async fn find_by_id(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<User>, OidcError> {
        let sql = r#"
            SELECT id, realm_id, email, email_verified, username, password_hash,
                   given_name, family_name, enabled
            FROM users
            WHERE id = $1 AND deleted_at IS NULL
        "#;
        let row = conn
            .query_one_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find a user by email within a realm.
    pub async fn find_by_email(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
        email: &str,
    ) -> Result<Option<User>, OidcError> {
        let sql = r#"
            SELECT id, realm_id, email, email_verified, username, password_hash,
                   given_name, family_name, enabled
            FROM users
            WHERE realm_id = $1 AND email = $2 AND deleted_at IS NULL
        "#;
        let row = conn
            .query_one_params(sql, &[&realm_id, &email])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Insert a new user.
    pub async fn create(&self, conn: &mut Connection, entity: &User) -> Result<(), OidcError> {
        let sql = r#"
            INSERT INTO users (
                id, realm_id, email, email_verified, username, password_hash,
                given_name, family_name, enabled
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#;
        conn.execute_params(
            sql,
            &[
                &entity.id,
                &entity.realm_id,
                &entity.email,
                &entity.email_verified,
                &entity.username,
                &entity.password_hash,
                &entity.given_name,
                &entity.family_name,
                &entity.enabled,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Update an existing user.
    pub async fn update(&self, conn: &mut Connection, entity: &User) -> Result<(), OidcError> {
        let sql = r#"
            UPDATE users SET
                email = $1,
                email_verified = $2,
                username = $3,
                password_hash = $4,
                given_name = $5,
                family_name = $6,
                enabled = $7,
                updated_at = NOW()
            WHERE id = $8 AND deleted_at IS NULL
        "#;
        conn.execute_params(
            sql,
            &[
                &entity.email,
                &entity.email_verified,
                &entity.username,
                &entity.password_hash,
                &entity.given_name,
                &entity.family_name,
                &entity.enabled,
                &entity.id,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Soft-delete a user by ID.
    pub async fn delete(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "UPDATE users SET deleted_at = NOW() WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// List all users in a realm with optional search and pagination.
    pub async fn list(
        &self,
        conn: &mut Connection,
        realm_id: Option<Uuid>,
        search: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<User>, OidcError> {
        match (realm_id, search) {
            (Some(rid), Some(s)) => {
                let pattern = format!("%{}%", s);
                let sql = r#"
                    SELECT id, realm_id, email, email_verified, username, password_hash, given_name, family_name, enabled
                    FROM users
                    WHERE deleted_at IS NULL AND realm_id = $1 AND (email ILIKE $2 OR username ILIKE $2 OR given_name ILIKE $2 OR family_name ILIKE $2)
                    ORDER BY created_at DESC LIMIT $3 OFFSET $4
                "#;
                let result = conn
                    .query_params(sql, &[&rid, &pattern, &limit, &offset])
                    .await
                    .map_err(mapper::pg_err)?;
                result
                    .into_rows()
                    .iter()
                    .map(|r| Self::map_row(r))
                    .collect::<Result<Vec<_>, _>>()
            }
            (Some(rid), None) => {
                let sql = r#"
                    SELECT id, realm_id, email, email_verified, username, password_hash, given_name, family_name, enabled
                    FROM users
                    WHERE deleted_at IS NULL AND realm_id = $1
                    ORDER BY created_at DESC LIMIT $2 OFFSET $3
                "#;
                let result = conn
                    .query_params(sql, &[&rid, &limit, &offset])
                    .await
                    .map_err(mapper::pg_err)?;
                result
                    .into_rows()
                    .iter()
                    .map(|r| Self::map_row(r))
                    .collect::<Result<Vec<_>, _>>()
            }
            (None, Some(s)) => {
                let pattern = format!("%{}%", s);
                let sql = r#"
                    SELECT id, realm_id, email, email_verified, username, password_hash, given_name, family_name, enabled
                    FROM users
                    WHERE deleted_at IS NULL AND (email ILIKE $1 OR username ILIKE $1 OR given_name ILIKE $1 OR family_name ILIKE $1)
                    ORDER BY created_at DESC LIMIT $2 OFFSET $3
                "#;
                let result = conn
                    .query_params(sql, &[&pattern, &limit, &offset])
                    .await
                    .map_err(mapper::pg_err)?;
                result
                    .into_rows()
                    .iter()
                    .map(|r| Self::map_row(r))
                    .collect::<Result<Vec<_>, _>>()
            }
            (None, None) => {
                let sql = r#"
                    SELECT id, realm_id, email, email_verified, username, password_hash, given_name, family_name, enabled
                    FROM users
                    WHERE deleted_at IS NULL
                    ORDER BY created_at DESC LIMIT $1 OFFSET $2
                "#;
                let result = conn
                    .query_params(sql, &[&limit, &offset])
                    .await
                    .map_err(mapper::pg_err)?;
                result
                    .into_rows()
                    .iter()
                    .map(|r| Self::map_row(r))
                    .collect::<Result<Vec<_>, _>>()
            }
        }
    }

    /// Count users in a realm.
    pub async fn count(
        &self,
        conn: &mut Connection,
        realm_id: Option<Uuid>,
    ) -> Result<i64, OidcError> {
        let sql = match realm_id {
            Some(_) => "SELECT COUNT(*) FROM users WHERE deleted_at IS NULL AND realm_id = $1",
            None => "SELECT COUNT(*) FROM users WHERE deleted_at IS NULL",
        };
        let result = match realm_id {
            Some(rid) => conn
                .query_params(sql, &[&rid])
                .await
                .map_err(mapper::pg_err)?,
            None => conn.query(sql).await.map_err(mapper::pg_err)?,
        };
        let row = result
            .into_rows()
            .into_iter()
            .next()
            .ok_or(OidcError::Internal("count returned no rows".into()))?;
        mapper::i64_(&row, 0)
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<User, OidcError> {
        Ok(User {
            id: mapper::uuid(row, 0)?,
            realm_id: mapper::uuid(row, 1)?,
            email: mapper::string(row, 2)?,
            email_verified: mapper::bool_(row, 3)?,
            username: mapper::opt_string(row, 4)?,
            password_hash: mapper::opt_string(row, 5)?,
            given_name: mapper::opt_string(row, 6)?,
            family_name: mapper::opt_string(row, 7)?,
            enabled: mapper::bool_(row, 8)?,
        })
    }
}
