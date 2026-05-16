use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::User;
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

/// PostgreSQL implementation of the User repository.
pub struct UserRepo;

/// Column list for user SELECT queries (order must match map_row indices).
const USER_COLUMNS: &str = r#"
    id, realm_id, email, email_verified, username, password_hash,
    given_name, family_name, middle_name, nickname, preferred_username,
    profile, picture, website, gender, birthdate, zoneinfo,
    phone_number, phone_number_verified,
    street_address, locality, region, postal_code, country,
    locale, attributes, enabled,
    deleted_at, updated_at
"#;

impl UserRepo {
    /// Find a user by its primary key.
    pub async fn find_by_id(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<User>, OidcError> {
        let sql = &format!("SELECT {USER_COLUMNS} FROM users WHERE id = $1 AND deleted_at IS NULL");
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
        let sql = &format!(
            "SELECT {USER_COLUMNS} FROM users WHERE realm_id = $1 AND email = $2 AND deleted_at IS NULL"
        );
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
                given_name, family_name, middle_name, nickname, preferred_username,
                profile, picture, website, gender, birthdate, zoneinfo,
                phone_number, phone_number_verified,
                street_address, locality, region, postal_code, country,
                locale, attributes, enabled, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28)
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
                &entity.middle_name,
                &entity.nickname,
                &entity.preferred_username,
                &entity.profile,
                &entity.picture,
                &entity.website,
                &entity.gender,
                &entity.birthdate,
                &entity.zoneinfo,
                &entity.phone_number,
                &entity.phone_number_verified.unwrap_or(false),
                &entity.street_address,
                &entity.locality,
                &entity.region,
                &entity.postal_code,
                &entity.country,
                &entity.locale,
                &entity.attributes,
                &entity.enabled,
                &entity.updated_at,
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
                middle_name = $7,
                nickname = $8,
                preferred_username = $9,
                profile = $10,
                picture = $11,
                website = $12,
                gender = $13,
                birthdate = $14,
                zoneinfo = $15,
                phone_number = $16,
                phone_number_verified = $17,
                street_address = $18,
                locality = $19,
                region = $20,
                postal_code = $21,
                country = $22,
                locale = $23,
                attributes = $24,
                enabled = $25,
                updated_at = NOW()
            WHERE id = $26 AND deleted_at IS NULL
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
                &entity.middle_name,
                &entity.nickname,
                &entity.preferred_username,
                &entity.profile,
                &entity.picture,
                &entity.website,
                &entity.gender,
                &entity.birthdate,
                &entity.zoneinfo,
                &entity.phone_number,
                &entity.phone_number_verified.unwrap_or(false),
                &entity.street_address,
                &entity.locality,
                &entity.region,
                &entity.postal_code,
                &entity.country,
                &entity.locale,
                &entity.attributes,
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
        let mut where_clauses = vec!["deleted_at IS NULL".to_string()];
        let mut param_idx = 1usize;

        if realm_id.is_some() {
            where_clauses.push(format!("realm_id = ${}", param_idx));
            param_idx += 1;
        }
        if search.is_some() {
            where_clauses.push(format!(
                "(email ILIKE ${} OR username ILIKE ${} OR given_name ILIKE ${} OR family_name ILIKE ${})",
                param_idx, param_idx, param_idx, param_idx
            ));
            param_idx += 1;
        }

        let where_sql = where_clauses.join(" AND ");
        let limit_idx = param_idx;
        let offset_idx = param_idx + 1;

        let sql = format!(
            "SELECT {USER_COLUMNS} FROM users WHERE {where_sql} ORDER BY created_at DESC LIMIT ${limit_idx} OFFSET ${offset_idx}"
        );

        let realm_id_ref = realm_id.as_ref();
        let pattern = search.map(|s| format!("%{}%", escape_like(s)));

        let mut params: Vec<&dyn wasi_pg_client::ToSql> = Vec::new();
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

    /// Count users in a realm.
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
        let sql = format!("SELECT COUNT(*) FROM users WHERE {where_sql}");

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
            middle_name: mapper::opt_string(row, 8)?,
            nickname: mapper::opt_string(row, 9)?,
            preferred_username: mapper::opt_string(row, 10)?,
            profile: mapper::opt_string(row, 11)?,
            picture: mapper::opt_string(row, 12)?,
            website: mapper::opt_string(row, 13)?,
            gender: mapper::opt_string(row, 14)?,
            birthdate: mapper::opt_string(row, 15)?,
            zoneinfo: mapper::opt_string(row, 16)?,
            phone_number: mapper::opt_string(row, 17)?,
            phone_number_verified: mapper::opt_bool(row, 18)?,
            street_address: mapper::opt_string(row, 19)?,
            locality: mapper::opt_string(row, 20)?,
            region: mapper::opt_string(row, 21)?,
            postal_code: mapper::opt_string(row, 22)?,
            country: mapper::opt_string(row, 23)?,
            locale: mapper::string(row, 24)?,
            attributes: row.get::<serde_json::Value>(25).map_err(mapper::pg_err)?,
            enabled: mapper::bool_(row, 26)?,
            deleted_at: mapper::opt_datetime(row, 27)?,
            updated_at: mapper::datetime(row, 28)?,
        })
    }
}
