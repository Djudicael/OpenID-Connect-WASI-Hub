use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::{Role, User};
use uuid::Uuid;

/// Column list for role SELECT queries (order must match RoleRepo::map_row indices).
const ROLE_COLUMNS: &str = r#"
    r.id, r.realm_id, r.name, r.description, r.permissions, r.created_at, r.updated_at
"#;

/// Column list for user SELECT queries (order must match UserRepo::map_row indices).
const USER_COLUMNS: &str = r#"
    u.id, u.realm_id, u.email, u.email_verified, u.username, u.password_hash,
    u.given_name, u.family_name, u.middle_name, u.nickname, u.preferred_username,
    u.profile, u.picture, u.website, u.gender, u.birthdate, u.zoneinfo,
    u.phone_number, u.phone_number_verified,
    u.street_address, u.locality, u.region, u.postal_code, u.country,
    u.locale, u.attributes, u.enabled,
    u.deleted_at, u.updated_at
"#;

/// PostgreSQL implementation of the User-Role assignment repository.
pub struct UserRoleRepo;

impl UserRoleRepo {
    /// Assign a role to a user.
    pub async fn assign(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
        role_id: Uuid,
    ) -> Result<(), OidcError> {
        let sql = "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)";
        conn.execute_params(sql, &[&user_id, &role_id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Unassign a role from a user.
    pub async fn unassign(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
        role_id: Uuid,
    ) -> Result<(), OidcError> {
        let sql = "DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2";
        conn.execute_params(sql, &[&user_id, &role_id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Find all roles assigned to a user.
    pub async fn find_roles_by_user(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
    ) -> Result<Vec<Role>, OidcError> {
        let sql = &format!(
            "SELECT {ROLE_COLUMNS} FROM roles r \
             INNER JOIN user_roles ur ON ur.role_id = r.id \
             WHERE ur.user_id = $1 AND r.deleted_at IS NULL"
        );
        let result = conn
            .query_params(sql, &[&user_id])
            .await
            .map_err(mapper::pg_err)?;
        result
            .into_rows()
            .iter()
            .map(|r| Self::map_role_row(r))
            .collect::<Result<Vec<_>, _>>()
    }

    /// Find all users that have a specific role.
    pub async fn find_users_by_role(
        &self,
        conn: &mut Connection,
        role_id: Uuid,
    ) -> Result<Vec<User>, OidcError> {
        let sql = &format!(
            "SELECT {USER_COLUMNS} FROM users u \
             INNER JOIN user_roles ur ON ur.user_id = u.id \
             WHERE ur.role_id = $1 AND u.deleted_at IS NULL"
        );
        let result = conn
            .query_params(sql, &[&role_id])
            .await
            .map_err(mapper::pg_err)?;
        result
            .into_rows()
            .iter()
            .map(|r| Self::map_user_row(r))
            .collect::<Result<Vec<_>, _>>()
    }

    fn map_role_row(row: &wasi_pg_client::Row) -> Result<Role, OidcError> {
        Ok(Role {
            id: mapper::uuid(row, 0)?,
            realm_id: mapper::uuid(row, 1)?,
            name: mapper::string(row, 2)?,
            description: mapper::opt_string(row, 3)?,
            permissions: mapper::json_string_vec(row, 4)?,
            created_at: mapper::datetime(row, 5)?,
            updated_at: mapper::datetime(row, 6)?,
        })
    }

    fn map_user_row(row: &wasi_pg_client::Row) -> Result<User, OidcError> {
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
