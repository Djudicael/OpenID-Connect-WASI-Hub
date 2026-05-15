use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::{IdentityProvider, IdentityProviderType};
use uuid::Uuid;

/// PostgreSQL implementation of the IdentityProvider repository.
pub struct IdentityProviderRepo;

/// Column list for identity_providers SELECT queries (order must match map_row indices).
const IDP_COLUMNS: &str = r#"
    id, realm_id, alias, display_name, provider_type, enabled,
    issuer, authorization_url, token_url, userinfo_url, jwks_url,
    client_id, client_secret, scopes,
    auto_create_users, link_users_by_email, deleted_at
"#;

impl IdentityProviderRepo {
    /// Find an identity provider by its primary key.
    pub async fn find_by_id(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<IdentityProvider>, OidcError> {
        let sql = &format!(
            "SELECT {IDP_COLUMNS} FROM identity_providers WHERE id = $1 AND deleted_at IS NULL"
        );
        let row = conn
            .query_one_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find an identity provider by alias within a realm.
    pub async fn find_by_alias(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
        alias: &str,
    ) -> Result<Option<IdentityProvider>, OidcError> {
        let sql = &format!(
            "SELECT {IDP_COLUMNS} FROM identity_providers WHERE realm_id = $1 AND alias = $2 AND deleted_at IS NULL"
        );
        let row = conn
            .query_one_params(sql, &[&realm_id, &alias])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find all enabled identity providers for a realm.
    pub async fn find_by_realm(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
    ) -> Result<Vec<IdentityProvider>, OidcError> {
        let sql = &format!(
            "SELECT {IDP_COLUMNS} FROM identity_providers WHERE realm_id = $1 AND deleted_at IS NULL AND enabled = TRUE"
        );
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

    /// Insert a new identity provider.
    pub async fn create(
        &self,
        conn: &mut Connection,
        entity: &IdentityProvider,
    ) -> Result<(), OidcError> {
        let sql = r#"
            INSERT INTO identity_providers (
                id, realm_id, alias, display_name, provider_type, enabled,
                issuer, authorization_url, token_url, userinfo_url, jwks_url,
                client_id, client_secret, scopes,
                auto_create_users, link_users_by_email
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
        "#;
        let provider_type_str = match entity.provider_type {
            IdentityProviderType::Oidc => "oidc",
            IdentityProviderType::Google => "google",
            IdentityProviderType::GitHub => "github",
        };
        conn.execute_params(
            sql,
            &[
                &entity.id,
                &entity.realm_id,
                &entity.alias,
                &entity.display_name,
                &provider_type_str,
                &entity.enabled,
                &entity.issuer,
                &entity.authorization_url,
                &entity.token_url,
                &entity.userinfo_url,
                &entity.jwks_url,
                &entity.client_id,
                &entity.client_secret,
                &mapper::to_json_value_vec(&entity.scopes),
                &entity.auto_create_users,
                &entity.link_users_by_email,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Update an existing identity provider.
    pub async fn update(
        &self,
        conn: &mut Connection,
        entity: &IdentityProvider,
    ) -> Result<(), OidcError> {
        let sql = r#"
            UPDATE identity_providers SET
                alias = $1, display_name = $2, provider_type = $3, enabled = $4,
                issuer = $5, authorization_url = $6, token_url = $7, userinfo_url = $8,
                jwks_url = $9, client_id = $10, client_secret = $11, scopes = $12,
                auto_create_users = $13, link_users_by_email = $14
            WHERE id = $15 AND deleted_at IS NULL
        "#;
        let provider_type_str = match entity.provider_type {
            IdentityProviderType::Oidc => "oidc",
            IdentityProviderType::Google => "google",
            IdentityProviderType::GitHub => "github",
        };
        conn.execute_params(
            sql,
            &[
                &entity.alias,
                &entity.display_name,
                &provider_type_str,
                &entity.enabled,
                &entity.issuer,
                &entity.authorization_url,
                &entity.token_url,
                &entity.userinfo_url,
                &entity.jwks_url,
                &entity.client_id,
                &entity.client_secret,
                &mapper::to_json_value_vec(&entity.scopes),
                &entity.auto_create_users,
                &entity.link_users_by_email,
                &entity.id,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Soft-delete an identity provider by ID.
    pub async fn delete(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "UPDATE identity_providers SET deleted_at = NOW() WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<IdentityProvider, OidcError> {
        let provider_type_str: String = mapper::string(row, 4)?;
        let provider_type = match provider_type_str.as_str() {
            "google" => IdentityProviderType::Google,
            "github" => IdentityProviderType::GitHub,
            _ => IdentityProviderType::Oidc,
        };
        Ok(IdentityProvider {
            id: mapper::uuid(row, 0)?,
            realm_id: mapper::uuid(row, 1)?,
            alias: mapper::string(row, 2)?,
            display_name: mapper::string(row, 3)?,
            provider_type,
            enabled: mapper::bool_(row, 5)?,
            issuer: mapper::string(row, 6)?,
            authorization_url: mapper::string(row, 7)?,
            token_url: mapper::string(row, 8)?,
            userinfo_url: mapper::string(row, 9)?,
            jwks_url: mapper::string(row, 10)?,
            client_id: mapper::string(row, 11)?,
            client_secret: mapper::string(row, 12)?,
            scopes: mapper::json_string_vec(row, 13)?,
            auto_create_users: mapper::bool_(row, 14)?,
            link_users_by_email: mapper::bool_(row, 15)?,
            deleted_at: mapper::opt_datetime(row, 16)?,
        })
    }
}
