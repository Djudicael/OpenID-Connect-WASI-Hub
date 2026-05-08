use crate::connection::Connection;
use crate::mapper;
use oidc_core::models::{Client, ClientType};
use oidc_core::OidcError;
use uuid::Uuid;

/// PostgreSQL implementation of the Client repository.
pub struct ClientRepo;

impl ClientRepo {
    /// Find a client by its primary key.
    pub async fn find_by_id(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<Client>, OidcError> {
        let sql = r#"
            SELECT id, realm_id, client_id, client_type, client_secret_hash,
                   name, redirect_uris, allowed_scopes, allowed_grant_types,
                   pkce_required, enabled
            FROM clients
            WHERE id = $1
        "#;
        let row = conn.query_one_params(sql, &[&id]).await.map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find a client by its globally unique client_id string.
    pub async fn find_by_client_id(
        &self,
        conn: &mut Connection,
        client_id: &str,
    ) -> Result<Option<Client>, OidcError> {
        let sql = r#"
            SELECT id, realm_id, client_id, client_type, client_secret_hash,
                   name, redirect_uris, allowed_scopes, allowed_grant_types,
                   pkce_required, enabled
            FROM clients
            WHERE client_id = $1
        "#;
        let row = conn
            .query_one_params(sql, &[&client_id])
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
                pkce_required, enabled
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
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
                updated_at = NOW()
            WHERE id = $10
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
                &entity.id,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Hard-delete a client by ID.
    pub async fn delete(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "DELETE FROM clients WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
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
        })
    }
}
