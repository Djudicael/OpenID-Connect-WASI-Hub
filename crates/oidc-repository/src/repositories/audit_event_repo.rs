use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::audit_event::{ActorType, AuditEvent};
use uuid::Uuid;

/// PostgreSQL implementation of the AuditEvent repository.
pub struct AuditEventRepo;

impl AuditEventRepo {
    /// Find an audit event by its primary key.
    pub async fn find_by_id(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<AuditEvent>, OidcError> {
        let sql = r#"
            SELECT id, realm_id, event_type, actor_id, actor_type,
                   target_type, target_id, details, ip_address::TEXT, user_agent, created_at
            FROM audit_events
            WHERE id = $1
        "#;
        let row = conn
            .query_one_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find audit events for a realm within a time range.
    pub async fn find_by_realm(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
        limit: i64,
    ) -> Result<Vec<AuditEvent>, OidcError> {
        let sql = r#"
            SELECT id, realm_id, event_type, actor_id, actor_type,
                   target_type, target_id, details, ip_address::TEXT, user_agent, created_at
            FROM audit_events
            WHERE realm_id = $1
            ORDER BY created_at DESC
            LIMIT $2
        "#;
        let result = conn
            .query_params(sql, &[&realm_id, &limit])
            .await
            .map_err(mapper::pg_err)?;
        result
            .into_rows()
            .iter()
            .map(|r| Self::map_row(r))
            .collect::<Result<Vec<_>, _>>()
    }

    /// Find audit events by actor.
    pub async fn find_by_actor(
        &self,
        conn: &mut Connection,
        actor_id: Uuid,
        limit: i64,
    ) -> Result<Vec<AuditEvent>, OidcError> {
        let sql = r#"
            SELECT id, realm_id, event_type, actor_id, actor_type,
                   target_type, target_id, details, ip_address::TEXT, user_agent, created_at
            FROM audit_events
            WHERE actor_id = $1
            ORDER BY created_at DESC
            LIMIT $2
        "#;
        let result = conn
            .query_params(sql, &[&actor_id, &limit])
            .await
            .map_err(mapper::pg_err)?;
        result
            .into_rows()
            .iter()
            .map(|r| Self::map_row(r))
            .collect::<Result<Vec<_>, _>>()
    }

    /// List recent audit events across all realms.
    pub async fn list_recent(
        &self,
        conn: &mut Connection,
        limit: i64,
    ) -> Result<Vec<AuditEvent>, OidcError> {
        let sql = r#"
            SELECT id, realm_id, event_type, actor_id, actor_type,
                   target_type, target_id, details, ip_address::TEXT, user_agent, created_at
            FROM audit_events
            ORDER BY created_at DESC
            LIMIT $1
        "#;
        let result = conn
            .query_params(sql, &[&limit])
            .await
            .map_err(mapper::pg_err)?;
        result
            .into_rows()
            .iter()
            .map(|r| Self::map_row(r))
            .collect::<Result<Vec<_>, _>>()
    }

    /// Insert a new audit event.
    pub async fn create(
        &self,
        conn: &mut Connection,
        entity: &AuditEvent,
    ) -> Result<(), OidcError> {
        let sql = r#"
            INSERT INTO audit_events (
                id, realm_id, event_type, actor_id, actor_type,
                target_type, target_id, details, ip_address, user_agent, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#;
        let ip_str = entity.ip_address.map(|ip| ip.to_string());
        conn.execute_params(
            sql,
            &[
                &entity.id,
                &entity.realm_id,
                &entity.event_type,
                &entity.actor_id,
                &entity.actor_type.to_string(),
                &entity.target_type,
                &entity.target_id,
                &entity.details,
                &ip_str,
                &entity.user_agent,
                &entity.created_at,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<AuditEvent, OidcError> {
        let actor_type_str: String = mapper::string(row, 4)?;
        let actor_type = match actor_type_str.as_str() {
            "user" => ActorType::User,
            "api_key" => ActorType::ApiKey,
            _ => ActorType::System,
        };

        let ip_str: Option<String> = mapper::opt_string(row, 8)?;
        let ip_address = ip_str.and_then(|s| s.parse().ok());

        Ok(AuditEvent {
            id: mapper::uuid(row, 0)?,
            realm_id: mapper::opt_uuid(row, 1)?,
            event_type: mapper::string(row, 2)?,
            actor_id: mapper::opt_uuid(row, 3)?,
            actor_type,
            target_type: mapper::opt_string(row, 5)?,
            target_id: mapper::opt_uuid(row, 6)?,
            details: row.get::<serde_json::Value>(7).map_err(mapper::pg_err)?,
            ip_address,
            user_agent: mapper::opt_string(row, 9)?,
            created_at: mapper::datetime(row, 10)?,
        })
    }
}
