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

    /// Find audit events for a realm with pagination, optional event type, and time-range filters.
    pub async fn find_by_realm(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
        limit: i64,
        offset: i64,
        event_type: Option<&str>,
        from: Option<chrono::DateTime<chrono::Utc>>,
        to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Vec<AuditEvent>, OidcError> {
        let mut where_clauses = vec!["realm_id = $1".to_string()];
        let mut param_idx = 2usize;

        if event_type.is_some() {
            where_clauses.push(format!("event_type = ${}", param_idx));
            param_idx += 1;
        }
        if from.is_some() {
            where_clauses.push(format!("created_at >= ${}", param_idx));
            param_idx += 1;
        }
        if to.is_some() {
            where_clauses.push(format!("created_at <= ${}", param_idx));
            param_idx += 1;
        }

        let where_sql = where_clauses.join(" AND ");
        let limit_idx = param_idx;
        let offset_idx = param_idx + 1;

        let sql = format!(
            "SELECT id, realm_id, event_type, actor_id, actor_type, \
             target_type, target_id, details, ip_address::TEXT, user_agent, created_at \
             FROM audit_events WHERE {where_sql} ORDER BY created_at DESC LIMIT ${limit_idx} OFFSET ${offset_idx}"
        );

        let event_type_ref = event_type.as_ref();
        let from_ref = from.as_ref();
        let to_ref = to.as_ref();

        let mut params: Vec<&dyn wasi_pg_client::ToSql> = vec![&realm_id];
        if let Some(et) = event_type_ref {
            params.push(et);
        }
        if let Some(f) = from_ref {
            params.push(f);
        }
        if let Some(t) = to_ref {
            params.push(t);
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

    /// Find audit events by actor.
    pub async fn find_by_actor(
        &self,
        conn: &mut Connection,
        actor_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditEvent>, OidcError> {
        let sql = r#"
            SELECT id, realm_id, event_type, actor_id, actor_type,
                   target_type, target_id, details, ip_address::TEXT, user_agent, created_at
            FROM audit_events
            WHERE actor_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
        "#;
        let result = conn
            .query_params(sql, &[&actor_id, &limit, &offset])
            .await
            .map_err(mapper::pg_err)?;
        result
            .into_rows()
            .iter()
            .map(|r| Self::map_row(r))
            .collect::<Result<Vec<_>, _>>()
    }

    /// List recent audit events across all realms with optional filtering and time-range.
    pub async fn list_recent(
        &self,
        conn: &mut Connection,
        limit: i64,
        offset: i64,
        event_type: Option<&str>,
        actor_id: Option<&Uuid>,
        from: Option<chrono::DateTime<chrono::Utc>>,
        to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Vec<AuditEvent>, OidcError> {
        let mut where_clauses: Vec<String> = Vec::new();
        let mut param_idx = 1usize;

        if event_type.is_some() {
            where_clauses.push(format!("event_type = ${}", param_idx));
            param_idx += 1;
        }
        if actor_id.is_some() {
            where_clauses.push(format!("actor_id = ${}", param_idx));
            param_idx += 1;
        }
        if from.is_some() {
            where_clauses.push(format!("created_at >= ${}", param_idx));
            param_idx += 1;
        }
        if to.is_some() {
            where_clauses.push(format!("created_at <= ${}", param_idx));
            param_idx += 1;
        }

        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        let limit_idx = param_idx;
        let offset_idx = param_idx + 1;

        let sql = format!(
            "SELECT id, realm_id, event_type, actor_id, actor_type, \
             target_type, target_id, details, ip_address::TEXT, user_agent, created_at \
             FROM audit_events {where_sql} ORDER BY created_at DESC LIMIT ${limit_idx} OFFSET ${offset_idx}"
        );

        let event_type_ref = event_type.as_ref();
        let actor_id_owned = actor_id.cloned(); // Option<Uuid> so we can borrow it
        let actor_id_ref = actor_id_owned.as_ref();
        let from_ref = from.as_ref();
        let to_ref = to.as_ref();

        let mut params: Vec<&dyn wasi_pg_client::ToSql> = Vec::new();
        if let Some(et) = event_type_ref {
            params.push(et);
        }
        if let Some(aid) = actor_id_ref {
            params.push(aid);
        }
        if let Some(f) = from_ref {
            params.push(f);
        }
        if let Some(t) = to_ref {
            params.push(t);
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

    /// Count audit events with optional filtering and time-range.
    pub async fn count(
        &self,
        conn: &mut Connection,
        realm_id: Option<Uuid>,
        event_type: Option<&str>,
        actor_id: Option<&Uuid>,
        from: Option<chrono::DateTime<chrono::Utc>>,
        to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<i64, OidcError> {
        let mut where_clauses: Vec<String> = Vec::new();
        let mut param_idx = 1usize;

        if realm_id.is_some() {
            where_clauses.push(format!("realm_id = ${}", param_idx));
            param_idx += 1;
        }
        if event_type.is_some() {
            where_clauses.push(format!("event_type = ${}", param_idx));
            param_idx += 1;
        }
        if actor_id.is_some() {
            where_clauses.push(format!("actor_id = ${}", param_idx));
            param_idx += 1;
        }
        if from.is_some() {
            where_clauses.push(format!("created_at >= ${}", param_idx));
            param_idx += 1;
        }
        if to.is_some() {
            where_clauses.push(format!("created_at <= ${}", param_idx));
        }

        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        let sql = format!("SELECT COUNT(*) FROM audit_events {where_sql}");

        let realm_id_ref = realm_id.as_ref();
        let event_type_ref = event_type.as_ref();
        let actor_id_owned = actor_id.cloned(); // Option<Uuid> so we can borrow it
        let actor_id_ref = actor_id_owned.as_ref();
        let from_ref = from.as_ref();
        let to_ref = to.as_ref();

        let mut params: Vec<&dyn wasi_pg_client::ToSql> = Vec::new();
        if let Some(rid) = realm_id_ref {
            params.push(rid);
        }
        if let Some(et) = event_type_ref {
            params.push(et);
        }
        if let Some(aid) = actor_id_ref {
            params.push(aid);
        }
        if let Some(f) = from_ref {
            params.push(f);
        }
        if let Some(t) = to_ref {
            params.push(t);
        }

        let result = if params.is_empty() {
            conn.query(&sql).await.map_err(mapper::pg_err)?
        } else {
            conn.query_params(&sql, &params)
                .await
                .map_err(mapper::pg_err)?
        };
        let row = result
            .into_rows()
            .into_iter()
            .next()
            .ok_or(OidcError::Internal("count returned no rows".into()))?;
        mapper::i64_(&row, 0)
    }

    /// Count recent failed login attempts for a user identified by email in a realm.
    ///
    /// This is used for brute-force protection: looks up the user by email
    /// and counts `LOGIN_FAILURE` events within the last 5 minutes.
    pub async fn count_recent_failures(
        &self,
        conn: &mut Connection,
        email: &str,
        realm_id: Uuid,
    ) -> Result<i64, OidcError> {
        let sql = r#"
            SELECT COUNT(*) FROM audit_events
            WHERE event_type = 'LOGIN_FAILURE'
              AND actor_id = (SELECT id FROM users WHERE email = $1 AND realm_id = $2 LIMIT 1)
              AND created_at > NOW() - INTERVAL '5 minutes'
        "#;
        let result = conn
            .query_one_params(sql, &[&email, &realm_id])
            .await
            .map_err(mapper::pg_err)?;
        match result {
            Some(row) => mapper::i64_(&row, 0),
            None => Ok(0),
        }
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
