use chrono::{Duration, Utc};
use oidc_core::{
    OidcError,
    models::{
        AuditEvent, Workflow, WorkflowAction, WorkflowCondition, WorkflowExecution,
        WorkflowExecutionStatus,
    },
    utils::generate_uuid_v7,
};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;

use crate::{Connection, mapper};

pub struct WorkflowRepo;

#[derive(Debug, Default, Serialize)]
pub struct WorkflowRunReport {
    pub scheduled_workflows: usize,
    pub enqueued: usize,
    pub completed: usize,
    pub waiting: usize,
    pub failed: usize,
    pub cancelled: usize,
}

impl WorkflowRepo {
    pub async fn validate_references(
        &self,
        conn: &mut Connection,
        workflow: &Workflow,
    ) -> Result<(), OidcError> {
        let mut roles = Vec::new();
        let mut groups = Vec::new();
        for condition in &workflow.conditions {
            match condition {
                WorkflowCondition::HasRole { role_id } => roles.push(*role_id),
                WorkflowCondition::InGroup { group_id } => groups.push(*group_id),
                _ => {}
            }
        }
        for step in &workflow.steps {
            match step.action {
                WorkflowAction::GrantRole { role_id } | WorkflowAction::RevokeRole { role_id } => {
                    roles.push(role_id)
                }
                WorkflowAction::JoinGroup { group_id }
                | WorkflowAction::LeaveGroup { group_id } => groups.push(group_id),
                _ => {}
            }
        }
        roles.sort_unstable();
        roles.dedup();
        groups.sort_unstable();
        groups.dedup();
        for id in roles {
            if conn
                .query_one_params(
                    "SELECT 1 FROM roles WHERE id=$1 AND realm_id=$2 AND deleted_at IS NULL",
                    &[&id, &workflow.realm_id],
                )
                .await
                .map_err(mapper::pg_err)?
                .is_none()
            {
                return Err(OidcError::InvalidInput(format!(
                    "role {id} does not exist in this realm"
                )));
            }
        }
        for id in groups {
            if conn
                .query_one_params(
                    "SELECT 1 FROM groups WHERE id=$1 AND realm_id=$2 AND deleted_at IS NULL",
                    &[&id, &workflow.realm_id],
                )
                .await
                .map_err(mapper::pg_err)?
                .is_none()
            {
                return Err(OidcError::InvalidInput(format!(
                    "group {id} does not exist in this realm"
                )));
            }
        }
        Ok(())
    }
    pub async fn list(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
    ) -> Result<Vec<Workflow>, OidcError> {
        let rows=conn.query_params("SELECT id,realm_id,name,description,enabled,trigger_events,conditions,steps,schedule_config,last_scheduled_at,created_at,updated_at FROM workflows WHERE realm_id=$1 AND deleted_at IS NULL ORDER BY lower(name)",&[&realm_id]).await.map_err(mapper::pg_err)?;
        rows.iter().map(Self::map_workflow).collect()
    }
    pub async fn find(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<Workflow>, OidcError> {
        conn.query_one_params("SELECT id,realm_id,name,description,enabled,trigger_events,conditions,steps,schedule_config,last_scheduled_at,created_at,updated_at FROM workflows WHERE id=$1 AND deleted_at IS NULL",&[&id]).await.map_err(mapper::pg_err)?.map(|r|Self::map_workflow(&r)).transpose()
    }
    pub async fn create(&self, conn: &mut Connection, value: &Workflow) -> Result<(), OidcError> {
        value.validate()?;
        let events = json!(value.trigger_events);
        let conditions = json!(value.conditions);
        let steps = json!(value.steps);
        let schedule = serde_json::to_value(&value.schedule)
            .map_err(|e| OidcError::InvalidInput(e.to_string()))?;
        conn.execute_params("INSERT INTO workflows(id,realm_id,name,description,enabled,trigger_events,conditions,steps,schedule_config,last_scheduled_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",&[&value.id,&value.realm_id,&value.name,&value.description,&value.enabled,&events,&conditions,&steps,&schedule,&value.last_scheduled_at,&value.created_at,&value.updated_at]).await.map_err(mapper::pg_err)?;
        Ok(())
    }
    pub async fn update(&self, conn: &mut Connection, value: &Workflow) -> Result<(), OidcError> {
        value.validate()?;
        let events = json!(value.trigger_events);
        let conditions = json!(value.conditions);
        let steps = json!(value.steps);
        let schedule = serde_json::to_value(&value.schedule)
            .map_err(|e| OidcError::InvalidInput(e.to_string()))?;
        conn.execute_params("UPDATE workflows SET name=$2,description=$3,enabled=$4,trigger_events=$5,conditions=$6,steps=$7,schedule_config=$8,updated_at=$9 WHERE id=$1 AND deleted_at IS NULL",&[&value.id,&value.name,&value.description,&value.enabled,&events,&conditions,&steps,&schedule,&value.updated_at]).await.map_err(mapper::pg_err)?;
        Ok(())
    }
    pub async fn delete(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        conn.execute_params(
            "UPDATE workflows SET deleted_at=NOW(),enabled=FALSE,updated_at=NOW() WHERE id=$1",
            &[&id],
        )
        .await
        .map_err(mapper::pg_err)?;
        conn.execute_params("UPDATE workflow_executions SET status='cancelled',completed_at=NOW(),updated_at=NOW(),last_error='Workflow deleted' WHERE workflow_id=$1 AND status IN ('queued','waiting','running')",&[&id]).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn list_executions(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
        workflow_id: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<WorkflowExecution>, OidcError> {
        let limit = limit.clamp(1, 500);
        let rows=if let Some(id)=workflow_id { conn.query_params("SELECT id,workflow_id,realm_id,user_id,trigger_event,status,current_step,attempts,next_run_at,last_error,started_at,completed_at,created_at,updated_at FROM workflow_executions WHERE realm_id=$1 AND workflow_id=$2 ORDER BY created_at DESC LIMIT $3",&[&realm_id,&id,&limit]).await } else { conn.query_params("SELECT id,workflow_id,realm_id,user_id,trigger_event,status,current_step,attempts,next_run_at,last_error,started_at,completed_at,created_at,updated_at FROM workflow_executions WHERE realm_id=$1 ORDER BY created_at DESC LIMIT $2",&[&realm_id,&limit]).await }.map_err(mapper::pg_err)?;
        rows.iter().map(Self::map_execution).collect()
    }

    pub async fn activate(
        &self,
        conn: &mut Connection,
        workflow: &Workflow,
        user_id: Uuid,
        trigger_event: &str,
    ) -> Result<Option<Uuid>, OidcError> {
        let user=conn.query_one_params("SELECT enabled,email_verified,attributes FROM users WHERE id=$1 AND realm_id=$2 AND deleted_at IS NULL",&[&user_id,&workflow.realm_id]).await.map_err(mapper::pg_err)?;
        let Some(user) = user else {
            return Err(OidcError::NotFound("user not found".into()));
        };
        if !Self::conditions_match(conn, workflow, user_id, &user).await? {
            return Ok(None);
        }
        let id = generate_uuid_v7();
        let now = Utc::now();
        let delay = workflow.steps.first().map(|s| s.after_seconds).unwrap_or(0);
        let next = now + Duration::seconds(delay);
        let status = if delay > 0 { "waiting" } else { "queued" };
        let inserted=conn.execute_params("INSERT INTO workflow_executions(id,workflow_id,realm_id,user_id,trigger_event,status,current_step,attempts,next_run_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,0,0,$7,$8,$8) ON CONFLICT DO NOTHING",&[&id,&workflow.id,&workflow.realm_id,&user_id,&trigger_event,&status,&next,&now]).await.map_err(mapper::pg_err)?;
        if inserted == 0 {
            Ok(None)
        } else {
            Self::lifecycle_audit(
                conn,
                workflow.realm_id,
                "workflow.activated",
                id,
                user_id,
                json!({"workflow_id":workflow.id,"trigger":trigger_event}),
            )
            .await?;
            Ok(Some(id))
        }
    }

    pub async fn dispatch_event(
        &self,
        conn: &mut Connection,
        event: &AuditEvent,
    ) -> Result<WorkflowRunReport, OidcError> {
        let (Some(realm_id), Some(user_id)) = (event.realm_id, Self::event_user(event)) else {
            return Ok(Default::default());
        };
        if event.event_type.starts_with("workflow.") {
            return Ok(Default::default());
        }
        let workflows = self.list(conn, realm_id).await?;
        let mut report = WorkflowRunReport::default();
        for workflow in workflows.into_iter().filter(|w| {
            w.enabled
                && w.trigger_events
                    .iter()
                    .any(|p| Self::event_matches(p, &event.event_type))
        }) {
            if self
                .activate(conn, &workflow, user_id, &event.event_type)
                .await?
                .is_some()
            {
                report.enqueued += 1;
            }
        }
        let ran = self.run_due(conn, Some(realm_id), 200, false).await?;
        report.completed += ran.completed;
        report.waiting += ran.waiting;
        report.failed += ran.failed;
        report.cancelled += ran.cancelled;
        Ok(report)
    }

    pub async fn run_due(
        &self,
        conn: &mut Connection,
        realm_id: Option<Uuid>,
        limit: i64,
        include_schedules: bool,
    ) -> Result<WorkflowRunReport, OidcError> {
        let mut report = WorkflowRunReport::default();
        if include_schedules {
            self.enqueue_schedules(conn, realm_id, &mut report).await?;
        }
        let limit = limit.clamp(1, 1000);
        let rows=if let Some(realm)=realm_id { conn.query_params("SELECT id FROM workflow_executions WHERE realm_id=$1 AND status IN ('queued','waiting') AND next_run_at<=NOW() ORDER BY next_run_at LIMIT $2",&[&realm,&limit]).await } else { conn.query_params("SELECT id FROM workflow_executions WHERE status IN ('queued','waiting') AND next_run_at<=NOW() ORDER BY next_run_at LIMIT $1",&[&limit]).await }.map_err(mapper::pg_err)?;
        let ids = rows
            .iter()
            .map(|r| mapper::uuid(r, 0))
            .collect::<Result<Vec<_>, _>>()?;
        for id in ids {
            match self.process(conn, id).await {
                Ok(WorkflowExecutionStatus::Completed) => report.completed += 1,
                Ok(WorkflowExecutionStatus::Waiting) => report.waiting += 1,
                Ok(WorkflowExecutionStatus::Cancelled) => report.cancelled += 1,
                Ok(WorkflowExecutionStatus::Failed) => report.failed += 1,
                Ok(_) => {}
                Err(_) => report.failed += 1,
            }
        }
        Ok(report)
    }

    async fn enqueue_schedules(
        &self,
        conn: &mut Connection,
        realm_id: Option<Uuid>,
        report: &mut WorkflowRunReport,
    ) -> Result<(), OidcError> {
        let workflows = if let Some(realm) = realm_id {
            self.list(conn, realm).await?
        } else {
            let rows=conn.query("SELECT id,realm_id,name,description,enabled,trigger_events,conditions,steps,schedule_config,last_scheduled_at,created_at,updated_at FROM workflows WHERE enabled AND schedule_config IS NOT NULL AND deleted_at IS NULL ORDER BY created_at").await.map_err(mapper::pg_err)?;
            rows.iter()
                .map(Self::map_workflow)
                .collect::<Result<Vec<_>, _>>()?
        };
        let now = Utc::now();
        for workflow in workflows.into_iter().filter(|w| {
            w.enabled
                && w.schedule.as_ref().is_some_and(|s| {
                    w.last_scheduled_at
                        .is_none_or(|last| last + Duration::seconds(s.every_seconds) <= now)
                })
        }) {
            let schedule = workflow.schedule.as_ref().unwrap();
            let users=conn.query_params("SELECT u.id FROM users u LEFT JOIN workflow_executions e ON e.user_id=u.id AND e.workflow_id=$2 AND e.trigger_event='schedule' WHERE u.realm_id=$1 AND u.deleted_at IS NULL GROUP BY u.id,u.created_at ORDER BY MAX(e.created_at) NULLS FIRST,u.created_at LIMIT $3",&[&workflow.realm_id,&workflow.id,&schedule.batch_size]).await.map_err(mapper::pg_err)?;
            for row in users.iter() {
                let user_id = mapper::uuid(row, 0)?;
                if self
                    .activate(conn, &workflow, user_id, "schedule")
                    .await?
                    .is_some()
                {
                    report.enqueued += 1;
                }
            }
            conn.execute_params(
                "UPDATE workflows SET last_scheduled_at=$2,updated_at=$2 WHERE id=$1",
                &[&workflow.id, &now],
            )
            .await
            .map_err(mapper::pg_err)?;
            report.scheduled_workflows += 1;
        }
        Ok(())
    }

    pub async fn retry(
        &self,
        conn: &mut Connection,
        id: Uuid,
        realm_id: Uuid,
    ) -> Result<(), OidcError> {
        let changed=conn.execute_params("UPDATE workflow_executions SET status='queued',attempts=attempts+1,next_run_at=NOW(),last_error=NULL,completed_at=NULL,updated_at=NOW() WHERE id=$1 AND realm_id=$2 AND status='failed'",&[&id,&realm_id]).await.map_err(mapper::pg_err)?;
        if changed == 0 {
            return Err(OidcError::InvalidInput(
                "only failed executions can be retried".into(),
            ));
        }
        Ok(())
    }
    pub async fn cancel(
        &self,
        conn: &mut Connection,
        id: Uuid,
        realm_id: Uuid,
    ) -> Result<(), OidcError> {
        let changed=conn.execute_params("UPDATE workflow_executions SET status='cancelled',completed_at=NOW(),updated_at=NOW() WHERE id=$1 AND realm_id=$2 AND status IN ('queued','waiting','failed')",&[&id,&realm_id]).await.map_err(mapper::pg_err)?;
        if changed == 0 {
            return Err(OidcError::InvalidInput(
                "execution cannot be cancelled".into(),
            ));
        }
        Ok(())
    }

    async fn process(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<WorkflowExecutionStatus, OidcError> {
        let Some(mut execution) = self.find_execution(conn, id).await? else {
            return Err(OidcError::NotFound("workflow execution not found".into()));
        };
        let Some(workflow) = self.find(conn, execution.workflow_id).await? else {
            return self
                .finish_cancelled(conn, &execution, "Workflow is unavailable")
                .await;
        };
        if !workflow.enabled {
            return self
                .finish_cancelled(conn, &execution, "Workflow is disabled")
                .await;
        }
        conn.execute_params("UPDATE workflow_executions SET status='running',started_at=COALESCE(started_at,NOW()),updated_at=NOW() WHERE id=$1",&[&id]).await.map_err(mapper::pg_err)?;
        while (execution.current_step as usize) < workflow.steps.len() {
            let step = &workflow.steps[execution.current_step as usize];
            if let Err(error) = Self::execute_action(conn, execution.user_id, &step.action).await {
                let message = error.to_string();
                conn.execute_params("UPDATE workflow_executions SET status='failed',attempts=attempts+1,last_error=$2,updated_at=NOW() WHERE id=$1",&[&id,&message]).await.map_err(mapper::pg_err)?;
                Self::lifecycle_audit(conn,execution.realm_id,"workflow.failed",id,execution.user_id,json!({"workflow_id":workflow.id,"step":execution.current_step,"error":message})).await?;
                return Ok(WorkflowExecutionStatus::Failed);
            }
            Self::lifecycle_audit(conn,execution.realm_id,"workflow.step_completed",id,execution.user_id,json!({"workflow_id":workflow.id,"step":execution.current_step,"action":step.action})).await?;
            execution.current_step += 1;
            if (execution.current_step as usize) >= workflow.steps.len() {
                conn.execute_params("UPDATE workflow_executions SET status='completed',current_step=$2,completed_at=NOW(),updated_at=NOW() WHERE id=$1",&[&id,&execution.current_step]).await.map_err(mapper::pg_err)?;
                Self::lifecycle_audit(
                    conn,
                    execution.realm_id,
                    "workflow.completed",
                    id,
                    execution.user_id,
                    json!({"workflow_id":workflow.id}),
                )
                .await?;
                return Ok(WorkflowExecutionStatus::Completed);
            }
            let delay = workflow.steps[execution.current_step as usize].after_seconds;
            if delay > 0 {
                let next = Utc::now() + Duration::seconds(delay);
                conn.execute_params("UPDATE workflow_executions SET status='waiting',current_step=$2,next_run_at=$3,updated_at=NOW() WHERE id=$1",&[&id,&execution.current_step,&next]).await.map_err(mapper::pg_err)?;
                return Ok(WorkflowExecutionStatus::Waiting);
            }
            conn.execute_params(
                "UPDATE workflow_executions SET current_step=$2,updated_at=NOW() WHERE id=$1",
                &[&id, &execution.current_step],
            )
            .await
            .map_err(mapper::pg_err)?;
        }
        Ok(WorkflowExecutionStatus::Completed)
    }

    async fn execute_action(
        conn: &mut Connection,
        user_id: Uuid,
        action: &WorkflowAction,
    ) -> Result<(), OidcError> {
        match action {
            WorkflowAction::DisableUser => {
                conn.execute_params("UPDATE users SET enabled=FALSE,updated_at=NOW() WHERE id=$1 AND deleted_at IS NULL",&[&user_id]).await.map_err(mapper::pg_err)?;
            }
            WorkflowAction::EnableUser => {
                conn.execute_params("UPDATE users SET enabled=TRUE,updated_at=NOW() WHERE id=$1 AND deleted_at IS NULL",&[&user_id]).await.map_err(mapper::pg_err)?;
            }
            WorkflowAction::DeleteUser => {
                conn.execute_params("UPDATE users SET deleted_at=NOW(),enabled=FALSE,updated_at=NOW() WHERE id=$1 AND deleted_at IS NULL",&[&user_id]).await.map_err(mapper::pg_err)?;
            }
            WorkflowAction::AddRequiredAction { action } => {
                conn.execute_params("INSERT INTO user_required_actions(user_id,action) VALUES($1,$2) ON CONFLICT DO NOTHING",&[&user_id,&action.as_str()]).await.map_err(mapper::pg_err)?;
            }
            WorkflowAction::RemoveRequiredAction { action } => {
                conn.execute_params(
                    "DELETE FROM user_required_actions WHERE user_id=$1 AND action=$2",
                    &[&user_id, &action.as_str()],
                )
                .await
                .map_err(mapper::pg_err)?;
            }
            WorkflowAction::RevokeSessions => {
                conn.execute_params(
                    "UPDATE sessions SET revoked=TRUE WHERE user_id=$1 AND NOT revoked",
                    &[&user_id],
                )
                .await
                .map_err(mapper::pg_err)?;
            }
            WorkflowAction::SetUserAttribute { name, value } => {
                conn.execute_params("UPDATE users SET attributes=COALESCE(attributes,'{}'::jsonb)||jsonb_build_object($2::text,$3::text),updated_at=NOW() WHERE id=$1 AND deleted_at IS NULL",&[&user_id,name,value]).await.map_err(mapper::pg_err)?;
            }
            WorkflowAction::RemoveUserAttribute { name } => {
                conn.execute_params("UPDATE users SET attributes=COALESCE(attributes,'{}'::jsonb)-$2::text,updated_at=NOW() WHERE id=$1 AND deleted_at IS NULL",&[&user_id,name]).await.map_err(mapper::pg_err)?;
            }
            WorkflowAction::GrantRole { role_id } => {
                conn.execute_params("INSERT INTO user_roles(user_id,role_id) SELECT $1,r.id FROM roles r JOIN users u ON u.id=$1 WHERE r.id=$2 AND r.realm_id=u.realm_id AND r.deleted_at IS NULL ON CONFLICT DO NOTHING",&[&user_id,role_id]).await.map_err(mapper::pg_err)?;
            }
            WorkflowAction::RevokeRole { role_id } => {
                conn.execute_params(
                    "DELETE FROM user_roles WHERE user_id=$1 AND role_id=$2",
                    &[&user_id, role_id],
                )
                .await
                .map_err(mapper::pg_err)?;
            }
            WorkflowAction::JoinGroup { group_id } => {
                conn.execute_params("INSERT INTO user_groups(user_id,group_id) SELECT $1,g.id FROM groups g JOIN users u ON u.id=$1 WHERE g.id=$2 AND g.realm_id=u.realm_id AND g.deleted_at IS NULL ON CONFLICT DO NOTHING",&[&user_id,group_id]).await.map_err(mapper::pg_err)?;
            }
            WorkflowAction::LeaveGroup { group_id } => {
                conn.execute_params(
                    "DELETE FROM user_groups WHERE user_id=$1 AND group_id=$2",
                    &[&user_id, group_id],
                )
                .await
                .map_err(mapper::pg_err)?;
            }
        }
        Ok(())
    }

    async fn conditions_match(
        conn: &mut Connection,
        workflow: &Workflow,
        user_id: Uuid,
        user: &wasi_pg_client::Row,
    ) -> Result<bool, OidcError> {
        let enabled = mapper::bool_(user, 0)?;
        let verified = mapper::bool_(user, 1)?;
        let attrs = mapper::json_value(user, 2)?;
        for condition in &workflow.conditions {
            let yes = match condition {
                WorkflowCondition::UserEnabled { value } => enabled == *value,
                WorkflowCondition::EmailVerified { value } => verified == *value,
                WorkflowCondition::UserAttributeEquals { name, value } => attrs
                    .get(name)
                    .and_then(|v| v.as_str())
                    .is_some_and(|v| v == value),
                WorkflowCondition::HasRole { role_id } => conn
                    .query_one_params(
                        "SELECT 1 FROM user_roles WHERE user_id=$1 AND role_id=$2",
                        &[&user_id, role_id],
                    )
                    .await
                    .map_err(mapper::pg_err)?
                    .is_some(),
                WorkflowCondition::InGroup { group_id } => conn
                    .query_one_params(
                        "SELECT 1 FROM user_groups WHERE user_id=$1 AND group_id=$2",
                        &[&user_id, group_id],
                    )
                    .await
                    .map_err(mapper::pg_err)?
                    .is_some(),
                WorkflowCondition::InactiveForDays { days } => {
                    let row=conn.query_one_params("SELECT COALESCE(MAX(a.created_at),u.created_at) < NOW() - ($2::bigint * INTERVAL '1 day') FROM users u LEFT JOIN audit_events a ON a.actor_id=u.id AND a.event_type='user.authenticated' WHERE u.id=$1 GROUP BY u.created_at",&[&user_id,days]).await.map_err(mapper::pg_err)?;
                    row.is_some_and(|r| mapper::bool_(&r, 0).unwrap_or(false))
                }
            };
            if !yes {
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn event_user(event: &AuditEvent) -> Option<Uuid> {
        if event
            .target_type
            .as_deref()
            .is_some_and(|v| v.eq_ignore_ascii_case("user"))
        {
            event.target_id
        } else if event.event_type.starts_with("user.") || event.event_type.starts_with("LOGIN_") {
            event.actor_id
        } else {
            None
        }
    }
    fn event_matches(pattern: &str, event: &str) -> bool {
        pattern == "*"
            || pattern == event
            || pattern
                .strip_suffix('*')
                .is_some_and(|prefix| event.starts_with(prefix))
    }
    async fn lifecycle_audit(
        conn: &mut Connection,
        realm: Uuid,
        event: &str,
        execution: Uuid,
        user: Uuid,
        details: serde_json::Value,
    ) -> Result<(), OidcError> {
        let id = generate_uuid_v7();
        conn.execute_params("INSERT INTO audit_events(id,realm_id,event_type,actor_type,target_type,target_id,details,created_at) VALUES($1,$2,$3,'system','user',$4,$5,NOW())",&[&id,&realm,&event,&user,&json!({"execution_id":execution,"details":details})]).await.map_err(mapper::pg_err)?;
        Ok(())
    }
    async fn finish_cancelled(
        &self,
        conn: &mut Connection,
        e: &WorkflowExecution,
        reason: &str,
    ) -> Result<WorkflowExecutionStatus, OidcError> {
        conn.execute_params("UPDATE workflow_executions SET status='cancelled',last_error=$2,completed_at=NOW(),updated_at=NOW() WHERE id=$1",&[&e.id,&reason]).await.map_err(mapper::pg_err)?;
        Ok(WorkflowExecutionStatus::Cancelled)
    }
    async fn find_execution(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<WorkflowExecution>, OidcError> {
        conn.query_one_params("SELECT id,workflow_id,realm_id,user_id,trigger_event,status,current_step,attempts,next_run_at,last_error,started_at,completed_at,created_at,updated_at FROM workflow_executions WHERE id=$1",&[&id]).await.map_err(mapper::pg_err)?.map(|r|Self::map_execution(&r)).transpose()
    }
    fn map_workflow(r: &wasi_pg_client::Row) -> Result<Workflow, OidcError> {
        Ok(Workflow {
            id: mapper::uuid(r, 0)?,
            realm_id: mapper::uuid(r, 1)?,
            name: mapper::string(r, 2)?,
            description: mapper::opt_string(r, 3)?,
            enabled: mapper::bool_(r, 4)?,
            trigger_events: serde_json::from_value(mapper::json_value(r, 5)?)
                .map_err(|e| OidcError::Internal(e.to_string()))?,
            conditions: serde_json::from_value(mapper::json_value(r, 6)?)
                .map_err(|e| OidcError::Internal(e.to_string()))?,
            steps: serde_json::from_value(mapper::json_value(r, 7)?)
                .map_err(|e| OidcError::Internal(e.to_string()))?,
            schedule: serde_json::from_value(mapper::json_value(r, 8)?)
                .map_err(|e| OidcError::Internal(e.to_string()))?,
            last_scheduled_at: mapper::opt_datetime(r, 9)?,
            created_at: mapper::datetime(r, 10)?,
            updated_at: mapper::datetime(r, 11)?,
        })
    }
    fn map_execution(r: &wasi_pg_client::Row) -> Result<WorkflowExecution, OidcError> {
        let status = mapper::string(r, 5)?
            .parse()
            .map_err(|_| OidcError::Internal("invalid workflow execution status".into()))?;
        Ok(WorkflowExecution {
            id: mapper::uuid(r, 0)?,
            workflow_id: mapper::uuid(r, 1)?,
            realm_id: mapper::uuid(r, 2)?,
            user_id: mapper::uuid(r, 3)?,
            trigger_event: mapper::string(r, 4)?,
            status,
            current_step: mapper::i32_(r, 6)?,
            attempts: mapper::i32_(r, 7)?,
            next_run_at: mapper::datetime(r, 8)?,
            last_error: mapper::opt_string(r, 9)?,
            started_at: mapper::opt_datetime(r, 10)?,
            completed_at: mapper::opt_datetime(r, 11)?,
            created_at: mapper::datetime(r, 12)?,
            updated_at: mapper::datetime(r, 13)?,
        })
    }
}
