use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::OidcError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkflowCondition {
    UserEnabled { value: bool },
    EmailVerified { value: bool },
    UserAttributeEquals { name: String, value: String },
    InactiveForDays { days: i64 },
    HasRole { role_id: Uuid },
    InGroup { group_id: Uuid },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkflowAction {
    DisableUser,
    EnableUser,
    DeleteUser,
    AddRequiredAction { action: super::RequiredActionKind },
    RemoveRequiredAction { action: super::RequiredActionKind },
    RevokeSessions,
    SetUserAttribute { name: String, value: String },
    RemoveUserAttribute { name: String },
    GrantRole { role_id: Uuid },
    RevokeRole { role_id: Uuid },
    JoinGroup { group_id: Uuid },
    LeaveGroup { group_id: Uuid },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowStep {
    pub action: WorkflowAction,
    #[serde(default)]
    pub after_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowSchedule {
    pub every_seconds: i64,
    #[serde(default = "default_batch_size")]
    pub batch_size: i64,
}

fn default_batch_size() -> i64 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub id: Uuid,
    pub realm_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    #[serde(default)]
    pub trigger_events: Vec<String>,
    #[serde(default)]
    pub conditions: Vec<WorkflowCondition>,
    pub steps: Vec<WorkflowStep>,
    pub schedule: Option<WorkflowSchedule>,
    pub last_scheduled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Workflow {
    pub fn validate(&self) -> Result<(), OidcError> {
        if self.name.trim().is_empty() || self.name.chars().count() > 120 {
            return Err(OidcError::InvalidInput(
                "workflow name must contain 1 to 120 characters".into(),
            ));
        }
        if self.steps.is_empty() || self.steps.len() > 50 {
            return Err(OidcError::InvalidInput(
                "a workflow must contain 1 to 50 steps".into(),
            ));
        }
        if self.trigger_events.len() > 50
            || self.trigger_events.iter().any(|v| {
                v.is_empty()
                    || v.len() > 100
                    || !v
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '*'))
            })
        {
            return Err(OidcError::InvalidInput(
                "event names must be valid and no longer than 100 characters".into(),
            ));
        }
        if let Some(schedule) = &self.schedule {
            if !(60..=31_536_000).contains(&schedule.every_seconds) {
                return Err(OidcError::InvalidInput(
                    "schedule interval must be between 60 seconds and one year".into(),
                ));
            }
            if !(1..=1000).contains(&schedule.batch_size) {
                return Err(OidcError::InvalidInput(
                    "schedule batch size must be between 1 and 1000".into(),
                ));
            }
        }
        for (index, step) in self.steps.iter().enumerate() {
            if !(0..=31_536_000).contains(&step.after_seconds) {
                return Err(OidcError::InvalidInput(
                    "step delay must be between zero and one year".into(),
                ));
            }
            match &step.action {
                WorkflowAction::DeleteUser if index + 1 != self.steps.len() => {
                    return Err(OidcError::InvalidInput(
                        "delete user must be the final workflow action".into(),
                    ));
                }
                WorkflowAction::SetUserAttribute { name, .. }
                | WorkflowAction::RemoveUserAttribute { name }
                    if name.trim().is_empty() || name.len() > 120 =>
                {
                    return Err(OidcError::InvalidInput(
                        "attribute names must contain 1 to 120 characters".into(),
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowExecutionStatus {
    Queued,
    Waiting,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl WorkflowExecutionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Waiting => "waiting",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

impl std::str::FromStr for WorkflowExecutionStatus {
    type Err = ();
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "queued" => Ok(Self::Queued),
            "waiting" => Ok(Self::Waiting),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowExecution {
    pub id: Uuid,
    pub workflow_id: Uuid,
    pub realm_id: Uuid,
    pub user_id: Uuid,
    pub trigger_event: String,
    pub status: WorkflowExecutionStatus,
    pub current_step: i32,
    pub attempts: i32,
    pub next_run_at: DateTime<Utc>,
    pub last_error: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_workflow_limits() {
        let now = Utc::now();
        let value = Workflow {
            id: Uuid::nil(),
            realm_id: Uuid::nil(),
            name: "Inactive users".into(),
            description: None,
            enabled: true,
            trigger_events: vec!["user.authenticated".into()],
            conditions: vec![],
            steps: vec![WorkflowStep {
                action: WorkflowAction::DisableUser,
                after_seconds: 0,
            }],
            schedule: Some(WorkflowSchedule {
                every_seconds: 86400,
                batch_size: 100,
            }),
            last_scheduled_at: None,
            created_at: now,
            updated_at: now,
        };
        assert!(value.validate().is_ok());
    }
}
