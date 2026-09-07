use serde::{Deserialize, Serialize};

/// Realm policy for refresh tokens granted with the `offline_access` scope.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct OfflineSessionPolicy {
    #[serde(default = "default_idle_seconds")]
    pub idle_seconds: i64,
    #[serde(default = "default_max_seconds")]
    pub max_seconds: i64,
}

const fn default_idle_seconds() -> i64 {
    30 * 24 * 60 * 60
}

const fn default_max_seconds() -> i64 {
    90 * 24 * 60 * 60
}

impl Default for OfflineSessionPolicy {
    fn default() -> Self {
        Self {
            idle_seconds: default_idle_seconds(),
            max_seconds: default_max_seconds(),
        }
    }
}

impl OfflineSessionPolicy {
    pub fn from_realm_config(config: &serde_json::Value) -> Self {
        config
            .get("offline_sessions")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
            .unwrap_or_default()
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.idle_seconds <= 0 {
            return Err("Offline session idle timeout must be greater than zero".into());
        }
        if self.max_seconds <= 0 {
            return Err("Offline session maximum lifetime must be greater than zero".into());
        }
        if self.idle_seconds > self.max_seconds {
            return Err("Offline session idle timeout cannot exceed its maximum lifetime".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_thirty_day_idle_and_ninety_day_maximum() {
        let policy = OfflineSessionPolicy::default();
        assert_eq!(policy.idle_seconds, 2_592_000);
        assert_eq!(policy.max_seconds, 7_776_000);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn rejects_idle_timeout_longer_than_maximum() {
        let policy = OfflineSessionPolicy {
            idle_seconds: 20,
            max_seconds: 10,
        };
        assert!(policy.validate().is_err());
    }
}
