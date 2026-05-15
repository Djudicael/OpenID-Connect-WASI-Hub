//! Per-realm password policy model and validation.
//!
//! Password policies are stored as JSON within the realm's `config` field
//! under the `"password_policy"` key. This module provides the model,
//! serialization/deserialization, and validation logic.

use serde::{Deserialize, Serialize};

/// Per-realm password policy configuration.
/// Stored as JSON within the realm's `config` field under the `"password_policy"` key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PasswordPolicy {
    /// Minimum password length. Default: 8
    #[serde(default = "default_min_length")]
    pub min_length: usize,

    /// Maximum password length (to prevent DoS). Default: 128
    #[serde(default = "default_max_length")]
    pub max_length: usize,

    /// Require at least one uppercase letter (A-Z). Default: true
    #[serde(default = "default_true")]
    pub require_uppercase: bool,

    /// Require at least one lowercase letter (a-z). Default: true
    #[serde(default = "default_true")]
    pub require_lowercase: bool,

    /// Require at least one digit (0-9). Default: true
    #[serde(default = "default_true")]
    pub require_digit: bool,

    /// Require at least one special character. Default: false
    #[serde(default)]
    pub require_special: bool,

    /// Minimum number of unique characters. Default: 0 (no constraint)
    #[serde(default)]
    pub min_unique_chars: usize,

    /// Number of previous passwords to check against (password history). Default: 0 (no history check)
    /// Note: history checking is done at the application layer, not in this validator.
    #[serde(default)]
    pub password_history_count: usize,

    /// Maximum consecutive identical characters. Default: 0 (no limit)
    #[serde(default)]
    pub max_identical_consecutive: usize,

    /// Disallowed passwords (common passwords list). Default: empty
    #[serde(default)]
    pub disallowed_passwords: Vec<String>,
}

fn default_min_length() -> usize {
    8
}
fn default_max_length() -> usize {
    128
}
fn default_true() -> bool {
    true
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: default_min_length(),
            max_length: default_max_length(),
            require_uppercase: default_true(),
            require_lowercase: default_true(),
            require_digit: default_true(),
            require_special: false,
            min_unique_chars: 0,
            password_history_count: 0,
            max_identical_consecutive: 0,
            disallowed_passwords: Vec::new(),
        }
    }
}

/// Structured error returned when a password violates one or more policy rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PasswordPolicyViolation {
    /// List of rule names that were violated (e.g., `["min_length", "require_uppercase"]`).
    pub rules: Vec<String>,
}

impl PasswordPolicyViolation {
    /// Create a violation from a list of rule names.
    pub fn new(rules: Vec<String>) -> Self {
        Self { rules }
    }
}

impl std::fmt::Display for PasswordPolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "password violates the following rules: {}",
            self.rules.join(", ")
        )
    }
}

impl std::error::Error for PasswordPolicyViolation {}

impl PasswordPolicy {
    /// Extract a `PasswordPolicy` from a realm's `config` JSON value.
    ///
    /// Looks for the `"password_policy"` key within the config object.
    /// Falls back to `PasswordPolicy::default()` if the key is missing or
    /// cannot be deserialized.
    pub fn from_realm_config(config: &serde_json::Value) -> Self {
        config
            .get("password_policy")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default()
    }

    /// Validate a password against all rules in this policy.
    ///
    /// Returns `Ok(())` if the password satisfies every rule, or
    /// `Err(PasswordPolicyViolation)` with the list of violated rule names.
    pub fn validate_password(&self, password: &str) -> Result<(), PasswordPolicyViolation> {
        let mut violated: Vec<String> = Vec::new();

        // --- Length checks ---
        if password.len() < self.min_length {
            violated.push("min_length".into());
        }
        if password.len() > self.max_length {
            violated.push("max_length".into());
        }

        // --- Character class checks ---
        let mut has_upper = false;
        let mut has_lower = false;
        let mut has_digit = false;
        let mut has_special = false;

        for ch in password.chars() {
            if ch.is_ascii_uppercase() {
                has_upper = true;
            } else if ch.is_ascii_lowercase() {
                has_lower = true;
            } else if ch.is_ascii_digit() {
                has_digit = true;
            } else {
                // Anything that is not uppercase, lowercase, or digit counts as "special".
                has_special = true;
            }
        }

        if self.require_uppercase && !has_upper {
            violated.push("require_uppercase".into());
        }
        if self.require_lowercase && !has_lower {
            violated.push("require_lowercase".into());
        }
        if self.require_digit && !has_digit {
            violated.push("require_digit".into());
        }
        if self.require_special && !has_special {
            violated.push("require_special".into());
        }

        // --- Unique characters ---
        if self.min_unique_chars > 0 {
            let unique_count = password
                .chars()
                .collect::<std::collections::HashSet<_>>()
                .len();
            if unique_count < self.min_unique_chars {
                violated.push("min_unique_chars".into());
            }
        }

        // --- Max consecutive identical characters ---
        if self.max_identical_consecutive > 0 && !password.is_empty() {
            let mut max_run = 1usize;
            let mut current_run = 1usize;
            let mut prev = None;
            for ch in password.chars() {
                if Some(ch) == prev {
                    current_run += 1;
                    if current_run > max_run {
                        max_run = current_run;
                    }
                } else {
                    current_run = 1;
                }
                prev = Some(ch);
            }
            if max_run > self.max_identical_consecutive {
                violated.push("max_identical_consecutive".into());
            }
        }

        // --- Disallowed passwords ---
        if !self.disallowed_passwords.is_empty() {
            let lower_password = password.to_lowercase();
            for disallowed in &self.disallowed_passwords {
                if lower_password == disallowed.to_lowercase() {
                    violated.push("disallowed_password".into());
                    break;
                }
            }
        }

        if violated.is_empty() {
            Ok(())
        } else {
            Err(PasswordPolicyViolation::new(violated))
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Default policy matches is_strong_password behavior ----

    #[test]
    fn default_policy_accepts_strong_password() {
        let policy = PasswordPolicy::default();
        assert!(policy.validate_password("Abcdefg1").is_ok());
    }

    #[test]
    fn default_policy_accepts_strong_with_special() {
        let policy = PasswordPolicy::default();
        assert!(policy.validate_password("Abcdefg1!@#").is_ok());
    }

    #[test]
    fn default_policy_rejects_too_short() {
        let policy = PasswordPolicy::default();
        let result = policy.validate_password("Ab1");
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert!(violation.rules.contains(&"min_length".to_string()));
    }

    #[test]
    fn default_policy_rejects_no_uppercase() {
        let policy = PasswordPolicy::default();
        let result = policy.validate_password("abcdefg1");
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert!(violation.rules.contains(&"require_uppercase".to_string()));
    }

    #[test]
    fn default_policy_rejects_no_lowercase() {
        let policy = PasswordPolicy::default();
        let result = policy.validate_password("ABCDEFG1");
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert!(violation.rules.contains(&"require_lowercase".to_string()));
    }

    #[test]
    fn default_policy_rejects_no_digit() {
        let policy = PasswordPolicy::default();
        let result = policy.validate_password("Abcdefgh");
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert!(violation.rules.contains(&"require_digit".to_string()));
    }

    #[test]
    fn default_policy_exactly_8_chars_passes() {
        let policy = PasswordPolicy::default();
        assert!(policy.validate_password("Abcdefg1").is_ok());
    }

    #[test]
    fn default_policy_exactly_7_chars_fails() {
        let policy = PasswordPolicy::default();
        let result = policy.validate_password("Abcdef1");
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert!(violation.rules.contains(&"min_length".to_string()));
    }

    // ---- Custom min_length ----

    #[test]
    fn custom_min_length_rejects_short() {
        let policy = PasswordPolicy {
            min_length: 12,
            ..Default::default()
        };
        let result = policy.validate_password("Abcdefg1");
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert!(violation.rules.contains(&"min_length".to_string()));
    }

    #[test]
    fn custom_min_length_accepts_long_enough() {
        let policy = PasswordPolicy {
            min_length: 12,
            ..Default::default()
        };
        assert!(policy.validate_password("Abcdefghij12").is_ok());
    }

    // ---- require_special ----

    #[test]
    fn require_special_rejects_without_special() {
        let policy = PasswordPolicy {
            require_special: true,
            ..Default::default()
        };
        let result = policy.validate_password("Abcdefg1");
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert!(violation.rules.contains(&"require_special".to_string()));
    }

    #[test]
    fn require_special_accepts_with_special() {
        let policy = PasswordPolicy {
            require_special: true,
            ..Default::default()
        };
        assert!(policy.validate_password("Abcdefg1!").is_ok());
    }

    // ---- min_unique_chars ----

    #[test]
    fn min_unique_chars_rejects_repetitive() {
        let policy = PasswordPolicy {
            min_unique_chars: 5,
            ..Default::default()
        };
        // "Aa1Aa1Aa1" only has 4 unique chars: A, a, 1
        let result = policy.validate_password("Aa1Aa1Aa");
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert!(violation.rules.contains(&"min_unique_chars".to_string()));
    }

    #[test]
    fn min_unique_chars_accepts_diverse() {
        let policy = PasswordPolicy {
            min_unique_chars: 5,
            ..Default::default()
        };
        assert!(policy.validate_password("Abcde1Fg").is_ok());
    }

    #[test]
    fn min_unique_chars_zero_means_no_constraint() {
        let policy = PasswordPolicy {
            min_unique_chars: 0,
            ..Default::default()
        };
        assert!(policy.validate_password("Aa1Aa1Aa").is_ok());
    }

    // ---- max_identical_consecutive ----

    #[test]
    fn max_identical_consecutive_rejects_repeats() {
        let policy = PasswordPolicy {
            max_identical_consecutive: 2,
            ..Default::default()
        };
        let result = policy.validate_password("AAAbcdef1");
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert!(
            violation
                .rules
                .contains(&"max_identical_consecutive".to_string())
        );
    }

    #[test]
    fn max_identical_consecutive_accepts_no_long_run() {
        let policy = PasswordPolicy {
            max_identical_consecutive: 2,
            ..Default::default()
        };
        assert!(policy.validate_password("AAbcdef1").is_ok());
    }

    #[test]
    fn max_identical_consecutive_zero_means_no_limit() {
        let policy = PasswordPolicy {
            max_identical_consecutive: 0,
            ..Default::default()
        };
        assert!(policy.validate_password("AAAAAAA1a").is_ok());
    }

    #[test]
    fn max_identical_consecutive_exactly_at_limit() {
        let policy = PasswordPolicy {
            max_identical_consecutive: 3,
            ..Default::default()
        };
        // Exactly 3 consecutive 'A's — should pass
        assert!(policy.validate_password("AAAabcdef1").is_ok());
    }

    #[test]
    fn max_identical_consecutive_one_over_limit() {
        let policy = PasswordPolicy {
            max_identical_consecutive: 3,
            ..Default::default()
        };
        // 4 consecutive 'A's — should fail
        let result = policy.validate_password("AAAAabcdef1");
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert!(
            violation
                .rules
                .contains(&"max_identical_consecutive".to_string())
        );
    }

    // ---- disallowed_passwords ----

    #[test]
    fn disallowed_passwords_rejects_common() {
        let policy = PasswordPolicy {
            disallowed_passwords: vec!["password1".into(), "12345678".into()],
            ..Default::default()
        };
        let result = policy.validate_password("Password1");
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert!(violation.rules.contains(&"disallowed_password".to_string()));
    }

    #[test]
    fn disallowed_passwords_case_insensitive() {
        let policy = PasswordPolicy {
            disallowed_passwords: vec!["password1".into()],
            ..Default::default()
        };
        let result = policy.validate_password("Password1");
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert!(violation.rules.contains(&"disallowed_password".to_string()));
    }

    #[test]
    fn disallowed_passwords_accepts_non_matching() {
        let policy = PasswordPolicy {
            disallowed_passwords: vec!["password".into(), "12345678".into()],
            ..Default::default()
        };
        assert!(policy.validate_password("Xylophone9").is_ok());
    }

    #[test]
    fn disallowed_passwords_empty_list_means_no_check() {
        let policy = PasswordPolicy {
            disallowed_passwords: Vec::new(),
            ..Default::default()
        };
        assert!(policy.validate_password("Password1").is_ok());
    }

    // ---- max_length ----

    #[test]
    fn max_length_rejects_too_long() {
        let policy = PasswordPolicy {
            max_length: 16,
            ..Default::default()
        };
        let result = policy.validate_password("Abcdefghijklmnop1");
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert!(violation.rules.contains(&"max_length".to_string()));
    }

    #[test]
    fn max_length_accepts_at_limit() {
        let policy = PasswordPolicy {
            max_length: 16,
            ..Default::default()
        };
        assert!(policy.validate_password("Abcdefghijklmn1").is_ok());
    }

    #[test]
    fn default_max_length_128_rejects_longer() {
        let policy = PasswordPolicy::default();
        // 129 chars: 1 uppercase + 126 lowercase + 1 digit = 128, need 129
        let long_pw = format!("A{}1", "a".repeat(127));
        let result = policy.validate_password(&long_pw);
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert!(violation.rules.contains(&"max_length".to_string()));
    }

    // ---- All rules failing at once ----

    #[test]
    fn all_rules_failing_at_once() {
        let policy = PasswordPolicy {
            min_length: 16,
            max_length: 20,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            min_unique_chars: 8,
            max_identical_consecutive: 2,
            disallowed_passwords: vec!["aa".into()],
            ..Default::default()
        };
        // "aa" fails: min_length, require_uppercase, require_digit, require_special, min_unique_chars
        let result = policy.validate_password("aa");
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert!(violation.rules.contains(&"min_length".to_string()));
        assert!(violation.rules.contains(&"require_uppercase".to_string()));
        assert!(violation.rules.contains(&"require_digit".to_string()));
        assert!(violation.rules.contains(&"require_special".to_string()));
        assert!(violation.rules.contains(&"min_unique_chars".to_string()));
        // It also matches the disallowed list
        assert!(violation.rules.contains(&"disallowed_password".to_string()));
        // Should NOT have max_length or max_identical_consecutive
        assert!(!violation.rules.contains(&"max_length".to_string()));
        assert!(
            !violation
                .rules
                .contains(&"max_identical_consecutive".to_string())
        );
    }

    // ---- Empty password ----

    #[test]
    fn empty_password_fails_min_length() {
        let policy = PasswordPolicy::default();
        let result = policy.validate_password("");
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert!(violation.rules.contains(&"min_length".to_string()));
        assert!(violation.rules.contains(&"require_uppercase".to_string()));
        assert!(violation.rules.contains(&"require_lowercase".to_string()));
        assert!(violation.rules.contains(&"require_digit".to_string()));
    }

    // ---- Exact boundary tests ----

    #[test]
    fn password_exactly_at_min_length() {
        let policy = PasswordPolicy {
            min_length: 8,
            ..Default::default()
        };
        assert!(policy.validate_password("Abcdefg1").is_ok());
    }

    #[test]
    fn password_one_below_min_length() {
        let policy = PasswordPolicy {
            min_length: 8,
            ..Default::default()
        };
        let result = policy.validate_password("Abcdef1");
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert!(violation.rules.contains(&"min_length".to_string()));
    }

    #[test]
    fn password_exactly_at_max_length() {
        let policy = PasswordPolicy {
            max_length: 10,
            ..Default::default()
        };
        // 10 chars: "Abcdefgh1" is 9, need exactly 10
        assert!(policy.validate_password("Abcdefghi1").is_ok());
    }

    #[test]
    fn password_one_above_max_length() {
        let policy = PasswordPolicy {
            max_length: 10,
            ..Default::default()
        };
        let result = policy.validate_password("Abcdefghij1");
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert!(violation.rules.contains(&"max_length".to_string()));
    }

    // ---- from_realm_config ----

    #[test]
    fn from_realm_config_extracts_policy() {
        let config = serde_json::json!({
            "password_policy": {
                "min_length": 12,
                "require_special": true
            }
        });
        let policy = PasswordPolicy::from_realm_config(&config);
        assert_eq!(policy.min_length, 12);
        assert!(policy.require_special);
        // Other fields should use defaults
        assert!(policy.require_uppercase);
        assert!(policy.require_lowercase);
        assert!(policy.require_digit);
    }

    #[test]
    fn from_realm_config_missing_key_returns_default() {
        let config = serde_json::json!({});
        let policy = PasswordPolicy::from_realm_config(&config);
        assert_eq!(policy, PasswordPolicy::default());
    }

    #[test]
    fn from_realm_config_null_returns_default() {
        let config = serde_json::json!({"password_policy": null});
        let policy = PasswordPolicy::from_realm_config(&config);
        assert_eq!(policy, PasswordPolicy::default());
    }

    #[test]
    fn from_realm_config_invalid_type_returns_default() {
        let config = serde_json::json!({"password_policy": "not_an_object"});
        let policy = PasswordPolicy::from_realm_config(&config);
        assert_eq!(policy, PasswordPolicy::default());
    }

    // ---- Serialization roundtrip ----

    #[test]
    fn serde_roundtrip_default() {
        let policy = PasswordPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: PasswordPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, deserialized);
    }

    #[test]
    fn serde_roundtrip_custom() {
        let policy = PasswordPolicy {
            min_length: 16,
            max_length: 64,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            min_unique_chars: 6,
            password_history_count: 3,
            max_identical_consecutive: 3,
            disallowed_passwords: vec!["password".into(), "12345678".into()],
        };
        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: PasswordPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, deserialized);
    }

    #[test]
    fn serde_partial_json_uses_defaults() {
        // Only min_length is provided; other fields should get defaults
        let json = r#"{"min_length": 20}"#;
        let policy: PasswordPolicy = serde_json::from_str(json).unwrap();
        assert_eq!(policy.min_length, 20);
        assert_eq!(policy.max_length, 128);
        assert!(policy.require_uppercase);
        assert!(policy.require_lowercase);
        assert!(policy.require_digit);
        assert!(!policy.require_special);
        assert_eq!(policy.min_unique_chars, 0);
        assert_eq!(policy.max_identical_consecutive, 0);
        assert!(policy.disallowed_passwords.is_empty());
    }

    // ---- PasswordPolicyViolation display ----

    #[test]
    fn violation_display_format() {
        let violation =
            PasswordPolicyViolation::new(vec!["min_length".into(), "require_uppercase".into()]);
        let msg = format!("{}", violation);
        assert!(msg.contains("min_length"));
        assert!(msg.contains("require_uppercase"));
    }

    // ---- password_history_count is informational only ----

    #[test]
    fn password_history_count_does_not_affect_validation() {
        let policy = PasswordPolicy {
            password_history_count: 5,
            ..Default::default()
        };
        // Validation should pass — history check is done at the application layer
        assert!(policy.validate_password("Abcdefg1").is_ok());
    }
}
