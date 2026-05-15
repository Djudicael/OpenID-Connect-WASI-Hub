//! Input validation utilities.
//!
//! Reusable, pure-Rust validation functions for user-supplied data.
//! All functions return `bool` so callers can decide how to surface errors
//! (e.g. generic messages to avoid enumeration).

/// Returns `true` when `email` matches a basic but practical email pattern.
///
/// Pattern: `^[^@\s]+@[^@\s]+\.[^@\s]+$`
///
/// This deliberately does **not** attempt full RFC 5322 compliance — that
/// almost always leads to false positives or ReDoS.  The check ensures:
/// - exactly one `@`,
/// - non-empty local part (no whitespace),
/// - non-empty domain with at least one dot and a TLD.
pub fn is_valid_email(email: &str) -> bool {
    // Quick pre-checks before regex
    if email.is_empty() || email.len() > 320 {
        return false;
    }
    // Must contain exactly one '@'
    let at_count = email.matches('@').count();
    if at_count != 1 {
        return false;
    }
    let parts: Vec<&str> = email.splitn(2, '@').collect();
    let local = parts[0];
    let domain = parts[1];

    // Local part: non-empty, no whitespace
    if local.is_empty() || local.contains(char::is_whitespace) {
        return false;
    }

    // Domain part: non-empty, no whitespace, must contain at least one dot,
    // and the TLD (last segment) must be at least 2 chars.
    if domain.is_empty() || domain.contains(char::is_whitespace) {
        return false;
    }
    if !domain.contains('.') {
        return false;
    }
    // TLD must be at least 2 characters
    let tld = domain.rsplit('.').next().unwrap_or("");
    if tld.len() < 2 {
        return false;
    }

    true
}

/// Returns `true` when `password` satisfies minimum strength requirements:
///
/// - at least 8 characters,
/// - at least one uppercase letter (`A-Z`),
/// - at least one lowercase letter (`a-z`),
/// - at least one digit (`0-9`).
pub fn is_strong_password(password: &str) -> bool {
    if password.len() < 8 {
        return false;
    }
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    for ch in password.chars() {
        if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_lowercase() {
            has_lower = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        }
    }
    has_upper && has_lower && has_digit
}

/// Returns `true` when `username` is an acceptable display name:
///
/// - 2–100 characters,
/// - only alphanumeric ASCII, spaces, and hyphens,
/// - must not start or end with a space or hyphen.
pub fn is_valid_username(username: &str) -> bool {
    let len = username.len();
    if len < 2 || len > 100 {
        return false;
    }
    // Must not start or end with space or hyphen
    let first = username.chars().next().unwrap();
    let last = username.chars().last().unwrap();
    if first == ' ' || first == '-' || last == ' ' || last == '-' {
        return false;
    }
    // All characters must be alphanumeric, space, or hyphen
    username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '-')
}

/// Validate a password against a password policy.
/// Returns a list of violated rule names, or empty if all rules pass.
pub fn validate_password_against_policy(
    password: &str,
    policy: &crate::models::PasswordPolicy,
) -> Result<(), crate::models::PasswordPolicyViolation> {
    policy.validate_password(password)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- is_valid_email ----

    #[test]
    fn email_valid_simple() {
        assert!(is_valid_email("user@example.com"));
    }

    #[test]
    fn email_valid_subdomain() {
        assert!(is_valid_email("user@mail.example.co.uk"));
    }

    #[test]
    fn email_valid_plus_tag() {
        assert!(is_valid_email("user+tag@example.com"));
    }

    #[test]
    fn email_valid_dots_local() {
        assert!(is_valid_email("first.last@example.com"));
    }

    #[test]
    fn email_empty() {
        assert!(!is_valid_email(""));
    }

    #[test]
    fn email_no_at() {
        assert!(!is_valid_email("userexample.com"));
    }

    #[test]
    fn email_double_at() {
        assert!(!is_valid_email("user@@example.com"));
    }

    #[test]
    fn email_space_in_local() {
        assert!(!is_valid_email("user @example.com"));
    }

    #[test]
    fn email_space_in_domain() {
        assert!(!is_valid_email("user@exa mple.com"));
    }

    #[test]
    fn email_no_domain_tld() {
        assert!(!is_valid_email("user@example"));
    }

    #[test]
    fn email_tld_too_short() {
        assert!(!is_valid_email("user@example.c"));
    }

    #[test]
    fn email_empty_local() {
        assert!(!is_valid_email("@example.com"));
    }

    #[test]
    fn email_empty_domain() {
        assert!(!is_valid_email("user@"));
    }

    #[test]
    fn email_no_dot_in_domain() {
        assert!(!is_valid_email("user@examplecom"));
    }

    #[test]
    fn email_very_long() {
        let local = "a".repeat(310);
        let email = format!("{local}@example.com");
        assert!(!is_valid_email(&email));
    }

    // ---- is_strong_password ----

    #[test]
    fn password_strong() {
        assert!(is_strong_password("Abcdefg1"));
    }

    #[test]
    fn password_strong_with_special() {
        assert!(is_strong_password("Abcdefg1!@#"));
    }

    #[test]
    fn password_too_short() {
        assert!(!is_strong_password("Ab1"));
    }

    #[test]
    fn password_no_uppercase() {
        assert!(!is_strong_password("abcdefg1"));
    }

    #[test]
    fn password_no_lowercase() {
        assert!(!is_strong_password("ABCDEFG1"));
    }

    #[test]
    fn password_no_digit() {
        assert!(!is_strong_password("Abcdefgh"));
    }

    #[test]
    fn password_exactly_8_meets_all() {
        assert!(is_strong_password("Abcdefg1"));
    }

    #[test]
    fn password_exactly_7_fails() {
        assert!(!is_strong_password("Abcdef1"));
    }

    #[test]
    fn password_empty() {
        assert!(!is_strong_password(""));
    }

    // ---- is_valid_username ----

    #[test]
    fn username_valid_simple() {
        assert!(is_valid_username("alice"));
    }

    #[test]
    fn username_valid_with_hyphen() {
        assert!(is_valid_username("alice-smith"));
    }

    #[test]
    fn username_valid_with_space() {
        assert!(is_valid_username("Alice Smith"));
    }

    #[test]
    fn username_valid_alphanumeric() {
        assert!(is_valid_username("user123"));
    }

    #[test]
    fn username_valid_mixed() {
        assert!(is_valid_username("Alice Smith-Jones123"));
    }

    #[test]
    fn username_too_short() {
        assert!(!is_valid_username("a"));
    }

    #[test]
    fn username_exactly_2() {
        assert!(is_valid_username("ab"));
    }

    #[test]
    fn username_too_long() {
        let name = "a".repeat(101);
        assert!(!is_valid_username(&name));
    }

    #[test]
    fn username_exactly_100() {
        let name = "a".repeat(100);
        assert!(is_valid_username(&name));
    }

    #[test]
    fn username_starts_with_space() {
        assert!(!is_valid_username(" alice"));
    }

    #[test]
    fn username_ends_with_space() {
        assert!(!is_valid_username("alice "));
    }

    #[test]
    fn username_starts_with_hyphen() {
        assert!(!is_valid_username("-alice"));
    }

    #[test]
    fn username_ends_with_hyphen() {
        assert!(!is_valid_username("alice-"));
    }

    #[test]
    fn username_special_chars() {
        assert!(!is_valid_username("alice@smith"));
    }

    #[test]
    fn username_underscore() {
        assert!(!is_valid_username("alice_smith"));
    }

    #[test]
    fn username_empty() {
        assert!(!is_valid_username(""));
    }

    #[test]
    fn username_double_space_inside() {
        // Double spaces are allowed — the rule is alphanumeric + spaces + hyphens
        assert!(is_valid_username("Alice  Smith"));
    }
}
