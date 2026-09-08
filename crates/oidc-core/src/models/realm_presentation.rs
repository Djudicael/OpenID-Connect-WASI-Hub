use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::OidcError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RealmTheme {
    pub login_title: String,
    pub logo_url: String,
    pub favicon_url: String,
    pub primary_color: String,
    pub background_color: String,
    pub card_color: String,
    pub text_color: String,
    pub font_family: String,
    pub footer_text: String,
}

impl Default for RealmTheme {
    fn default() -> Self {
        Self {
            login_title: String::new(),
            logo_url: String::new(),
            favicon_url: String::new(),
            primary_color: "#2563eb".into(),
            background_color: "#f8fafc".into(),
            card_color: "#ffffff".into(),
            text_color: "#111827".into(),
            font_family: "system-ui, sans-serif".into(),
            footer_text: "Powered by OpenID Connect Hub".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RealmLocalization {
    pub default_locale: String,
    pub supported_locales: Vec<String>,
    pub messages: BTreeMap<String, BTreeMap<String, String>>,
}

impl Default for RealmLocalization {
    fn default() -> Self {
        Self {
            default_locale: "en".into(),
            supported_locales: vec!["en".into()],
            messages: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct EmailTemplate {
    pub subject: String,
    pub text: String,
    pub html: String,
}

impl Default for EmailTemplate {
    fn default() -> Self {
        Self {
            subject: String::new(),
            text: String::new(),
            html: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct RealmEmailTemplates {
    /// Locale -> template name -> template.
    pub locales: BTreeMap<String, BTreeMap<String, EmailTemplate>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct RealmPresentation {
    pub theme: RealmTheme,
    pub localization: RealmLocalization,
    pub email_templates: RealmEmailTemplates,
}

impl RealmPresentation {
    fn config_value(config: &serde_json::Value) -> serde_json::Value {
        let mut value = serde_json::Map::new();
        for key in ["theme", "localization", "email_templates"] {
            if let Some(v) = config.get(key) {
                value.insert(key.into(), v.clone());
            }
        }
        value.into()
    }

    pub fn from_realm_config(config: &serde_json::Value) -> Self {
        let mut presentation: Self =
            serde_json::from_value(Self::config_value(config)).unwrap_or_default();
        // Preserve the original theme field name used by older realms.
        if presentation.theme.background_color == RealmTheme::default().background_color {
            if let Some(value) = config.pointer("/theme/bg_color").and_then(|v| v.as_str()) {
                presentation.theme.background_color = value.into();
            }
        }
        presentation
    }

    pub fn validate_realm_config(config: &serde_json::Value) -> Result<(), String> {
        let presentation: Self = serde_json::from_value(Self::config_value(config))
            .map_err(|error| format!("invalid presentation configuration: {error}"))?;
        presentation.validate()
    }

    pub fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("primary_color", &self.theme.primary_color),
            ("background_color", &self.theme.background_color),
            ("card_color", &self.theme.card_color),
            ("text_color", &self.theme.text_color),
        ] {
            if !valid_hex_color(value) {
                return Err(format!("theme {name} must be a six-digit hex color"));
            }
        }
        if self.theme.font_family.len() > 200
            || !self
                .theme
                .font_family
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || " ,_-'\"".contains(c))
            || self.theme.footer_text.len() > 500
        {
            return Err("theme font family or footer text is too long".into());
        }
        for (name, url) in [
            ("logo URL", &self.theme.logo_url),
            ("favicon URL", &self.theme.favicon_url),
        ] {
            if !url.is_empty() && !valid_asset_url(url) {
                return Err(format!("{name} must use HTTPS or a root-relative path"));
            }
        }
        if self.localization.supported_locales.is_empty()
            || self.localization.supported_locales.len() > 50
        {
            return Err("localization needs between 1 and 50 supported locales".into());
        }
        if !self
            .localization
            .supported_locales
            .contains(&self.localization.default_locale)
        {
            return Err("default locale must be included in supported locales".into());
        }
        for locale in &self.localization.supported_locales {
            if !valid_locale(locale) {
                return Err(format!("invalid locale '{locale}'"));
            }
        }
        for (locale, messages) in &self.localization.messages {
            if !self.localization.supported_locales.contains(locale) {
                return Err(format!("translations use unsupported locale '{locale}'"));
            }
            if messages.len() > 200 {
                return Err(format!("locale '{locale}' has too many messages"));
            }
            if messages
                .iter()
                .any(|(k, v)| k.len() > 100 || v.len() > 2_000)
            {
                return Err(format!("locale '{locale}' contains an oversized message"));
            }
        }
        for (locale, templates) in &self.email_templates.locales {
            if !self.localization.supported_locales.contains(locale) {
                return Err(format!("email templates use unsupported locale '{locale}'"));
            }
            for (name, template) in templates {
                let allowed = template_variables(name)
                    .ok_or_else(|| format!("unknown email template '{name}'"))?;
                for value in [&template.subject, &template.text, &template.html] {
                    validate_placeholders(value, allowed)?;
                }
                if template.subject.len() > 300
                    || template.text.len() > 50_000
                    || template.html.len() > 100_000
                {
                    return Err(format!("email template '{name}' is too large"));
                }
            }
        }
        Ok(())
    }

    pub fn resolve_locale(&self, requested: Option<&str>, accept_language: Option<&str>) -> String {
        requested
            .into_iter()
            .flat_map(|v| v.split_whitespace())
            .chain(
                accept_language
                    .into_iter()
                    .flat_map(|v| v.split(',').map(|p| p.split(';').next().unwrap_or(""))),
            )
            .find_map(|candidate| {
                match_locale(candidate.trim(), &self.localization.supported_locales)
            })
            .unwrap_or_else(|| self.localization.default_locale.clone())
    }

    pub fn message(&self, locale: &str, key: &str) -> String {
        self.localization
            .messages
            .get(locale)
            .and_then(|m| m.get(key))
            .or_else(|| {
                self.localization
                    .messages
                    .get(&self.localization.default_locale)
                    .and_then(|m| m.get(key))
            })
            .cloned()
            .unwrap_or_else(|| default_message(key).unwrap_or(key).to_string())
    }

    pub fn render_email(
        &self,
        name: &str,
        locale: &str,
        variables: &[(&str, &str)],
    ) -> Result<crate::traits::EmailMessage, OidcError> {
        let defaults = default_email_template(name)
            .ok_or_else(|| OidcError::InvalidInput(format!("unknown email template '{name}'")))?;
        let custom = self
            .email_templates
            .locales
            .get(locale)
            .and_then(|m| m.get(name))
            .or_else(|| {
                self.email_templates
                    .locales
                    .get(&self.localization.default_locale)
                    .and_then(|m| m.get(name))
            });
        let choose = |field: &str, fallback: &str| -> String {
            custom
                .and_then(|t| match field {
                    "subject" => Some(&t.subject),
                    "text" => Some(&t.text),
                    _ => Some(&t.html),
                })
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_else(|| fallback.into())
        };
        let render = |mut value: String, html: bool| {
            for (key, raw) in variables {
                let replacement = if html {
                    escape_html(raw)
                } else {
                    (*raw).to_string()
                };
                value = value.replace(&format!("{{{{{key}}}}}"), &replacement);
            }
            value
        };
        Ok(crate::traits::EmailMessage {
            subject: render(choose("subject", defaults.subject), false),
            text: render(choose("text", defaults.text), false),
            html: Some(render(choose("html", defaults.html), true)),
        })
    }
}

struct TemplateDefaults {
    subject: &'static str,
    text: &'static str,
    html: &'static str,
}
fn default_email_template(name: &str) -> Option<TemplateDefaults> {
    match name {
        "password_reset" => Some(TemplateDefaults {
            subject: "Reset your password",
            text: "Hello {{user_name}},\n\nUse this link to reset your password:\n{{action_url}}\n\nThis link expires in {{expires_in}}.",
            html: "<p>Hello {{user_name}},</p><p><a href=\"{{action_url}}\">Reset your password</a></p><p>This link expires in {{expires_in}}.</p>",
        }),
        "email_verification" => Some(TemplateDefaults {
            subject: "Verify your email address",
            text: "Hello {{user_name}},\n\nVerify your email address:\n{{action_url}}\n\nThis link expires in {{expires_in}}.",
            html: "<p>Hello {{user_name}},</p><p><a href=\"{{action_url}}\">Verify your email address</a></p><p>This link expires in {{expires_in}}.</p>",
        }),
        "organization_invitation" => Some(TemplateDefaults {
            subject: "Invitation to join {{organization_name}}",
            text: "You have been invited to join {{organization_name}}.\n\nAccept the invitation:\n{{action_url}}\n\nThis link expires in {{expires_in}}.",
            html: "<p>You have been invited to join <strong>{{organization_name}}</strong>.</p><p><a href=\"{{action_url}}\">Accept invitation</a></p><p>This link expires in {{expires_in}}.</p>",
        }),
        _ => None,
    }
}

fn template_variables(name: &str) -> Option<&'static [&'static str]> {
    match name {
        "password_reset" | "email_verification" => {
            Some(&["realm_name", "user_name", "action_url", "expires_in"])
        }
        "organization_invitation" => Some(&[
            "realm_name",
            "organization_name",
            "action_url",
            "expires_in",
        ]),
        _ => None,
    }
}

fn validate_placeholders(value: &str, allowed: &[&str]) -> Result<(), String> {
    let mut rest = value;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let end = after
            .find("}}")
            .ok_or_else(|| "email template has an unclosed placeholder".to_string())?;
        let key = after[..end].trim();
        if !allowed.contains(&key) {
            return Err(format!(
                "email template uses unknown placeholder '{{{{{key}}}}}'"
            ));
        }
        rest = &after[end + 2..];
    }
    Ok(())
}

fn valid_hex_color(value: &str) -> bool {
    value.len() == 7 && value.starts_with('#') && value[1..].chars().all(|c| c.is_ascii_hexdigit())
}
fn valid_locale(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 35
        && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}
fn valid_asset_url(value: &str) -> bool {
    value.starts_with('/') || url::Url::parse(value).is_ok_and(|u| u.scheme() == "https")
}
fn match_locale(candidate: &str, supported: &[String]) -> Option<String> {
    supported
        .iter()
        .find(|v| v.eq_ignore_ascii_case(candidate))
        .cloned()
        .or_else(|| {
            let language = candidate.split('-').next()?;
            supported
                .iter()
                .find(|v| {
                    v.split('-')
                        .next()
                        .is_some_and(|p| p.eq_ignore_ascii_case(language))
                })
                .cloned()
        })
}
fn default_message(key: &str) -> Option<&'static str> {
    match key {
        "page_title" => Some("Sign in"),
        "subtitle" => Some("Sign in to continue"),
        "email" => Some("Email"),
        "email_placeholder" => Some("you@example.com"),
        "password" => Some("Password"),
        "sign_in" => Some("Sign in"),
        "signing_in" => Some("Signing in…"),
        "login_failed" => Some("Sign-in failed"),
        "toggle_password" => Some("Show or hide password"),
        _ => None,
    }
}
pub fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolves_requested_language_and_falls_back() {
        let p = RealmPresentation {
            localization: RealmLocalization {
                default_locale: "en".into(),
                supported_locales: vec!["en".into(), "fr".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(p.resolve_locale(Some("de fr-FR"), None), "fr");
        assert_eq!(p.resolve_locale(Some("de"), None), "en");
    }
    #[test]
    fn validates_template_placeholders() {
        let mut p = RealmPresentation::default();
        p.email_templates
            .locales
            .entry("en".into())
            .or_default()
            .insert(
                "password_reset".into(),
                EmailTemplate {
                    subject: "Hi {{secret}}".into(),
                    ..Default::default()
                },
            );
        assert!(p.validate().unwrap_err().contains("unknown placeholder"));
    }
    #[test]
    fn escapes_html_template_values() {
        let p = RealmPresentation::default();
        let m = p
            .render_email(
                "password_reset",
                "en",
                &[
                    ("user_name", "<Admin>"),
                    ("action_url", "https://example.test/?a=1&b=2"),
                    ("expires_in", "15 minutes"),
                    ("realm_name", "Realm"),
                ],
            )
            .unwrap();
        assert!(m.html.unwrap().contains("&lt;Admin&gt;"));
    }
}
