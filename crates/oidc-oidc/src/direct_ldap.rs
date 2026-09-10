use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use bytes::BytesMut;
use lber::common::TagClass;
use lber::parse::{parse_tag, parse_uint};
use lber::structure::{PL, StructureTag};
use lber::structures::{ASNTag, Boolean, Enumerated, Integer, OctetString, Sequence, Tag};
use lber::universal::Types;
use oidc_core::OidcError;
use oidc_core::models::{DirectoryUser, UserFederationProvider, UserFederationType};
use serde::Deserialize;
use serde_json::{Map, Value};
use wasi_pg_client::transport::tls::TlsTransport;
use wasi_pg_client::transport::{AsyncTransport, ClientTransport};

use crate::state::OidcState;

const MAX_LDAP_MESSAGE: usize = 4 * 1024 * 1024;
const DEFAULT_TIMEOUT_SECONDS: u64 = 10;
const DEFAULT_RESULT_LIMIT: usize = 1_000;
const PAGED_RESULTS_OID: &[u8] = b"1.2.840.113556.1.4.319";

#[derive(Debug, Deserialize)]
#[serde(default)]
struct DirectLdapConfig {
    base_dn: String,
    bind_dn: String,
    user_filter: String,
    sync_filter: String,
    id_attribute: String,
    username_attribute: String,
    email_attribute: String,
    given_name_attribute: String,
    family_name_attribute: String,
    display_name_attribute: String,
    group_attribute: String,
    enabled_attribute: String,
    custom_attributes: Vec<String>,
    timeout_seconds: u64,
    result_limit: usize,
    page_size: usize,
    ca_certificate_pem: Option<String>,
}

impl Default for DirectLdapConfig {
    fn default() -> Self {
        Self {
            base_dn: String::new(),
            bind_dn: String::new(),
            user_filter: "(uid={identifier})".into(),
            sync_filter: "(objectClass=person)".into(),
            id_attribute: "entryUUID".into(),
            username_attribute: "uid".into(),
            email_attribute: "mail".into(),
            given_name_attribute: "givenName".into(),
            family_name_attribute: "sn".into(),
            display_name_attribute: "displayName".into(),
            group_attribute: "memberOf".into(),
            enabled_attribute: String::new(),
            custom_attributes: Vec::new(),
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            result_limit: DEFAULT_RESULT_LIMIT,
            page_size: 500,
            ca_certificate_pem: None,
        }
    }
}

impl DirectLdapConfig {
    fn from_provider(provider: &UserFederationProvider) -> Result<Self, OidcError> {
        let mut value: Self = serde_json::from_value(provider.config.clone()).map_err(|error| {
            OidcError::InvalidInput(format!("invalid directory configuration: {error}"))
        })?;
        if value.base_dn.trim().is_empty() {
            return Err(OidcError::InvalidInput(
                "base_dn is required for direct LDAP".into(),
            ));
        }
        if !(1..=120).contains(&value.timeout_seconds) {
            return Err(OidcError::InvalidInput(
                "timeout_seconds must be between 1 and 120".into(),
            ));
        }
        if !(1..=10_000).contains(&value.result_limit) {
            return Err(OidcError::InvalidInput(
                "result_limit must be between 1 and 10000".into(),
            ));
        }
        if !(1..=1_000).contains(&value.page_size) {
            return Err(OidcError::InvalidInput(
                "page_size must be between 1 and 1000".into(),
            ));
        }
        if provider.provider_type == UserFederationType::ActiveDirectory {
            if value.user_filter == "(uid={identifier})" {
                value.user_filter =
                    "(|(userPrincipalName={identifier})(sAMAccountName={identifier}))".into();
            }
            if value.id_attribute == "entryUUID" {
                value.id_attribute = "objectGUID".into();
            }
            if value.username_attribute == "uid" {
                value.username_attribute = "sAMAccountName".into();
            }
            if value.enabled_attribute.is_empty() {
                value.enabled_attribute = "userAccountControl".into();
            }
        }
        Ok(value)
    }

    fn requested_attributes(&self) -> Vec<String> {
        let mut attributes = vec![
            self.id_attribute.clone(),
            self.username_attribute.clone(),
            self.email_attribute.clone(),
            self.given_name_attribute.clone(),
            self.family_name_attribute.clone(),
            self.display_name_attribute.clone(),
            self.group_attribute.clone(),
        ];
        if !self.enabled_attribute.is_empty() {
            attributes.push(self.enabled_attribute.clone());
        }
        attributes.extend(self.custom_attributes.iter().cloned());
        attributes.retain(|value| !value.trim().is_empty());
        attributes.sort_by_key(|value| value.to_ascii_lowercase());
        attributes.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
        attributes
    }
}

#[derive(Debug)]
struct LdapEntry {
    dn: String,
    attributes: HashMap<String, Vec<Vec<u8>>>,
}

impl LdapEntry {
    fn values(&self, name: &str) -> &[Vec<u8>] {
        self.attributes
            .get(&name.to_ascii_lowercase())
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn text(&self, name: &str) -> Option<String> {
        self.values(name)
            .first()
            .and_then(|value| String::from_utf8(value.clone()).ok())
            .filter(|value| !value.trim().is_empty())
    }
}

enum LdapTransport {
    Plain(ClientTransport),
    Tls(Box<TlsTransport<ClientTransport>>),
}

impl AsyncTransport for LdapTransport {
    async fn read(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<usize, wasi_pg_client::transport::TransportError> {
        match self {
            Self::Plain(inner) => inner.read(buffer).await,
            Self::Tls(inner) => inner.read(buffer).await,
        }
    }

    async fn write(
        &mut self,
        buffer: &[u8],
    ) -> Result<usize, wasi_pg_client::transport::TransportError> {
        match self {
            Self::Plain(inner) => inner.write(buffer).await,
            Self::Tls(inner) => inner.write(buffer).await,
        }
    }

    async fn write_all(
        &mut self,
        buffer: &[u8],
    ) -> Result<(), wasi_pg_client::transport::TransportError> {
        match self {
            Self::Plain(inner) => inner.write_all(buffer).await,
            Self::Tls(inner) => inner.write_all(buffer).await,
        }
    }

    async fn read_exact(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<(), wasi_pg_client::transport::TransportError> {
        match self {
            Self::Plain(inner) => inner.read_exact(buffer).await,
            Self::Tls(inner) => inner.read_exact(buffer).await,
        }
    }

    async fn flush(&mut self) -> Result<(), wasi_pg_client::transport::TransportError> {
        match self {
            Self::Plain(inner) => inner.flush().await,
            Self::Tls(inner) => inner.flush().await,
        }
    }

    async fn shutdown(&mut self) -> Result<(), wasi_pg_client::transport::TransportError> {
        match self {
            Self::Plain(inner) => inner.shutdown().await,
            Self::Tls(inner) => inner.shutdown().await,
        }
    }
}

struct LdapConnection {
    transport: Option<LdapTransport>,
    incoming: Vec<u8>,
    next_message_id: i32,
    timeout: Duration,
}

impl LdapConnection {
    async fn connect(
        provider: &UserFederationProvider,
        config: &DirectLdapConfig,
    ) -> Result<Self, OidcError> {
        let url = url::Url::parse(&provider.gateway_url)
            .map_err(|_| OidcError::InvalidInput("directory URL is invalid".into()))?;
        let host = url
            .host_str()
            .ok_or_else(|| OidcError::InvalidInput("directory URL needs a host".into()))?;
        let scheme = url.scheme();
        let port = url
            .port()
            .unwrap_or(if scheme == "ldaps" { 636 } else { 389 });
        let timeout = Duration::from_secs(config.timeout_seconds);
        let plain = connect_transport(host, port, timeout).await?;
        if scheme == "ldaps" {
            return Ok(Self {
                transport: Some(LdapTransport::Tls(Box::new(
                    tls_transport(plain, host, config).await?,
                ))),
                incoming: Vec::new(),
                next_message_id: 1,
                timeout,
            });
        }
        let mut connection = Self {
            transport: Some(LdapTransport::Plain(plain)),
            incoming: Vec::new(),
            next_message_id: 1,
            timeout,
        };
        match scheme {
            "ldap" => Ok(connection),
            "ldap+starttls" => {
                connection.start_tls(host, config).await?;
                Ok(connection)
            }
            _ => Err(OidcError::InvalidInput(
                "direct directory URL must use ldap://, ldap+starttls://, or ldaps://".into(),
            )),
        }
    }

    fn message_id(&mut self) -> i32 {
        let id = self.next_message_id;
        self.next_message_id = self.next_message_id.saturating_add(1).max(1);
        id
    }

    fn transport_mut(&mut self) -> Result<&mut LdapTransport, OidcError> {
        self.transport
            .as_mut()
            .ok_or_else(|| OidcError::Internal("LDAP transport is unavailable".into()))
    }

    async fn request(&mut self, operation: Tag) -> Result<(i32, StructureTag), OidcError> {
        let id = self.message_id();
        let message = Tag::Sequence(Sequence {
            inner: vec![
                Tag::Integer(Integer {
                    inner: id as i64,
                    ..Default::default()
                }),
                operation,
            ],
            ..Default::default()
        });
        let mut encoded = BytesMut::new();
        lber::write::encode_into(&mut encoded, message.into_structure())
            .map_err(|error| OidcError::Internal(format!("LDAP encoding failed: {error}")))?;
        self.transport_mut()?
            .write_all(&encoded)
            .await
            .map_err(transport_error)?;
        self.transport_mut()?
            .flush()
            .await
            .map_err(transport_error)?;
        let (response_id, response, _) = self.read_message().await?;
        if response_id != id {
            return Err(OidcError::Internal(
                "LDAP returned an unexpected message ID".into(),
            ));
        }
        Ok((id, response))
    }

    async fn bind(&mut self, dn: &str, password: &str) -> Result<bool, OidcError> {
        let (_, response) = self
            .request(Tag::Sequence(Sequence {
                class: TagClass::Application,
                id: 0,
                inner: vec![
                    Tag::Integer(Integer {
                        inner: 3,
                        ..Default::default()
                    }),
                    octet(dn.as_bytes()),
                    Tag::OctetString(OctetString {
                        class: TagClass::Context,
                        id: 0,
                        inner: password.as_bytes().to_vec(),
                    }),
                ],
            }))
            .await?;
        if response.class != TagClass::Application || response.id != 1 {
            return Err(OidcError::Internal(
                "LDAP bind returned an invalid response".into(),
            ));
        }
        match ldap_result_code(&response)? {
            0 => Ok(true),
            49 => Ok(false),
            code => Err(OidcError::Internal(format!(
                "LDAP bind failed with result code {code}"
            ))),
        }
    }

    async fn start_tls(&mut self, host: &str, config: &DirectLdapConfig) -> Result<(), OidcError> {
        let (_, response) = self
            .request(Tag::Sequence(Sequence {
                class: TagClass::Application,
                id: 23,
                inner: vec![Tag::OctetString(OctetString {
                    class: TagClass::Context,
                    id: 0,
                    inner: b"1.3.6.1.4.1.1466.20037".to_vec(),
                })],
            }))
            .await?;
        if response.class != TagClass::Application
            || response.id != 24
            || ldap_result_code(&response)? != 0
        {
            return Err(OidcError::Internal(
                "LDAP StartTLS upgrade was rejected".into(),
            ));
        }
        if !self.incoming.is_empty() {
            return Err(OidcError::Internal(
                "LDAP sent unexpected bytes before TLS negotiation".into(),
            ));
        }
        let plain = match self
            .transport
            .take()
            .ok_or_else(|| OidcError::Internal("LDAP transport is unavailable".into()))?
        {
            LdapTransport::Plain(value) => value,
            LdapTransport::Tls(_) => {
                return Err(OidcError::Internal(
                    "LDAP connection is already encrypted".into(),
                ));
            }
        };
        self.transport = Some(LdapTransport::Tls(Box::new(
            tls_transport(plain, host, config).await?,
        )));
        Ok(())
    }

    async fn search(
        &mut self,
        base: &str,
        filter: Tag,
        attributes: &[String],
        size_limit: usize,
        page_cookie: Option<&[u8]>,
    ) -> Result<(Vec<LdapEntry>, Vec<u8>), OidcError> {
        let id = self.message_id();
        let operation = Tag::Sequence(Sequence {
            class: TagClass::Application,
            id: 3,
            inner: vec![
                octet(base.as_bytes()),
                Tag::Enumerated(Enumerated {
                    inner: 2,
                    ..Default::default()
                }),
                Tag::Enumerated(Enumerated {
                    inner: 0,
                    ..Default::default()
                }),
                Tag::Integer(Integer {
                    inner: size_limit as i64,
                    ..Default::default()
                }),
                Tag::Integer(Integer {
                    inner: self.timeout.as_secs() as i64,
                    ..Default::default()
                }),
                Tag::Boolean(Boolean {
                    inner: false,
                    ..Default::default()
                }),
                filter,
                Tag::Sequence(Sequence {
                    inner: attributes
                        .iter()
                        .map(|value| octet(value.as_bytes()))
                        .collect(),
                    ..Default::default()
                }),
            ],
        });
        let mut message_values = vec![
            Tag::Integer(Integer {
                inner: id as i64,
                ..Default::default()
            }),
            operation,
        ];
        if let Some(cookie) = page_cookie {
            message_values.push(paged_results_control(size_limit, cookie)?);
        }
        let message = Tag::Sequence(Sequence {
            inner: message_values,
            ..Default::default()
        });
        let mut encoded = BytesMut::new();
        lber::write::encode_into(&mut encoded, message.into_structure())
            .map_err(|error| OidcError::Internal(format!("LDAP encoding failed: {error}")))?;
        self.transport_mut()?
            .write_all(&encoded)
            .await
            .map_err(transport_error)?;
        self.transport_mut()?
            .flush()
            .await
            .map_err(transport_error)?;

        let mut entries = Vec::new();
        loop {
            let (response_id, operation, controls) = self.read_message().await?;
            if response_id != id {
                return Err(OidcError::Internal(
                    "LDAP returned an unexpected message ID".into(),
                ));
            }
            match (operation.class, operation.id) {
                (TagClass::Application, 4) => {
                    if entries.len() >= size_limit {
                        return Err(OidcError::Internal("LDAP result limit exceeded".into()));
                    }
                    entries.push(parse_search_entry(operation)?);
                }
                (TagClass::Application, 5) => {
                    let code = ldap_result_code(&operation)?;
                    if code == 0 {
                        return Ok((entries, paged_results_cookie(controls)?));
                    }
                    if code == 4 && page_cookie.is_none() {
                        return Ok((entries, Vec::new()));
                    }
                    return Err(OidcError::Internal(format!(
                        "LDAP search failed with result code {code}"
                    )));
                }
                (TagClass::Application, 19) => {}
                _ => {
                    return Err(OidcError::Internal(
                        "LDAP search returned an invalid response".into(),
                    ));
                }
            }
        }
    }

    async fn read_message(&mut self) -> Result<(i32, StructureTag, Vec<StructureTag>), OidcError> {
        loop {
            match parse_tag(&self.incoming) {
                Ok((remaining, tag)) => {
                    let consumed = self.incoming.len() - remaining.len();
                    self.incoming.drain(..consumed);
                    return parse_ldap_message(tag);
                }
                Err(lber::Err::Incomplete(_)) => {}
                Err(_) => return Err(OidcError::Internal("LDAP returned malformed BER".into())),
            }
            if self.incoming.len() >= MAX_LDAP_MESSAGE {
                return Err(OidcError::Internal(
                    "LDAP response exceeded the message limit".into(),
                ));
            }
            let mut chunk = [0u8; 8192];
            let timeout = self.timeout;
            let read = timed_read(self.transport_mut()?, &mut chunk, timeout).await?;
            if read == 0 {
                return Err(OidcError::Internal(
                    "LDAP connection closed unexpectedly".into(),
                ));
            }
            self.incoming.extend_from_slice(&chunk[..read]);
        }
    }
}

pub async fn test_connection(
    state: &OidcState,
    provider: &UserFederationProvider,
) -> Result<String, OidcError> {
    let config = DirectLdapConfig::from_provider(provider)?;
    let mut connection = LdapConnection::connect(provider, &config).await?;
    service_bind(state, provider, &config, &mut connection).await?;
    let filter = parse_filter("(objectClass=*)")?;
    connection
        .search(
            &config.base_dn,
            filter,
            std::slice::from_ref(&config.id_attribute),
            1,
            None,
        )
        .await?;
    Ok("Direct directory connection successful".into())
}

pub async fn authenticate(
    state: &OidcState,
    provider: &UserFederationProvider,
    identifier: &str,
    password: &str,
) -> Result<Option<DirectoryUser>, OidcError> {
    if password.is_empty() {
        return Ok(None);
    }
    let config = DirectLdapConfig::from_provider(provider)?;
    let escaped = escape_filter_value(identifier);
    let filter_text = config.user_filter.replace("{identifier}", &escaped);
    if filter_text == config.user_filter {
        return Err(OidcError::InvalidInput(
            "user_filter must contain {identifier}".into(),
        ));
    }
    let mut search_connection = LdapConnection::connect(provider, &config).await?;
    service_bind(state, provider, &config, &mut search_connection).await?;
    let entries = search_connection
        .search(
            &config.base_dn,
            parse_filter(&filter_text)?,
            &config.requested_attributes(),
            2,
            None,
        )
        .await?;
    let entries = entries.0;
    if entries.len() != 1 {
        return Ok(None);
    }
    let entry = entries.into_iter().next().expect("one entry");
    let mut user_connection = LdapConnection::connect(provider, &config).await?;
    if !user_connection.bind(&entry.dn, password).await? {
        return Ok(None);
    }
    Ok(Some(map_entry(provider.provider_type, &config, entry)?))
}

pub async fn list_users(
    state: &OidcState,
    provider: &UserFederationProvider,
    cursor: Option<&str>,
) -> Result<(Vec<DirectoryUser>, Option<String>), OidcError> {
    let config = DirectLdapConfig::from_provider(provider)?;
    let cookie = cursor
        .map(|value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(value)
                .map_err(|_| OidcError::InvalidInput("directory cursor is invalid".into()))
        })
        .transpose()?
        .unwrap_or_default();
    if cookie.len() > 4_096 {
        return Err(OidcError::InvalidInput(
            "directory cursor is too large".into(),
        ));
    }
    let mut connection = LdapConnection::connect(provider, &config).await?;
    service_bind(state, provider, &config, &mut connection).await?;
    let page_size = config.page_size.min(config.result_limit);
    let (entries, next_cookie) = connection
        .search(
            &config.base_dn,
            parse_filter(&config.sync_filter)?,
            &config.requested_attributes(),
            page_size,
            Some(&cookie),
        )
        .await?;
    let users = entries
        .into_iter()
        .map(|entry| map_entry(provider.provider_type, &config, entry))
        .collect::<Result<Vec<_>, _>>()?;
    let next_cursor = (!next_cookie.is_empty())
        .then(|| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(next_cookie));
    Ok((users, next_cursor))
}

fn paged_results_control(size: usize, cookie: &[u8]) -> Result<Tag, OidcError> {
    let value = Tag::Sequence(Sequence {
        inner: vec![
            Tag::Integer(Integer {
                inner: size as i64,
                ..Default::default()
            }),
            octet(cookie),
        ],
        ..Default::default()
    });
    let mut encoded = BytesMut::new();
    lber::write::encode_into(&mut encoded, value.into_structure()).map_err(|error| {
        OidcError::Internal(format!("LDAP paging control encoding failed: {error}"))
    })?;
    Ok(Tag::Sequence(Sequence {
        class: TagClass::Context,
        id: 0,
        inner: vec![Tag::Sequence(Sequence {
            inner: vec![octet(PAGED_RESULTS_OID), octet(&encoded)],
            ..Default::default()
        })],
    }))
}

fn paged_results_cookie(controls: Vec<StructureTag>) -> Result<Vec<u8>, OidcError> {
    let Some(controls) = controls
        .into_iter()
        .find(|tag| tag.class == TagClass::Context && tag.id == 0)
    else {
        return Ok(Vec::new());
    };
    for control in constructed(controls)? {
        let mut fields = constructed(control)?;
        if fields.len() < 2 || primitive(fields.remove(0))? != PAGED_RESULTS_OID {
            continue;
        }
        let encoded = primitive(fields.pop().expect("control value"))?;
        let (_, value) = parse_tag(&encoded)
            .map_err(|_| OidcError::Internal("LDAP paging control is malformed".into()))?;
        let mut values = constructed(value)?;
        if values.len() != 2 {
            return Err(OidcError::Internal(
                "LDAP paging control is incomplete".into(),
            ));
        }
        let _estimated_size = primitive_uint(&values.remove(0))?;
        let cookie = primitive(values.remove(0))?;
        if cookie.len() > 4_096 {
            return Err(OidcError::Internal(
                "LDAP paging cookie exceeded the limit".into(),
            ));
        }
        return Ok(cookie);
    }
    Ok(Vec::new())
}

async fn service_bind(
    state: &OidcState,
    provider: &UserFederationProvider,
    config: &DirectLdapConfig,
    connection: &mut LdapConnection,
) -> Result<(), OidcError> {
    if config.bind_dn.is_empty() {
        if connection.bind("", "").await? {
            return Ok(());
        }
    } else {
        let password = state.decrypt_sensitive_string(&provider.gateway_secret)?;
        if connection.bind(&config.bind_dn, &password).await? {
            return Ok(());
        }
    }
    Err(OidcError::AuthenticationFailed(
        "directory service bind failed".into(),
    ))
}

async fn connect_transport(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<ClientTransport, OidcError> {
    #[cfg(target_arch = "wasm32")]
    {
        let transport = wasi_pg_client::transport::connect_with_timeout(host, port, Some(timeout))
            .await
            .map_err(transport_error)?;
        Ok(ClientTransport::Wasi(transport))
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let transport = wasi_pg_client::transport::connect_with_timeout(host, port, Some(timeout))
            .await
            .map_err(transport_error)?;
        Ok(ClientTransport::Tokio(transport))
    }
}

async fn tls_transport(
    plain: ClientTransport,
    host: &str,
    config: &DirectLdapConfig,
) -> Result<TlsTransport<ClientTransport>, OidcError> {
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    if let Some(pem) = &config.ca_certificate_pem {
        let certificates = rustls::pki_types::CertificateDer::pem_slice_iter(pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| OidcError::InvalidInput("ca_certificate_pem is invalid".into()))?;
        if certificates.is_empty() {
            return Err(OidcError::InvalidInput(
                "ca_certificate_pem contains no certificate".into(),
            ));
        }
        for certificate in certificates {
            roots
                .add(certificate)
                .map_err(|_| OidcError::InvalidInput("CA certificate is invalid".into()))?;
        }
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let crypto = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(crypto)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| OidcError::Internal(format!("TLS configuration failed: {error}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsTransport::handshake(plain, Arc::new(tls), host)
        .await
        .map_err(transport_error)
}

async fn timed_read(
    transport: &mut LdapTransport,
    buffer: &mut [u8],
    timeout: Duration,
) -> Result<usize, OidcError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        tokio::time::timeout(timeout, transport.read(buffer))
            .await
            .map_err(|_| OidcError::Internal("LDAP operation timed out".into()))?
            .map_err(transport_error)
    }
    #[cfg(target_arch = "wasm32")]
    {
        use futures_concurrency::future::Race;
        let read = async { transport.read(buffer).await.map_err(transport_error) };
        let expired = async {
            let duration = timeout.as_nanos().min(u64::MAX as u128) as u64;
            wasip3::clocks::monotonic_clock::wait_for(duration).await;
            Err(OidcError::Internal("LDAP operation timed out".into()))
        };
        (read, expired).race().await
    }
}

fn transport_error(error: wasi_pg_client::transport::TransportError) -> OidcError {
    OidcError::Internal(format!("directory transport failed: {error}"))
}

fn parse_ldap_message(
    tag: StructureTag,
) -> Result<(i32, StructureTag, Vec<StructureTag>), OidcError> {
    if tag.class != TagClass::Universal || tag.id != Types::Sequence as u64 {
        return Err(OidcError::Internal(
            "LDAP response is not a sequence".into(),
        ));
    }
    let mut values = constructed(tag)?;
    if values.len() < 2 {
        return Err(OidcError::Internal("LDAP response is incomplete".into()));
    }
    let message_id = primitive_uint(&values.remove(0))? as i32;
    let operation = values.remove(0);
    Ok((message_id, operation, values))
}

fn ldap_result_code(operation: &StructureTag) -> Result<u64, OidcError> {
    let values = match &operation.payload {
        PL::C(values) => values,
        _ => return Err(OidcError::Internal("LDAP result is malformed".into())),
    };
    values
        .first()
        .map(primitive_uint)
        .transpose()?
        .ok_or_else(|| OidcError::Internal("LDAP result omitted its status".into()))
}

fn parse_search_entry(operation: StructureTag) -> Result<LdapEntry, OidcError> {
    let mut fields = constructed(operation)?;
    if fields.len() != 2 {
        return Err(OidcError::Internal("LDAP search entry is malformed".into()));
    }
    let dn = String::from_utf8(primitive(fields.remove(0))?)
        .map_err(|_| OidcError::Internal("LDAP returned a non-UTF-8 DN".into()))?;
    let attributes = constructed(fields.remove(0))?;
    let mut mapped = HashMap::new();
    for attribute in attributes {
        let mut parts = constructed(attribute)?;
        if parts.len() != 2 {
            return Err(OidcError::Internal("LDAP attribute is malformed".into()));
        }
        let name = String::from_utf8(primitive(parts.remove(0))?)
            .map_err(|_| OidcError::Internal("LDAP attribute name is invalid".into()))?
            .to_ascii_lowercase();
        let values = constructed(parts.remove(0))?
            .into_iter()
            .map(primitive)
            .collect::<Result<Vec<_>, _>>()?;
        mapped.insert(name, values);
    }
    Ok(LdapEntry {
        dn,
        attributes: mapped,
    })
}

fn map_entry(
    provider_type: UserFederationType,
    config: &DirectLdapConfig,
    entry: LdapEntry,
) -> Result<DirectoryUser, OidcError> {
    let raw_id = entry
        .values(&config.id_attribute)
        .first()
        .ok_or_else(|| OidcError::InvalidInput("directory user omitted the stable ID".into()))?;
    let external_id = if provider_type == UserFederationType::ActiveDirectory && raw_id.len() == 16
    {
        let data1 = u32::from_le_bytes(raw_id[0..4].try_into().expect("four bytes"));
        let data2 = u16::from_le_bytes(raw_id[4..6].try_into().expect("two bytes"));
        let data3 = u16::from_le_bytes(raw_id[6..8].try_into().expect("two bytes"));
        let data4: &[u8; 8] = raw_id[8..16].try_into().expect("eight bytes");
        uuid::Uuid::from_fields(data1, data2, data3, data4).to_string()
    } else {
        String::from_utf8(raw_id.clone()).unwrap_or_else(|_| hex::encode(raw_id))
    };
    let username = entry
        .text(&config.username_attribute)
        .ok_or_else(|| OidcError::InvalidInput("directory user omitted username".into()))?;
    let email = entry
        .text(&config.email_attribute)
        .ok_or_else(|| OidcError::InvalidInput("directory user omitted email".into()))?;
    let groups = entry
        .values(&config.group_attribute)
        .iter()
        .filter_map(|value| String::from_utf8(value.clone()).ok())
        .map(|value| group_name(&value))
        .collect();
    let enabled = if provider_type == UserFederationType::ActiveDirectory {
        entry
            .text(&config.enabled_attribute)
            .and_then(|value| value.parse::<u32>().ok())
            .map(|flags| flags & 2 == 0)
            .unwrap_or(true)
    } else if config.enabled_attribute.is_empty() {
        true
    } else {
        entry
            .text(&config.enabled_attribute)
            .map(|value| {
                !matches!(
                    value.to_ascii_lowercase().as_str(),
                    "false" | "0" | "disabled"
                )
            })
            .unwrap_or(true)
    };
    let mut attributes = Map::new();
    for name in &config.custom_attributes {
        let values = entry
            .values(name)
            .iter()
            .filter_map(|value| String::from_utf8(value.clone()).ok())
            .collect::<Vec<_>>();
        if values.len() == 1 {
            attributes.insert(name.clone(), Value::String(values[0].clone()));
        } else if !values.is_empty() {
            attributes.insert(
                name.clone(),
                Value::Array(values.into_iter().map(Value::String).collect()),
            );
        }
    }
    let user = DirectoryUser {
        external_id,
        username,
        email,
        dn: Some(entry.dn.clone()),
        given_name: entry.text(&config.given_name_attribute),
        family_name: entry.text(&config.family_name_attribute),
        display_name: entry.text(&config.display_name_attribute),
        enabled,
        groups,
        attributes: Value::Object(attributes),
    };
    user.validate()?;
    Ok(user)
}

fn group_name(dn_or_name: &str) -> String {
    let first = dn_or_name.split(',').next().unwrap_or(dn_or_name).trim();
    first
        .strip_prefix("CN=")
        .or_else(|| first.strip_prefix("cn="))
        .unwrap_or(first)
        .replace("\\,", ",")
}

fn constructed(tag: StructureTag) -> Result<Vec<StructureTag>, OidcError> {
    match tag.payload {
        PL::C(values) => Ok(values),
        _ => Err(OidcError::Internal(
            "LDAP BER value should be constructed".into(),
        )),
    }
}

fn primitive(tag: StructureTag) -> Result<Vec<u8>, OidcError> {
    match tag.payload {
        PL::P(value) => Ok(value),
        _ => Err(OidcError::Internal(
            "LDAP BER value should be primitive".into(),
        )),
    }
}

fn primitive_uint(tag: &StructureTag) -> Result<u64, OidcError> {
    match &tag.payload {
        PL::P(value) => parse_uint(value)
            .map(|(_, value)| value)
            .map_err(|_| OidcError::Internal("LDAP integer is invalid".into())),
        _ => Err(OidcError::Internal("LDAP integer is malformed".into())),
    }
}

fn octet(value: &[u8]) -> Tag {
    Tag::OctetString(OctetString {
        inner: value.to_vec(),
        ..Default::default()
    })
}

fn escape_filter_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            0..=0x1f | 0x7f..=u8::MAX | b'(' | b')' | b'*' | b'\\' => {
                escaped.push_str(&format!("\\{byte:02x}"))
            }
            _ => escaped.push(*byte as char),
        }
    }
    escaped
}

fn parse_filter(value: &str) -> Result<Tag, OidcError> {
    let mut parser = FilterParser {
        input: value.as_bytes(),
        position: 0,
        depth: 0,
    };
    let filter = parser.filter()?;
    if parser.position != parser.input.len() {
        return Err(OidcError::InvalidInput(
            "LDAP filter contains trailing data".into(),
        ));
    }
    Ok(filter)
}

struct FilterParser<'a> {
    input: &'a [u8],
    position: usize,
    depth: usize,
}

impl FilterParser<'_> {
    fn filter(&mut self) -> Result<Tag, OidcError> {
        self.depth += 1;
        if self.depth > 16 {
            return Err(OidcError::InvalidInput(
                "LDAP filter nesting is too deep".into(),
            ));
        }
        self.expect(b'(')?;
        let tag = match self.peek() {
            Some(b'&') | Some(b'|') => {
                let id = if self.take() == Some(b'&') { 0 } else { 1 };
                let mut children = Vec::new();
                while self.peek() == Some(b'(') {
                    children.push(self.filter()?);
                    if children.len() > 32 {
                        return Err(OidcError::InvalidInput(
                            "LDAP filter has too many branches".into(),
                        ));
                    }
                }
                if children.is_empty() {
                    return Err(OidcError::InvalidInput(
                        "LDAP logical filter is empty".into(),
                    ));
                }
                Tag::Sequence(Sequence {
                    class: TagClass::Context,
                    id,
                    inner: children,
                })
            }
            Some(b'!') => {
                self.take();
                let inner = self.filter()?;
                Tag::Sequence(Sequence {
                    class: TagClass::Context,
                    id: 2,
                    inner: vec![inner],
                })
            }
            _ => self.item()?,
        };
        self.expect(b')')?;
        self.depth -= 1;
        Ok(tag)
    }

    fn item(&mut self) -> Result<Tag, OidcError> {
        let start = self.position;
        while matches!(self.peek(), Some(value) if value.is_ascii_alphanumeric() || matches!(value, b'-' | b'.' | b';'))
        {
            self.position += 1;
        }
        if self.position == start {
            return Err(OidcError::InvalidInput(
                "LDAP filter attribute is invalid".into(),
            ));
        }
        let attribute = &self.input[start..self.position];
        self.expect(b'=')?;
        if self.peek() == Some(b'*') && self.input.get(self.position + 1) == Some(&b')') {
            self.position += 1;
            return Ok(Tag::OctetString(OctetString {
                class: TagClass::Context,
                id: 7,
                inner: attribute.to_vec(),
            }));
        }
        let mut assertion = Vec::new();
        while let Some(value) = self.peek() {
            if value == b')' {
                break;
            }
            if value == b'*' {
                return Err(OidcError::InvalidInput(
                    "LDAP substring filters are not supported".into(),
                ));
            }
            self.position += 1;
            if value == b'\\' {
                let high = self.take().and_then(hex_value).ok_or_else(|| {
                    OidcError::InvalidInput("LDAP filter escape is invalid".into())
                })?;
                let low = self.take().and_then(hex_value).ok_or_else(|| {
                    OidcError::InvalidInput("LDAP filter escape is invalid".into())
                })?;
                assertion.push((high << 4) | low);
            } else {
                assertion.push(value);
            }
        }
        Ok(Tag::Sequence(Sequence {
            class: TagClass::Context,
            id: 3,
            inner: vec![octet(attribute), octet(&assertion)],
        }))
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }
    fn take(&mut self) -> Option<u8> {
        let value = self.peek()?;
        self.position += 1;
        Some(value)
    }
    fn expect(&mut self, expected: u8) -> Result<(), OidcError> {
        if self.take() == Some(expected) {
            Ok(())
        } else {
            Err(OidcError::InvalidInput(
                "LDAP filter syntax is invalid".into(),
            ))
        }
    }
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(url: String) -> UserFederationProvider {
        UserFederationProvider {
            id: uuid::Uuid::new_v4(),
            realm_id: uuid::Uuid::new_v4(),
            name: "Test LDAP".into(),
            provider_type: UserFederationType::Ldap,
            enabled: true,
            priority: 0,
            gateway_url: url,
            gateway_secret: String::new(),
            config: serde_json::json!({"base_dn":"dc=example,dc=com","allow_insecure_transport":true}),
            import_users: true,
            sync_groups: true,
            last_sync_at: None,
            last_sync_status: None,
            last_sync_error: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn ldap_result_message(message_id: i32, application_id: u64, result_code: i64) -> Vec<u8> {
        let message = Tag::Sequence(Sequence {
            inner: vec![
                Tag::Integer(Integer {
                    inner: message_id as i64,
                    ..Default::default()
                }),
                Tag::Sequence(Sequence {
                    class: TagClass::Application,
                    id: application_id,
                    inner: vec![
                        Tag::Enumerated(Enumerated {
                            inner: result_code,
                            ..Default::default()
                        }),
                        octet(b""),
                        octet(b""),
                    ],
                }),
            ],
            ..Default::default()
        });
        let mut encoded = BytesMut::new();
        lber::write::encode_into(&mut encoded, message.into_structure()).unwrap();
        encoded.to_vec()
    }

    #[test]
    fn escapes_filter_injection() {
        assert_eq!(
            escape_filter_value("a*)(uid=*)"),
            "a\\2a\\29\\28uid=\\2a\\29"
        );
        assert_eq!(escape_filter_value("élise"), "\\c3\\a9lise");
    }

    #[test]
    fn parses_default_and_active_directory_filters() {
        assert!(parse_filter("(uid=alice)").is_ok());
        assert!(parse_filter("(|(userPrincipalName=alice)(sAMAccountName=alice))").is_ok());
        assert!(parse_filter("(objectClass=*)").is_ok());
        assert!(parse_filter("(uid=a*)(objectClass=*)").is_err());
        assert!(
            parse_filter(&format!("{}(uid=alice){}", "(!".repeat(17), ")".repeat(17))).is_err()
        );
    }

    #[test]
    fn converts_active_directory_guid() {
        let config = DirectLdapConfig {
            base_dn: "dc=example,dc=com".into(),
            id_attribute: "objectGUID".into(),
            username_attribute: "sAMAccountName".into(),
            ..Default::default()
        };
        let mut attributes = HashMap::new();
        attributes.insert(
            "objectguid".into(),
            vec![vec![
                0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]],
        );
        attributes.insert("samaccountname".into(), vec![b"alice".to_vec()]);
        attributes.insert("mail".into(), vec![b"alice@example.com".to_vec()]);
        let user = map_entry(
            UserFederationType::ActiveDirectory,
            &config,
            LdapEntry {
                dn: "CN=Alice,DC=example,DC=com".into(),
                attributes,
            },
        )
        .unwrap();
        assert_eq!(user.external_id, "00112233-4455-6677-8899-aabbccddeeff");
    }

    #[test]
    fn paged_results_cookie_round_trips() {
        let control = paged_results_control(250, b"opaque-cookie").unwrap();
        let cookie = paged_results_cookie(vec![control.into_structure()]).unwrap();
        assert_eq!(cookie, b"opaque-cookie");
    }

    #[tokio::test]
    async fn direct_tcp_bind_handles_fragmented_protocol_responses() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut pending = Vec::new();
            for expected_code in [0, 49] {
                let (message_id, password) = loop {
                    if let Ok((remaining, tag)) = parse_tag(&pending) {
                        let consumed = pending.len() - remaining.len();
                        let (message_id, operation, _) = parse_ldap_message(tag).unwrap();
                        assert_eq!((operation.class, operation.id), (TagClass::Application, 0));
                        let fields = constructed(operation).unwrap();
                        let password = match &fields[2].payload {
                            PL::P(value) => value.clone(),
                            _ => panic!("password must be primitive"),
                        };
                        pending.drain(..consumed);
                        break (message_id, password);
                    }
                    let mut buffer = [0u8; 128];
                    let read = socket.read(&mut buffer).await.unwrap();
                    assert!(read > 0);
                    pending.extend_from_slice(&buffer[..read]);
                };
                assert_eq!(
                    password,
                    if expected_code == 0 {
                        b"correct".to_vec()
                    } else {
                        b"wrong".to_vec()
                    }
                );
                let response = ldap_result_message(message_id, 1, expected_code);
                let split = response.len() / 2;
                socket.write_all(&response[..split]).await.unwrap();
                tokio::task::yield_now().await;
                socket.write_all(&response[split..]).await.unwrap();
            }
        });

        let config =
            DirectLdapConfig::from_provider(&provider(format!("ldap://{address}"))).unwrap();
        let mut connection =
            LdapConnection::connect(&provider(format!("ldap://{address}")), &config)
                .await
                .unwrap();
        assert!(
            connection
                .bind("uid=alice,dc=example,dc=com", "correct")
                .await
                .unwrap()
        );
        assert!(
            !connection
                .bind("uid=alice,dc=example,dc=com", "wrong")
                .await
                .unwrap()
        );
        server.await.unwrap();
    }
}
