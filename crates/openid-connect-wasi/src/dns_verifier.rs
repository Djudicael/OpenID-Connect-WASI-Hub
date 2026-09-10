use oidc_core::OidcError;

/// Resolve TXT records through DNS-over-HTTPS so the same code works in WASI Preview 2.
pub async fn txt_records(name: &str) -> Result<Vec<String>, OidcError> {
    let endpoint = std::env::var("OIDC_DNS_OVER_HTTPS_URL")
        .unwrap_or_else(|_| "https://cloudflare-dns.com/dns-query".into());
    let url = format!("{}?name={}&type=TXT", endpoint, urlencoding::encode(name));
    #[cfg(not(target_arch = "wasm32"))]
    let json: serde_json::Value = reqwest::Client::new()
        .get(&url)
        .header("Accept", "application/dns-json")
        .send()
        .await
        .map_err(|error| OidcError::Internal(format!("DNS verification request failed: {error}")))?
        .json()
        .await
        .map_err(|error| OidcError::Internal(format!("DNS response was invalid: {error}")))?;
    #[cfg(target_arch = "wasm32")]
    let json: serde_json::Value = {
        let request = wstd::http::Request::get(&url)
            .header("Accept", "application/dns-json")
            .body(wstd::http::Body::from(Vec::new()))
            .map_err(|error| OidcError::Internal(format!("DNS request build failed: {error}")))?;
        let mut response = wstd::http::Client::new()
            .send(request)
            .await
            .map_err(|error| {
                OidcError::Internal(format!("DNS verification request failed: {error}"))
            })?;
        let bytes =
            response.body_mut().contents().await.map_err(|error| {
                OidcError::Internal(format!("DNS response read failed: {error}"))
            })?;
        serde_json::from_slice(bytes)
            .map_err(|error| OidcError::Internal(format!("DNS response was invalid: {error}")))?
    };
    Ok(json
        .get("Answer")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|answer| answer.get("data").and_then(|value| value.as_str()))
        .map(|value| value.trim_matches('"').replace("\"\"", ""))
        .collect())
}
