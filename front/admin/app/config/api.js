/**
 * API base URL resolution.
 * Uses <meta> tag for configuration only — no global variable overrides.
 */

function resolveBaseUrl() {
  const meta = document.querySelector('meta[name="oidc-api-base-url"]');
  if (meta && meta.content) {
    return meta.content;
  }
  return '';
}

export const API_BASE_URL = resolveBaseUrl();

export function apiUrl(path) {
  if (path.startsWith('http')) return path;
  const base = API_BASE_URL.endsWith('/') ? API_BASE_URL.slice(0, -1) : API_BASE_URL;
  const cleanPath = path.startsWith('/') ? path : '/' + path;
  return base + cleanPath;
}
