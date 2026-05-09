/**
 * API base URL resolution.
 * In dev mode with the proxy, all API calls use relative paths.
 * In production, the meta tag or global can override.
 */

function resolveBaseUrl() {
  if (typeof globalThis !== 'undefined' && globalThis.__OIDC_API_BASE_URL__) {
    return globalThis.__OIDC_API_BASE_URL__;
  }
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
