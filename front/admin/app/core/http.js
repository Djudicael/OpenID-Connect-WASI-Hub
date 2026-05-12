import { apiUrl } from '../config/api.js';
import { authService } from '../auth/auth-service.js';

/**
 * Fetch wrapper with auth + CSRF protection.
 */

export class HttpError extends Error {
  constructor(status, statusText, body) {
    super(`${status} ${statusText}`);
    this.status = status;
    this.statusText = statusText;
    this.body = body;
  }
}

const CSRF_COOKIE_NAME = 'oidc_csrf_token';
const CSRF_HEADER_NAME = 'X-CSRF-Token';

function getCsrfTokenFromCookie() {
  const match = document.cookie.match(new RegExp(`(^| )${CSRF_COOKIE_NAME}=([^;]+)`));
  return match ? match[2] : null;
}

function ensureCsrfToken() {
  // Prefer server-set cookie
  let token = getCsrfTokenFromCookie();
  if (!token) {
    // Fallback: generate a token (server should set this in production)
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    token = Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
    // Set as non-HttpOnly so JS can read it for the header
    // In production, the backend should set this cookie with Secure and SameSite=Strict
    document.cookie = `${CSRF_COOKIE_NAME}=${token}; path=/; SameSite=Strict; max-age=86400`;
  }
  return token;
}

export async function http(url, options = {}) {
  const fullUrl = apiUrl(url);
  const csrfToken = ensureCsrfToken();
  const opts = {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      [CSRF_HEADER_NAME]: csrfToken,
      ...options.headers,
    },
    credentials: 'same-origin',
  };

  // Add auth header if authenticated
  if (authService.isAuthenticated()) {
    const token = await authService.getAccessToken();
    if (token) {
      opts.headers['Authorization'] = `Bearer ${token}`;
    }
  }

  const response = await fetch(fullUrl, opts);

  if (!response.ok) {
    let body = null;
    try { body = await response.json(); } catch { /* ignore */ }
    throw new HttpError(response.status, response.statusText, body);
  }

  if (response.status === 204) {
    return null;
  }

  return response.json();
}

export function get(url) {
  return http(url, { method: 'GET' });
}

export function post(url, body) {
  return http(url, { method: 'POST', body: JSON.stringify(body) });
}

export function put(url, body) {
  return http(url, { method: 'PUT', body: JSON.stringify(body) });
}

export function del(url) {
  return http(url, { method: 'DELETE' });
}
