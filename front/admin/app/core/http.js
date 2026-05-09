import { apiUrl } from '../config/api.js';
import { authService } from '../auth/auth-service.js';

/**
 * Fetch wrapper with auth + error handling.
 */

export class HttpError extends Error {
  constructor(status, statusText, body) {
    super(`${status} ${statusText}`);
    this.status = status;
    this.statusText = statusText;
    this.body = body;
  }
}

export async function http(url, options = {}) {
  const fullUrl = apiUrl(url);
  const opts = {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
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
