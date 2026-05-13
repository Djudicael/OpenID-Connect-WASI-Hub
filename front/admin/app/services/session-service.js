import { get, post } from '../core/http.js';

function buildQuery(params) {
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      qs.set(key, String(value));
    }
  }
  return qs.toString() ? `?${qs.toString()}` : '';
}

export function listSessions(params = {}) {
  return get(`/api/sessions${buildQuery(params)}`);
}

export function revokeSession(id) {
  return post(`/api/sessions/${id}/revoke`);
}
