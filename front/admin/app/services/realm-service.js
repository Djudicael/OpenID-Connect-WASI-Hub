import { get, post, put, del } from '../core/http.js';

function buildQuery(params) {
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      qs.set(key, String(value));
    }
  }
  return qs.toString() ? `?${qs.toString()}` : '';
}

export function listRealms(params = {}) {
  return get(`/api/realms${buildQuery(params)}`);
}

export function getRealm(id) {
  return get(`/api/realms/${id}`);
}

export function createRealm(body) {
  return post('/api/realms', body);
}

export function updateRealm(id, body) {
  return put(`/api/realms/${id}`, body);
}

export function deleteRealm(id) {
  return del(`/api/realms/${id}`);
}
