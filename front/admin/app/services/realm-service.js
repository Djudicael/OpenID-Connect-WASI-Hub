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

export function listRealms(params = {}, signal) {
  return get(`/api/realms${buildQuery(params)}`, signal);
}

export function getRealm(id, signal) {
  return get(`/api/realms/${id}`, signal);
}

export function createRealm(body, signal) {
  return post('/api/realms', body, signal);
}

export function updateRealm(id, body, signal) {
  return put(`/api/realms/${id}`, body, signal);
}

export function deleteRealm(id, signal) {
  return del(`/api/realms/${id}`, signal);
}
