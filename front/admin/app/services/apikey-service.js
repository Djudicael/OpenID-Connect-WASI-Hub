import { get, post, del } from '../core/http.js';

function buildQuery(params) {
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      qs.set(key, String(value));
    }
  }
  return qs.toString() ? `?${qs.toString()}` : '';
}

export function listApiKeys(params = {}) {
  return get(`/api/keys${buildQuery(params)}`);
}

export function getApiKey(id) {
  return get(`/api/keys/${id}`);
}

export function createApiKey(body) {
  return post('/api/keys', body);
}

export function rotateApiKey(id) {
  return post(`/api/keys/${id}/rotate`);
}

export function deleteApiKey(id) {
  return del(`/api/keys/${id}`);
}
