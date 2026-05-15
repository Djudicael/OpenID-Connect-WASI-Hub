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

export function listIdentityProviders(realmId, signal) {
  return get(`/api/realms/${realmId}/identity-providers`, signal);
}

export function getIdentityProvider(id, signal) {
  return get(`/api/identity-providers/${id}`, signal);
}

export function createIdentityProvider(body, signal) {
  return post('/api/identity-providers', body, signal);
}

export function updateIdentityProvider(id, body, signal) {
  return put(`/api/identity-providers/${id}`, body, signal);
}

export function deleteIdentityProvider(id, signal) {
  return del(`/api/identity-providers/${id}`, signal);
}
