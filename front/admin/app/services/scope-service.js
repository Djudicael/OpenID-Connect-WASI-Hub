import { get, post, del } from '../core/http.js';

export function listScopes(realmId, signal) {
  const qs = new URLSearchParams();
  qs.set('realm_id', realmId);
  return get(`/api/scopes?${qs.toString()}`, signal);
}

export function createScope(body, signal) {
  return post('/api/scopes', body, signal);
}

export function deleteScope(id, signal) {
  return del(`/api/scopes/${id}`, signal);
}
