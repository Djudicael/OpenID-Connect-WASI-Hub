import { get, post, del } from '../core/http.js';

export function listScopes(realmId) {
  const qs = new URLSearchParams();
  qs.set('realm_id', realmId);
  return get(`/api/scopes?${qs.toString()}`);
}

export function createScope(body) {
  return post('/api/scopes', body);
}

export function deleteScope(id) {
  return del(`/api/scopes/${id}`);
}
