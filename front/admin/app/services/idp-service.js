import { get, post, put, del } from '../core/http.js';
import { buildQuery } from '../utils/http-utils.js';
export function listIdentityProviders(realmId, signal) { return get(`/api/identity-providers?realm_id=${realmId}`, signal); }
export function getIdentityProvider(id, signal) { return get(`/api/identity-providers/${id}`, signal); }
export function createIdentityProvider(body, signal) { return post('/api/identity-providers', body, signal); }
export function updateIdentityProvider(id, body, signal) { return put(`/api/identity-providers/${id}`, body, signal); }
export function deleteIdentityProvider(id, signal) { return del(`/api/identity-providers/${id}`, signal); }
