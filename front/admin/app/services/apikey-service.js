import { get, post, del } from '../core/http.js';
import { buildQuery } from '../utils/http-utils.js';
export function listApiKeys(params = {}, signal) { return get(`/api/keys${buildQuery(params)}`, signal); }
export function getApiKey(id, signal) { return get(`/api/keys/${id}`, signal); }
export function createApiKey(body, signal) { return post('/api/keys', body, signal); }
export function rotateApiKey(id, signal) { return post(`/api/keys/${id}/rotate`, {}, signal); }
export function deleteApiKey(id, signal) { return del(`/api/keys/${id}`, signal); }
