import { get, post } from '../core/http.js';
import { buildQuery } from '../utils/http-utils.js';
export function listSessions(params = {}, signal) { return get(`/api/sessions${buildQuery(params)}`, signal); }
export function revokeSession(id, signal) { return post(`/api/sessions/${id}/revoke`, {}, signal); }
