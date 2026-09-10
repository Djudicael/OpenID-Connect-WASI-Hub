import { get, post, put, del } from '../core/http.js';
export function listScopes(realmId, signal) {
  const qs = new URLSearchParams();
  qs.set('realm_id', realmId);
  return get(`/api/scopes?${qs.toString()}`, signal);
}
export function createScope(body, signal) { return post('/api/scopes', body, signal); }
export function deleteScope(id, signal) { return del(`/api/scopes/${id}`, signal); }
export function getScope(id, signal) { return get(`/api/scopes/${id}`, signal); }
export function listProtocolMappers(scopeId, signal) { return get(`/api/scopes/${scopeId}/mappers`, signal); }
export function createProtocolMapper(scopeId, body, signal) { return post(`/api/scopes/${scopeId}/mappers`, body, signal); }
export function updateProtocolMapper(scopeId, mapperId, body, signal) { return put(`/api/scopes/${scopeId}/mappers/${mapperId}`, body, signal); }
export function deleteProtocolMapper(scopeId, mapperId, signal) { return del(`/api/scopes/${scopeId}/mappers/${mapperId}`, signal); }
export function listClientScopes(clientId, signal) { return get(`/api/clients/${clientId}/scopes`, signal); }
export function assignClientScope(clientId, scopeId, assignmentType, signal) { return post(`/api/clients/${clientId}/scopes`, { scope_id: scopeId, assignment_type: assignmentType }, signal); }
export function unassignClientScope(clientId, scopeId, signal) { return del(`/api/clients/${clientId}/scopes/${scopeId}`, signal); }
