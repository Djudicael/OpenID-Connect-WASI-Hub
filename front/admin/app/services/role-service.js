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

export function listRoles(params = {}, signal) {
  return get(`/api/roles${buildQuery(params)}`, signal);
}

export function getRole(id, signal) {
  return get(`/api/roles/${id}`, signal);
}

export function createRole(body, signal) {
  return post('/api/roles', body, signal);
}

export function updateRole(id, body, signal) {
  return put(`/api/roles/${id}`, body, signal);
}

export function deleteRole(id, signal) {
  return del(`/api/roles/${id}`, signal);
}

export function listUserRoles(userId, signal) {
  return get(`/api/users/${userId}/roles`, signal);
}

export function assignRoleToUser(userId, roleId, signal) {
  return post(`/api/users/${userId}/roles`, { role_id: roleId }, signal);
}

export function unassignRoleFromUser(userId, roleId, signal) {
  return del(`/api/users/${userId}/roles/${roleId}`, signal);
}
