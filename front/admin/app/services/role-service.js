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

export function listRoles(params = {}) {
  return get(`/api/roles${buildQuery(params)}`);
}

export function getRole(id) {
  return get(`/api/roles/${id}`);
}

export function createRole(body) {
  return post('/api/roles', body);
}

export function updateRole(id, body) {
  return put(`/api/roles/${id}`, body);
}

export function deleteRole(id) {
  return del(`/api/roles/${id}`);
}

export function listUserRoles(userId) {
  return get(`/api/users/${userId}/roles`);
}

export function assignRoleToUser(userId, roleId) {
  return post(`/api/users/${userId}/roles`, { role_id: roleId });
}

export function unassignRoleFromUser(userId, roleId) {
  return del(`/api/users/${userId}/roles/${roleId}`);
}
