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

export function listGroups(params = {}) {
  return get(`/api/groups${buildQuery(params)}`);
}

export function getGroup(id) {
  return get(`/api/groups/${id}`);
}

export function createGroup(body) {
  return post('/api/groups', body);
}

export function updateGroup(id, body) {
  return put(`/api/groups/${id}`, body);
}

export function deleteGroup(id) {
  return del(`/api/groups/${id}`);
}

export function listUserGroups(userId) {
  return get(`/api/users/${userId}/groups`);
}

export function assignGroupToUser(userId, groupId) {
  return post(`/api/users/${userId}/groups`, { group_id: groupId });
}

export function unassignGroupFromUser(userId, groupId) {
  return del(`/api/users/${userId}/groups/${groupId}`);
}

export function listGroupRoles(groupId) {
  return get(`/api/groups/${groupId}/roles`);
}

export function assignRoleToGroup(groupId, roleId) {
  return post(`/api/groups/${groupId}/roles`, { role_id: roleId });
}

export function unassignRoleFromGroup(groupId, roleId) {
  return del(`/api/groups/${groupId}/roles/${roleId}`);
}
