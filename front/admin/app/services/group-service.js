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

export function listGroups(params = {}, signal) {
  return get(`/api/groups${buildQuery(params)}`, signal);
}

export function getGroup(id, signal) {
  return get(`/api/groups/${id}`, signal);
}

export function createGroup(body, signal) {
  return post('/api/groups', body, signal);
}

export function updateGroup(id, body, signal) {
  return put(`/api/groups/${id}`, body, signal);
}

export function deleteGroup(id, signal) {
  return del(`/api/groups/${id}`, signal);
}

export function listUserGroups(userId, signal) {
  return get(`/api/users/${userId}/groups`, signal);
}

export function assignGroupToUser(userId, groupId, signal) {
  return post(`/api/users/${userId}/groups`, { group_id: groupId }, signal);
}

export function unassignGroupFromUser(userId, groupId, signal) {
  return del(`/api/users/${userId}/groups/${groupId}`, signal);
}

export function listGroupRoles(groupId, signal) {
  return get(`/api/groups/${groupId}/roles`, signal);
}

export function assignRoleToGroup(groupId, roleId, signal) {
  return post(`/api/groups/${groupId}/roles`, { role_id: roleId }, signal);
}

export function unassignRoleFromGroup(groupId, roleId, signal) {
  return del(`/api/groups/${groupId}/roles/${roleId}`, signal);
}
