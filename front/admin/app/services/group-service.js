import { createCrudService } from '../utils/http-utils.js';
export const groups = createCrudService('groups');
export const { list: listGroups, get: getGroup, create: createGroup, update: updateGroup, delete: deleteGroup } = groups;

import { get, post, del } from '../core/http.js';
export function listUserGroups(userId, signal) { return get(`/api/users/${userId}/groups`, signal); }
export function assignGroupToUser(userId, groupId, signal) { return post(`/api/users/${userId}/groups`, { group_id: groupId }, signal); }
export function unassignGroupFromUser(userId, groupId, signal) { return del(`/api/users/${userId}/groups/${groupId}`, signal); }
export function listGroupRoles(groupId, signal) { return get(`/api/groups/${groupId}/roles`, signal); }
export function assignRoleToGroup(groupId, roleId, signal) { return post(`/api/groups/${groupId}/roles`, { role_id: roleId }, signal); }
export function unassignRoleFromGroup(groupId, roleId, signal) { return del(`/api/groups/${groupId}/roles/${roleId}`, signal); }
