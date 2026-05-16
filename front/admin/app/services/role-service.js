import { createCrudService } from '../utils/http-utils.js';
export const roles = createCrudService('roles');
export const { list: listRoles, get: getRole, create: createRole, update: updateRole, delete: deleteRole } = roles;

import { get, post, del } from '../core/http.js';
export function listUserRoles(userId, signal) { return get(`/api/users/${userId}/roles`, signal); }
export function assignRoleToUser(userId, roleId, signal) { return post(`/api/users/${userId}/roles`, { role_id: roleId }, signal); }
export function unassignRoleFromUser(userId, roleId, signal) { return del(`/api/users/${userId}/roles/${roleId}`, signal); }
