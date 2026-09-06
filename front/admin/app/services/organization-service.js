import { createCrudService } from '../utils/http-utils.js';
import { del, get, post } from '../core/http.js';

export const organizations = createCrudService('organizations');
export const {
  list: listOrganizations,
  get: getOrganization,
  create: createOrganization,
  update: updateOrganization,
  delete: deleteOrganization,
} = organizations;

export const listOrganizationDomains = (id, signal) =>
  get(`/api/organizations/${id}/domains`, signal);
export const addOrganizationDomain = (id, body, signal) =>
  post(`/api/organizations/${id}/domains`, body, signal);
export const deleteOrganizationDomain = (id, domainId, signal) =>
  del(`/api/organizations/${id}/domains/${domainId}`, signal);
export const verifyOrganizationDomain = (id, domainId, signal) =>
  post(`/api/organizations/${id}/domains/${domainId}/verify`, {}, signal);
export const listOrganizationMembers = (id, signal) =>
  get(`/api/organizations/${id}/members`, signal);
export const addOrganizationMember = (id, body, signal) =>
  post(`/api/organizations/${id}/members`, body, signal);
export const removeOrganizationMember = (id, userId, signal) =>
  del(`/api/organizations/${id}/members/${userId}`, signal);
export const listOrganizationIdentityProviders = (id, signal) =>
  get(`/api/organizations/${id}/identity-providers`, signal);
export const linkOrganizationIdentityProvider = (id, body, signal) =>
  post(`/api/organizations/${id}/identity-providers`, body, signal);
export const unlinkOrganizationIdentityProvider = (id, providerId, signal) =>
  del(`/api/organizations/${id}/identity-providers/${providerId}`, signal);
export const listOrganizationInvitations = (id, signal) =>
  get(`/api/organizations/${id}/invitations`, signal);
export const createOrganizationInvitation = (id, body, signal) =>
  post(`/api/organizations/${id}/invitations`, body, signal);
export const revokeOrganizationInvitation = (id, invitationId, signal) =>
  del(`/api/organizations/${id}/invitations/${invitationId}`, signal);
export const listOrganizationGroups = (id, signal) =>
  get(`/api/organizations/${id}/groups`, signal);
export const linkOrganizationGroup = (id, groupId, signal) =>
  post(`/api/organizations/${id}/groups`, { group_id: groupId }, signal);
export const unlinkOrganizationGroup = (id, groupId, signal) =>
  del(`/api/organizations/${id}/groups/${groupId}`, signal);
