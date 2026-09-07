import { del, get, put } from '../core/http.js';

export const getAccount = (signal) => get('/oidc/account', signal);
export const updateAccount = (body, signal) => put('/oidc/account', body, signal);
export const changePassword = (body, signal) => put('/oidc/account/password', body, signal);
export const listAccountSessions = (signal) => get('/oidc/account/sessions', signal);
export const revokeAccountSession = (id, signal) => del(`/oidc/account/sessions/${id}`, signal);
export const listLinkedIdentities = (signal) => get('/oidc/account/linked-identities', signal);
export const unlinkIdentity = (id, signal) => del(`/oidc/account/linked-identities/${id}`, signal);
export const listApplications = (signal) => get('/oidc/account/applications', signal);
export const revokeApplication = (id, signal) => del(`/oidc/account/applications/${id}`, signal);
