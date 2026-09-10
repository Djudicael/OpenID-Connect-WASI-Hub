import { get, post, put, del } from '../core/http.js';

export const listFederationProviders = (realmId, signal) => get(`/api/user-federation?realm_id=${encodeURIComponent(realmId)}`, signal);
export const createFederationProvider = (body, signal) => post('/api/user-federation', body, signal);
export const updateFederationProvider = (id, body, signal) => put(`/api/user-federation/${id}`, body, signal);
export const deleteFederationProvider = (id, signal) => del(`/api/user-federation/${id}`, signal);
export const testFederationProvider = (id, signal) => post(`/api/user-federation/${id}/test`, {}, signal);
export const syncFederationProvider = (id, signal) => post(`/api/user-federation/${id}/sync`, {}, signal);
