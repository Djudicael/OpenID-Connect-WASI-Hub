import { get, post, put, del } from '../core/http.js';
export const listSamlClients=(realmId,signal)=>get(`/api/saml/clients?realm_id=${realmId}`,signal);
export const createSamlClient=(body,signal)=>post('/api/saml/clients',body,signal);
export const updateSamlClient=(id,body,signal)=>put(`/api/saml/clients/${id}`,body,signal);
export const deleteSamlClient=(id,signal)=>del(`/api/saml/clients/${id}`,signal);
