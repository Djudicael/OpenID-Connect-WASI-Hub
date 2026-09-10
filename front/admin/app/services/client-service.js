import { createCrudService } from '../utils/http-utils.js';
import { get, put } from '../core/http.js';
export const clients = createCrudService('clients');
export const { list: listClients, get: getClient, create: createClient, update: updateClient, delete: deleteClient } = clients;
export const getClientCiba = (id, signal) => get(`/api/clients/${id}/ciba`, signal);
export const updateClientCiba = (id, body, signal) => put(`/api/clients/${id}/ciba`, body, signal);
