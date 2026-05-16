import { createCrudService } from '../utils/http-utils.js';
export const clients = createCrudService('clients');
export const { list: listClients, get: getClient, create: createClient, update: updateClient, delete: deleteClient } = clients;
