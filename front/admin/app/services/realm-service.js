import { createCrudService } from '../utils/http-utils.js';
export const realms = createCrudService('realms');
export const { list: listRealms, get: getRealm, create: createRealm, update: updateRealm, delete: deleteRealm } = realms;
