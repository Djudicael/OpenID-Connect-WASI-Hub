import { createCrudService, listAllPages } from '../utils/http-utils.js';

export const realms = createCrudService('realms');
export const { list: listRealms, get: getRealm, create: createRealm, update: updateRealm, delete: deleteRealm } = realms;

export function listAllRealms(signal, options = {}) {
  return listAllPages(listRealms, {}, signal, options);
}
