import { createCrudService, listAllPages } from '../utils/http-utils.js';
import { post } from '../core/http.js';

export const realms = createCrudService('realms');
export const { list: listRealms, get: getRealm, create: createRealm, update: updateRealm, delete: deleteRealm } = realms;

export function listAllRealms(signal, options = {}) {
  return listAllPages(listRealms, {}, signal, options);
}

export function exportRealm(id, password, signal) {
  return post(`/api/realms/${id}/export`, { password }, signal);
}

export function importRealm(archive, password, replaceExisting, signal) {
  return post('/api/realms/import', {
    archive,
    password,
    replace_existing: replaceExisting,
  }, signal);
}

export function previewEmailTemplate(id, template, locale, signal) {
  return post(`/api/realms/${id}/email-template-preview`, { template, locale }, signal);
}
