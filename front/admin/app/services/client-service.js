import { get, post, put, del } from '../core/http.js';

function buildQuery(params) {
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      qs.set(key, String(value));
    }
  }
  return qs.toString() ? `?${qs.toString()}` : '';
}

export function listClients(params = {}) {
  return get(`/api/clients${buildQuery(params)}`);
}

export function getClient(id) {
  return get(`/api/clients/${id}`);
}

export function createClient(body) {
  return post('/api/clients', body);
}

export function updateClient(id, body) {
  return put(`/api/clients/${id}`, body);
}

export function deleteClient(id) {
  return del(`/api/clients/${id}`);
}
