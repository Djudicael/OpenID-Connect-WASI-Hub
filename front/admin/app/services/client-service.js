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

export function listClients(params = {}, signal) {
  return get(`/api/clients${buildQuery(params)}`, signal);
}

export function getClient(id, signal) {
  return get(`/api/clients/${id}`, signal);
}

export function createClient(body, signal) {
  return post('/api/clients', body, signal);
}

export function updateClient(id, body, signal) {
  return put(`/api/clients/${id}`, body, signal);
}

export function deleteClient(id, signal) {
  return del(`/api/clients/${id}`, signal);
}
