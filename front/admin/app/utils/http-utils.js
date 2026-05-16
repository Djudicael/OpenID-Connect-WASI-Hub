import { get, post, put, del } from '../core/http.js';

export function buildQuery(params) {
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      qs.set(key, String(value));
    }
  }
  return qs.toString() ? `?${qs.toString()}` : '';
}

export function createCrudService(resource) {
  return {
    list: (params = {}, signal) => get(`/api/${resource}${buildQuery(params)}`, signal),
    get: (id, signal) => get(`/api/${resource}/${id}`, signal),
    create: (body, signal) => post(`/api/${resource}`, body, signal),
    update: (id, body, signal) => put(`/api/${resource}/${id}`, body, signal),
    delete: (id, signal) => del(`/api/${resource}/${id}`, signal),
  };
}
