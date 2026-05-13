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

export function listUsers(params = {}) {
  return get(`/api/users${buildQuery(params)}`);
}

export function getUser(id) {
  return get(`/api/users/${id}`);
}

export function createUser(body) {
  return post('/api/users', body);
}

export function updateUser(id, body) {
  return put(`/api/users/${id}`, body);
}

export function deleteUser(id) {
  return del(`/api/users/${id}`);
}
