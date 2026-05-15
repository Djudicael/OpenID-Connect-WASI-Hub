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

export function listUsers(params = {}, signal) {
  return get(`/api/users${buildQuery(params)}`, signal);
}

export function getUser(id, signal) {
  return get(`/api/users/${id}`, signal);
}

export function createUser(body, signal) {
  return post('/api/users', body, signal);
}

export function updateUser(id, body, signal) {
  return put(`/api/users/${id}`, body, signal);
}

export function deleteUser(id, signal) {
  return del(`/api/users/${id}`, signal);
}
