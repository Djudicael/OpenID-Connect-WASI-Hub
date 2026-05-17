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

export async function listAllPages(listFn, params = {}, signal, options = {}) {
  const pageSize = Number(options.pageSize) || 100;
  let offset = 0;
  let total = null;
  const items = [];

  while (true) {
    const response = await listFn({
      ...params,
      limit: String(pageSize),
      offset: String(offset),
    }, signal);

    const pageItems = response?.items || [];
    items.push(...pageItems);

    if (typeof response?.total === 'number') {
      total = response.total;
    }

    if (pageItems.length === 0) break;
    offset += pageItems.length;

    if (pageItems.length < pageSize) break;
    if (total !== null && offset >= total) break;
  }

  return items;
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
