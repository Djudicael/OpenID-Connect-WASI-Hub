import { get } from '../core/http.js';

export function fetchStats() {
  return get('/api/stats');
}
