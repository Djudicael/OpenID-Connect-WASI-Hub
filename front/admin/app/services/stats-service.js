import { get } from '../core/http.js';

export function fetchStats(signal) {
  return get('/api/stats', signal);
}
