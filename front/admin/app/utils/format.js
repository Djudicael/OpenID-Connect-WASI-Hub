/**
 * Formatting utilities.
 */

export function formatDate(isoString) {
  if (!isoString) return '-';
  const d = new Date(isoString);
  if (isNaN(d)) return isoString;
  return d.toLocaleString();
}

export function formatRelativeTime(isoString) {
  if (!isoString) return '-';
  const d = new Date(isoString);
  if (isNaN(d)) return isoString;
  const now = Date.now();
  const diff = now - d.getTime();
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (seconds < 60) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 30) return `${days}d ago`;
  return d.toLocaleDateString();
}

export function formatBytes(bytes) {
  if (bytes === 0 || bytes == null) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

export function truncate(str, maxLen = 50) {
  if (!str || str.length <= maxLen) return str;
  return str.slice(0, maxLen) + '...';
}
