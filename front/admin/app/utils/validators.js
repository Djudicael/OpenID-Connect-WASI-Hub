/**
 * Validation utilities.
 */

export function isEmail(str) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(str);
}

export function isUuid(str) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(str);
}

export function isRequired(str) {
  return typeof str === 'string' && str.trim().length > 0;
}

export function minLength(str, min) {
  return typeof str === 'string' && str.length >= min;
}
