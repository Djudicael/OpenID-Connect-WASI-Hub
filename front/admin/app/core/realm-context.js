const STORAGE_KEY = 'oidc-admin.selectedRealmId';

function readStoredRealmId() {
  try {
    return window.localStorage.getItem(STORAGE_KEY) || '';
  } catch {
    return '';
  }
}

export function getSelectedRealmId() {
  return readStoredRealmId();
}

export function setSelectedRealmId(realmId) {
  const value = realmId || '';
  try {
    if (value) {
      window.localStorage.setItem(STORAGE_KEY, value);
    } else {
      window.localStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // Ignore storage failures; the UI can still operate with in-memory state.
  }
  return value;
}

export function resolveSelectedRealmId(realms, preferredRealmId = '') {
  if (!Array.isArray(realms) || realms.length === 0) return '';

  const preferred = preferredRealmId || readStoredRealmId();
  if (preferred && realms.some((realm) => realm.id === preferred)) {
    return preferred;
  }

  return realms[0].id;
}

export function getSelectedRealmName(realms, realmId) {
  const match = (realms || []).find((realm) => realm.id === realmId);
  return match ? (match.display_name || match.name) : '';
}
