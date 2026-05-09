/**
 * Lightweight observable state store.
 * Subscribe to changes with callbacks.
 */

class Store {
  constructor(initial = {}) {
    this._state = { ...initial };
    this._listeners = new Set();
  }

  getState() {
    return { ...this._state };
  }

  setState(patch) {
    this._state = { ...this._state, ...patch };
    this._notify();
  }

  subscribe(callback) {
    this._listeners.add(callback);
    return () => this._listeners.delete(callback);
  }

  _notify() {
    const state = this.getState();
    for (const cb of this._listeners) {
      try { cb(state); } catch (e) { console.error('Store listener error:', e); }
    }
  }
}

export const appStore = new Store({
  user: null,
  toasts: [],
  sidebarOpen: true,
});
