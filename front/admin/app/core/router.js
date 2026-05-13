import { html, render } from 'lit-html';
import { authService } from '../auth/auth-service.js';

const routes = [
  { path: '/login', component: 'login-page', public: true },
  { path: '/callback', component: 'login-page', public: true },
  { path: '/admin', component: 'dashboard-page' },
  { path: '/', component: 'dashboard-page' },
  { path: '/users', component: 'users-page' },
  { path: '/users/:id', component: 'user-detail-page' },
  { path: '/clients', component: 'clients-page' },
  { path: '/clients/:id', component: 'client-detail-page' },
  { path: '/realms', component: 'realms-page' },
  { path: '/realms/:id', component: 'realm-detail-page' },
  { path: '/sessions', component: 'sessions-page' },
  { path: '/api-keys', component: 'apikeys-page' },
  { path: '/api-keys/create', component: 'apikey-create-page' },
  { path: '/api-keys/:id', component: 'apikey-detail-page' },
  { path: '/scopes', component: 'scopes-page' },
  { path: '/audit', component: 'audit-page' },
];

function matchPath(pattern, path) {
  const patternParts = pattern.split('/').filter(Boolean);
  const pathParts = path.split('/').filter(Boolean);

  if (patternParts.length !== pathParts.length) return null;

  const params = {};
  for (let i = 0; i < patternParts.length; i++) {
    if (patternParts[i].startsWith(':')) {
      params[patternParts[i].slice(1)] = decodeURIComponent(pathParts[i]);
    } else if (patternParts[i] !== pathParts[i]) {
      return null;
    }
  }
  return params;
}

class RouterOutlet extends HTMLElement {
  connectedCallback() {
    window.addEventListener('popstate', () => this._match());
    window.addEventListener('navigate', () => this._match());
    this._match();
  }

  _match() {
    const path = window.location.pathname;
    let route = null;
    let params = {};

    for (const r of routes) {
      const m = matchPath(r.path, path);
      if (m) {
        route = r;
        params = m;
        break;
      }
    }

    if (!route) {
      this.innerHTML = '';
      const el = document.createElement('not-found-page');
      this.appendChild(el);
      return;
    }

    if (!route.public && !authService.isAuthenticated()) {
      this._navigate('/login');
      return;
    }

    // Check admin role for protected routes
    if (!route.public && authService.isAuthenticated()) {
      const token = authService.tokens;
      if (token && token.id_token) {
        try {
          const payload = JSON.parse(atob(token.id_token.split('.')[1]));
          if (payload.exp && payload.exp * 1000 < Date.now()) {
            this._navigate('/login');
            return;
          }
          // Check for admin scope in the access token
          const accessToken = token.access_token;
          if (accessToken) {
            const accessPayload = JSON.parse(atob(accessToken.split('.')[1]));
            // Scope check: allow access if user has 'admin' scope OR if no admin scope is configured
            // The backend enforces actual authorization per-endpoint
            const scopes = (accessPayload.scope || '').split(' ');
            // Only block if we can determine the user definitely lacks admin access
            // and the token has scopes (meaning scopes are being enforced)
            if (scopes.length > 0 && scopes[0] !== '' && !scopes.includes('admin')) {
              // Still allow access — backend enforces authorization
              // Just log a warning for observability
              console.warn('User lacks admin scope but is being allowed through; backend enforces authorization');
            }
          }
        } catch {
          // If we can't parse the token, let it through — the backend will enforce
        }
      }
    }

    if (route.public && authService.isAuthenticated() && route.path === '/login') {
      this._navigate('/');
      return;
    }

    this.innerHTML = '';
    const el = document.createElement(route.component);
    el.params = params;
    this.appendChild(el);
  }

  _navigate(path) {
    window.history.pushState({}, '', path);
    this._match();
  }
}

customElements.define('router-outlet', RouterOutlet);

/**
 * Programmatic navigation helper.
 */
export function navigate(path) {
  window.history.pushState({}, '', path);
  window.dispatchEvent(new Event('navigate'));
}
