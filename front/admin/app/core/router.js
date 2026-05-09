import { html, render } from 'lit-html';
import { authService } from '../auth/auth-service.js';

const routes = [
  { path: '/login', component: 'login-page', public: true },
  { path: '/callback', component: 'login-page', public: true },
  { path: '/', component: 'dashboard-page' },
  { path: '/users', component: 'users-page' },
  { path: '/users/:id', component: 'user-detail-page' },
  { path: '/clients', component: 'clients-page' },
  { path: '/realms', component: 'realms-page' },
  { path: '/sessions', component: 'sessions-page' },
  { path: '/api-keys', component: 'apikeys-page' },
  { path: '/api-keys/create', component: 'apikey-create-page' },
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
      this.innerHTML = '<h1>404 - Page Not Found</h1>';
      return;
    }

    if (!route.public && !authService.isAuthenticated()) {
      this._navigate('/login');
      return;
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
