import { html, render } from 'lit-html';
import { authService } from '../auth/auth-service.js';

const routes = [
  { path: '/login', component: 'login-page', public: true },
  { path: '/callback', component: 'login-page', public: true },
  { path: '/admin', component: 'dashboard-page' },
  { path: '/', component: 'dashboard-page' },
  { path: '/users', component: 'users-page' },
  { path: '/users/:id', component: 'user-detail-page' },
  { path: '/roles', component: 'roles-page' },
  { path: '/roles/:id', component: 'role-detail-page' },
  { path: '/groups', component: 'groups-page' },
  { path: '/groups/:id', component: 'group-detail-page' },
  { path: '/clients', component: 'clients-page' },
  { path: '/clients/:id', component: 'client-detail-page' },
  { path: '/realms', component: 'realms-page' },
  { path: '/realms/:id', component: 'realm-detail-page' },
  { path: '/sessions', component: 'sessions-page' },
  { path: '/api-keys', component: 'apikeys-page' },
  { path: '/api-keys/create', component: 'apikey-create-page' },
  { path: '/api-keys/:id', component: 'apikey-detail-page' },
  { path: '/scopes', component: 'scopes-page' },
  { path: '/identity-providers', component: 'identity-providers-page' },
  { path: '/password-policies', component: 'password-policies-page' },
  { path: '/maintenance', component: 'maintenance-page' },
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
  constructor() {
    super();
    this._onRouteChange = this._match.bind(this);
  }

  connectedCallback() {
    window.addEventListener('popstate', this._onRouteChange);
    window.addEventListener('navigate', this._onRouteChange);
    this._match();
  }

  disconnectedCallback() {
    window.removeEventListener('popstate', this._onRouteChange);
    window.removeEventListener('navigate', this._onRouteChange);
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

    if (!route.public) {
      if (!authService.isAuthenticated()) {
        this._navigate('/login');
        return;
      }

      if (!authService.hasValidSession() || !authService.hasAdminAccess()) {
        authService.clearSession();
        this._navigate('/login');
        return;
      }
    }

    if (
      route.public
      && route.path === '/login'
      && authService.isAuthenticated()
      && authService.hasValidSession()
      && authService.hasAdminAccess()
    ) {
      this._navigate('/');
      return;
    }

    this.innerHTML = '';
    const el = document.createElement(route.component);
    el.params = params;
    this.appendChild(el);
    this._focusRouteContent(el);
  }

  _focusRouteContent(routeElement) {
    requestAnimationFrame(() => {
      if (!routeElement?.isConnected) return;

      const pageLayout = routeElement.shadowRoot?.querySelector('c-page-layout');
      if (pageLayout && typeof pageLayout.focusPageContent === 'function') {
        pageLayout.focusPageContent({ preventScroll: true });
        return;
      }

      const fallback = routeElement.shadowRoot?.querySelector('[data-page-focus], h1, h2, [tabindex]');
      if (fallback instanceof HTMLElement) {
        if (!fallback.hasAttribute('tabindex')) {
          fallback.setAttribute('tabindex', '-1');
        }
        fallback.focus({ preventScroll: true });
        return;
      }

      if (routeElement instanceof HTMLElement) {
        if (!routeElement.hasAttribute('tabindex')) {
          routeElement.setAttribute('tabindex', '-1');
        }
        routeElement.focus({ preventScroll: true });
      }
    });
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
