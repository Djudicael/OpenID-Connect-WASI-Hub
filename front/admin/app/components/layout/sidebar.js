import { html } from 'lit-html';
import { BaseComponent } from '../../core/component.js';

const links = [
  { path: '/', label: 'Dashboard' },
  { path: '/users', label: 'Users' },
  { path: '/roles', label: 'Roles' },
  { path: '/groups', label: 'Groups' },
  { path: '/clients', label: 'Clients' },
  { path: '/realms', label: 'Realms' },
  // TODO: Add when backend admin CRUD endpoints exist for identity providers
  // { path: '/identity-providers', label: 'Identity Providers' },
  { path: '/password-policies', label: 'Password Policies' },
  { path: '/sessions', label: 'Sessions' },
  { path: '/api-keys', label: 'API Keys' },
  { path: '/scopes', label: 'Scopes' },
  { path: '/audit', label: 'Audit' },
  { path: '/maintenance', label: 'Maintenance' },
];

class Sidebar extends BaseComponent {
  constructor() {
    super();
    this._state = { currentPath: window.location.pathname };
  }

  connectedCallback() {
    super.connectedCallback();
    this._onPopState = () => this.setState({ currentPath: window.location.pathname });
    window.addEventListener('popstate', this._onPopState);
    window.addEventListener('navigate', this._onPopState);
  }

  disconnectedCallback() {
    window.removeEventListener('popstate', this._onPopState);
    window.removeEventListener('navigate', this._onPopState);
  }

  _navigate(e, path) {
    e.preventDefault();
    window.history.pushState({}, '', path);
    window.dispatchEvent(new Event('navigate'));
  }

  template() {
    const current = this._state.currentPath;
    return html`
      <style>
        :host { display: block; }
        .sidebar {
          width: 14rem;
          background: var(--color-surface);
          border-right: 1px solid #e2e8f0;
          min-height: 100vh;
          padding: 1rem 0;
        }
        .sidebar-brand {
          padding: 0 1.25rem 1rem;
          font-size: 1rem;
          font-weight: 700;
          color: var(--color-primary);
          letter-spacing: -0.01em;
        }
        .sidebar-nav {
          list-style: none;
          margin: 0;
          padding: 0;
        }
        .sidebar-nav li {
          margin: 0;
        }
        .sidebar-nav a {
          display: block;
          padding: 0.625rem 1.25rem;
          color: var(--color-text-muted);
          text-decoration: none;
          font-size: 0.875rem;
          font-weight: 500;
          border-left: 3px solid transparent;
          transition: all 0.15s;
        }
        .sidebar-nav a:hover {
          color: var(--color-text);
          background: #f8fafc;
        }
        .sidebar-nav a.active {
          color: var(--color-primary);
          background: #eff6ff;
          border-left-color: var(--color-primary);
        }
      </style>
      <nav class="sidebar">
        <div class="sidebar-brand">OIDC Hub</div>
        <ul class="sidebar-nav">
          ${links.map(link => html`
            <li>
              <a
                href=${link.path}
                class=${link.path === current || (link.path !== '/' && current.startsWith(link.path)) ? 'active' : ''}
                @click=${(e) => this._navigate(e, link.path)}
              >${link.label}</a>
            </li>
          `)}
        </ul>
      </nav>
    `;
  }
}

customElements.define('c-sidebar', Sidebar);
