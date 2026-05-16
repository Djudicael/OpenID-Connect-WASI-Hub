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
