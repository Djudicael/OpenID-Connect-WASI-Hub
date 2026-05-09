import { html } from 'lit-html';
import { BaseComponent } from '../../core/component.js';
import { authService } from '../../auth/auth-service.js';
import { navigate } from '../../core/router.js';

class Header extends BaseComponent {
  constructor() {
    super();
    this._state = { user: null };
  }

  connectedCallback() {
    super.connectedCallback();
    this._updateUser();
  }

  _updateUser() {
    const token = authService.tokens;
    if (token && token.id_token) {
      try {
        const payload = JSON.parse(atob(token.id_token.split('.')[1]));
        this.setState({ user: payload });
      } catch {
        this.setState({ user: null });
      }
    }
  }

  template() {
    const user = this._state.user;
    return html`
      <style>
        :host {
          display: block;
        }
        .header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 0 1.5rem;
          height: 3.5rem;
          background: var(--color-surface);
          border-bottom: 1px solid #e2e8f0;
          position: sticky;
          top: 0;
          z-index: 10;
        }
        .header-title {
          font-size: 1.125rem;
          font-weight: 600;
          color: var(--color-text);
        }
        .header-actions {
          display: flex;
          align-items: center;
          gap: 1rem;
        }
        .user-name {
          font-size: 0.875rem;
          color: var(--color-text-muted);
        }
        .logout-btn {
          padding: 0.375rem 0.75rem;
          font-size: 0.875rem;
          background: transparent;
          border: 1px solid #e2e8f0;
          border-radius: var(--radius-sm);
          cursor: pointer;
          color: var(--color-text);
        }
        .logout-btn:hover {
          background: var(--color-bg);
        }
      </style>
      <header class="header">
        <div class="header-title">OpenID Connect Hub</div>
        <div class="header-actions">
          ${user
        ? html`
                <span class="user-name">${user.name || user.preferred_username || user.email || 'User'}</span>
                <button class="logout-btn" @click=${() => authService.logout()}>Logout</button>
              `
        : html`<button class="logout-btn" @click=${() => navigate('/login')}>Login</button>`}
        </div>
      </header>
    `;
  }
}

customElements.define('c-header', Header);
