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
        const parts = token.id_token.split('.');
        if (parts.length !== 3) {
          this.setState({ user: null });
          return;
        }
        const payload = JSON.parse(atob(parts[1]));
        // Validate expiration claim
        if (payload.exp && payload.exp * 1000 < Date.now()) {
          this.setState({ user: null });
          return;
        }
        this.setState({ user: payload });
      } catch {
        this.setState({ user: null });
      }
    }
  }

  template() {
    const user = this._state.user;
    return html`
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
