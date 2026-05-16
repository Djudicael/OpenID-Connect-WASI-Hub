import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { authService } from '../auth/auth-service.js';

class LoginPage extends BaseComponent {
  constructor() {
    super();
    this._state = { error: null, loading: false, mode: 'password', realm: 'master' };
  }

  connectedCallback() {
    super.connectedCallback();
    // Handle OIDC callback
    if (window.location.pathname === '/callback' || window.location.pathname === '/admin/callback' || window.location.search.includes('code=')) {
      this._handleCallback();
    }
  }

  async _handleCallback() {
    this.setState({ loading: true, error: null });
    try {
      await authService.handleCallback();
      window.location.href = '/';
    } catch (err) {
      this.setState({ error: err.message, loading: false });
    }
  }

  async _loginWithPassword(e) {
    e.preventDefault();
    const email = this.shadowRoot.querySelector('#email').value;
    const password = this.shadowRoot.querySelector('#password').value;
    const realm = this._state.realm || 'master';

    this.setState({ loading: true, error: null });
    try {
      await authService.loginWithPassword(email, password, realm);
      window.location.href = '/';
    } catch (err) {
      this.setState({ error: err.message || 'Login failed', loading: false });
    }
  }

  _togglePassword(e) {
    const input = this.shadowRoot.querySelector('#password');
    if (!input) return;
    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';
    const btn = e.currentTarget;
    btn.textContent = isPassword ? '\u{1F576}' : '\u{1F441}';
  }

  _toggleMode() {
    this.setState({ mode: this._state.mode === 'password' ? 'oidc' : 'password', error: null });
  }

  template() {
    const { error, loading, mode, realm } = this._state;
    return html`
      <div class="login-box">
        <h1 class="login-title">OpenID Connect Hub</h1>
        <p class="login-subtitle">Admin Console</p>

        ${mode === 'password' ? html`
          <form class="login-form" @submit=${(e) => this._loginWithPassword(e)}>
            <div class="form-group">
              <label for="realm">Realm</label>
              <select id="realm" .value=${realm} @change=${(e) => this.setState({ realm: e.target.value })} ?disabled=${loading}>
                <option value="master">master</option>
              </select>
            </div>
            <div class="form-group">
              <label for="email">Email</label>
              <input id="email" type="email" placeholder="you@example.com" required ?disabled=${loading} />
            </div>
            <div class="form-group">
              <label for="password">Password</label>
              <div class="password-wrap">
                <input id="password" type="password" placeholder="••••••••" required ?disabled=${loading} />
                <button type="button" class="toggle-password" @click=${(e) => this._togglePassword(e)}
                  aria-label="Toggle password visibility">
                  &#128065;
                </button>
              </div>
            </div>
            <button class="login-btn" type="submit" ?disabled=${loading}>
              ${loading ? 'Signing in...' : 'Sign In'}
            </button>
          </form>

        ` : html`
          <button class="login-btn" ?disabled=${loading} @click=${() => authService.login()}>
            ${loading ? 'Redirecting...' : 'Sign in with OIDC'}
          </button>
        `}

        <div class="divider">or</div>

        <button class="toggle-link" @click=${() => this._toggleMode()}>
          ${mode === 'password' ? 'Sign in with OIDC instead' : 'Sign in with password instead'}
        </button>

        ${error ? html`<div class="error">${error}</div>` : ''}
      </div>
    `;
  }
}

customElements.define('login-page', LoginPage);
