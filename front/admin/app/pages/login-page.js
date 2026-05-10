import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { authService } from '../auth/auth-service.js';

class LoginPage extends BaseComponent {
  constructor() {
    super();
    this._state = { error: null, loading: false, mode: 'password' };
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

    this.setState({ loading: true, error: null });
    try {
      await authService.loginWithPassword(email, password);
      window.location.href = '/';
    } catch (err) {
      this.setState({ error: err.message || 'Login failed', loading: false });
    }
  }

  _toggleMode() {
    this.setState({ mode: this._state.mode === 'password' ? 'oidc' : 'password', error: null });
  }

  template() {
    const { error, loading, mode } = this._state;
    return html`
      <style>
        :host { display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .login-box {
          background: var(--color-surface);
          padding: 2.5rem;
          border-radius: var(--radius-md);
          box-shadow: var(--shadow-md);
          width: 100%;
          max-width: 24rem;
          text-align: center;
        }
        .login-title {
          font-size: 1.5rem;
          font-weight: 600;
          margin-bottom: 0.5rem;
        }
        .login-subtitle {
          color: var(--color-text-muted);
          margin-bottom: 1.5rem;
          font-size: 0.875rem;
        }
        .login-form {
          display: flex;
          flex-direction: column;
          gap: 1rem;
          margin-bottom: 1rem;
        }
        .form-group {
          text-align: left;
        }
        .form-group label {
          display: block;
          font-size: 0.875rem;
          font-weight: 500;
          margin-bottom: 0.25rem;
          color: var(--color-text);
        }
        .form-group input {
          width: 100%;
          padding: 0.625rem;
          border: 1px solid var(--color-border);
          border-radius: var(--radius-sm);
          font-size: 0.875rem;
          background: var(--color-bg);
          color: var(--color-text);
          box-sizing: border-box;
        }
        .form-group input:focus {
          outline: none;
          border-color: var(--color-primary);
          box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.1);
        }
        .login-btn {
          width: 100%;
          padding: 0.75rem;
          font-size: 1rem;
          font-weight: 500;
          background: var(--color-primary);
          color: #fff;
          border: none;
          border-radius: var(--radius-sm);
          cursor: pointer;
        }
        .login-btn:hover { background: var(--color-primary-dark); }
        .login-btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .divider {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          margin: 1rem 0;
          color: var(--color-text-muted);
          font-size: 0.75rem;
        }
        .divider::before, .divider::after {
          content: '';
          flex: 1;
          height: 1px;
          background: var(--color-border);
        }
        .oidc-btn {
          width: 100%;
          padding: 0.75rem;
          font-size: 0.875rem;
          font-weight: 500;
          background: var(--color-surface);
          color: var(--color-text);
          border: 1px solid var(--color-border);
          border-radius: var(--radius-sm);
          cursor: pointer;
        }
        .oidc-btn:hover { background: var(--color-bg); }
        .toggle-link {
          color: var(--color-primary);
          font-size: 0.875rem;
          cursor: pointer;
          background: none;
          border: none;
          text-decoration: underline;
        }
        .error {
          color: var(--color-danger);
          font-size: 0.875rem;
          margin-top: 1rem;
          padding: 0.75rem;
          background: #fef2f2;
          border-radius: var(--radius-sm);
        }
        .hint {
          color: var(--color-text-muted);
          font-size: 0.75rem;
          margin-top: 0.5rem;
        }
      </style>
      <div class="login-box">
        <h1 class="login-title">OpenID Connect Hub</h1>
        <p class="login-subtitle">Admin Console</p>

        ${mode === 'password' ? html`
          <form class="login-form" @submit=${(e) => this._loginWithPassword(e)}>
            <div class="form-group">
              <label for="email">Email</label>
              <input id="email" type="email" placeholder="you@example.com" required ?disabled=${loading} />
            </div>
            <div class="form-group">
              <label for="password">Password</label>
              <input id="password" type="password" placeholder="••••••••" required ?disabled=${loading} />
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
