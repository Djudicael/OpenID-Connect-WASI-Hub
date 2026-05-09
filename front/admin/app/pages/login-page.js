import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { authService } from '../auth/auth-service.js';

class LoginPage extends BaseComponent {
  constructor() {
    super();
    this._state = { error: null, loading: false };
  }

  connectedCallback() {
    super.connectedCallback();
    // Handle OIDC callback
    if (window.location.pathname === '/admin/callback' || window.location.search.includes('code=')) {
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

  template() {
    const { error, loading } = this._state;
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
        .error {
          color: var(--color-danger);
          font-size: 0.875rem;
          margin-top: 1rem;
          padding: 0.75rem;
          background: #fef2f2;
          border-radius: var(--radius-sm);
        }
      </style>
      <div class="login-box">
        <h1 class="login-title">OpenID Connect Hub</h1>
        <p class="login-subtitle">Admin Console</p>
        <button class="login-btn" ?disabled=${loading} @click=${() => authService.login()}>
          ${loading ? 'Processing...' : 'Sign in with OIDC'}
        </button>
        ${error ? html`<div class="error">${error}</div>` : ''}
      </div>
    `;
  }
}

customElements.define('login-page', LoginPage);
