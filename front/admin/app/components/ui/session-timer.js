import { html } from 'lit-html';
import { BaseComponent } from '../../core/component.js';
import { authService } from '../../auth/auth-service.js';

class SessionTimer extends BaseComponent {
  constructor() {
    super();
    this._state = {
      expiresIn: 0,
      warning: false,
      expired: false
    };
    this._interval = null;
  }

  connectedCallback() {
    super.connectedCallback();
    this._checkSession();
    this._interval = setInterval(() => this._checkSession(), 30000); // Check every 30s
  }

  disconnectedCallback() {
    if (this._interval) clearInterval(this._interval);
  }

  _checkSession() {
    const tokens = authService.tokens;
    if (!tokens || !tokens.expires_at) {
      this.setState({ expiresIn: 0, warning: false, expired: true });
      return;
    }
    const remaining = tokens.expires_at - Date.now();
    const minutesLeft = Math.floor(remaining / 60000);

    if (remaining <= 0) {
      this.setState({ expiresIn: 0, warning: false, expired: true });
    } else if (minutesLeft <= 5) {
      this.setState({ expiresIn: minutesLeft, warning: true, expired: false });
    } else {
      this.setState({ expiresIn: minutesLeft, warning: false, expired: false });
    }
  }

  template() {
    const { expiresIn, warning, expired } = this._state;

    if (expired) {
      return html`
        <style>
          :host { display: block; }
          .session-expired {
            background: #fef2f2;
            border: 1px solid #fecaca;
            color: #991b1b;
            padding: 0.75rem 1rem;
            border-radius: var(--radius-sm);
            font-size: 0.875rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 1rem;
          }
          .refresh-btn {
            padding: 0.375rem 0.75rem;
            background: var(--color-primary);
            color: #fff;
            border: none;
            border-radius: var(--radius-sm);
            cursor: pointer;
            font-size: 0.8125rem;
            white-space: nowrap;
          }
        </style>
        <div class="session-expired">
          <span>Your session has expired.</span>
          <button class="refresh-btn" @click=${() => window.location.reload()}>Refresh</button>
        </div>
      `;
    }

    if (warning) {
      return html`
        <style>
          :host { display: block; }
          .session-warning {
            background: #fffbeb;
            border: 1px solid #fde68a;
            color: #92400e;
            padding: 0.75rem 1rem;
            border-radius: var(--radius-sm);
            font-size: 0.875rem;
          }
        </style>
        <div class="session-warning">
          Your session will expire in ${expiresIn} minute${expiresIn !== 1 ? 's' : ''}.
          Save your work and refresh to extend your session.
        </div>
      `;
    }

    return html``;
  }
}

customElements.define('c-session-timer', SessionTimer);
