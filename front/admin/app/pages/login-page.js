import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { authService } from '../auth/auth-service.js';

class LoginPage extends BaseComponent {
  constructor() {
    super();
    this._state = { error: null, loading: false, mode: 'password', realm: 'master', mfa: null, mfaMethod: null };
    this._primary = null;
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
      window.location.href = authService.hasAdminAccess() ? '/' : '/account';
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
      const result = await authService.loginWithPassword(email, password, realm);
      if (result.mfa_required) {
        this._primary = { email, password, realm };
        const methods = result.challenge.methods;
        this.setState({ loading: false, mfa: result.challenge, mfaMethod: methods.includes('webauthn') ? 'webauthn' : methods[0] });
        if (methods.includes('webauthn')) await this._completePasskey();
        return;
      }
      window.location.href = authService.hasAdminAccess() ? '/' : '/account';
    } catch (err) {
      this.setState({ error: err.message || 'Login failed', loading: false });
    }
  }

  _b64urlToBytes(value) {
    const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
    return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
  }

  _bytesToB64url(value) {
    let binary = ''; for (const byte of new Uint8Array(value)) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  async _completePasskey() {
    const options = structuredClone(this._state.mfa.webauthn);
    options.challenge = this._b64urlToBytes(options.challenge);
    options.allowCredentials = (options.allowCredentials || []).map(c => ({ ...c, id: this._b64urlToBytes(c.id) }));
    this.setState({ loading: true, error: null, mfaMethod: 'webauthn' });
    try {
      const credential = await navigator.credentials.get({ publicKey: options });
      await this._finishMfa({ webauthn_response: {
        id: credential.id,
        authenticatorData: this._bytesToB64url(credential.response.authenticatorData),
        signature: this._bytesToB64url(credential.response.signature),
        clientDataJSON: this._bytesToB64url(credential.response.clientDataJSON),
        userHandle: credential.response.userHandle ? this._bytesToB64url(credential.response.userHandle) : null,
      }});
    } catch (err) { this.setState({ loading: false, error: err.message || 'Passkey verification was cancelled' }); }
  }

  async _submitMfa(e) {
    e.preventDefault();
    const value = this.shadowRoot.querySelector('#mfa-code')?.value?.trim();
    if (!value) return;
    await this._finishMfa(this._state.mfaMethod === 'recovery_code' ? { recovery_code: value } : { totp_code: value });
  }

  async _finishMfa(proof) {
    this.setState({ loading: true, error: null });
    try {
      const result = await authService.loginWithPassword(this._primary.email, this._primary.password, this._primary.realm, { ceremony_token: this._state.mfa.ceremony_token, ...proof });
      if (result.mfa_required) throw new Error('A new MFA challenge was requested');
      this._primary = null; window.location.href = authService.hasAdminAccess() ? '/' : '/account';
    } catch (err) { this.setState({ loading: false, error: err.message || 'Verification failed' }); }
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
    const { error, loading, mode, realm, mfa, mfaMethod } = this._state;
    return html`
      <div class="login-box">
        <h1 class="login-title">OpenID Connect Hub</h1>
        <p class="login-subtitle">Account and administration console</p>

        ${mfa ? html`
          <p class="login-subtitle">Complete your sign in with a second factor.</p>
          <div class="mfa-methods">
            ${mfa.methods.includes('webauthn') ? html`<button class="toggle-link" @click=${() => this._completePasskey()} ?disabled=${loading}>Use a passkey</button>` : ''}
            ${mfa.methods.includes('totp') ? html`<button class="toggle-link" @click=${() => this.setState({mfaMethod:'totp',error:null})}>Authenticator code</button>` : ''}
            ${mfa.methods.includes('recovery_code') ? html`<button class="toggle-link" @click=${() => this.setState({mfaMethod:'recovery_code',error:null})}>Recovery code</button>` : ''}
          </div>
          ${mfaMethod !== 'webauthn' ? html`<form class="login-form" @submit=${e=>this._submitMfa(e)}>
            <div class="form-group"><label for="mfa-code">${mfaMethod === 'recovery_code' ? 'Recovery code' : '6-digit code'}</label><input id="mfa-code" autocomplete="one-time-code" required ?disabled=${loading}></div>
            <button class="login-btn" type="submit" ?disabled=${loading}>${loading?'Verifying...':'Verify'}</button>
          </form>` : html`<p class="login-subtitle">Follow your browser’s passkey prompt.</p>`}
        ` : mode === 'password' ? html`
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

        ${!mfa ? html`<div class="divider">or</div>

        <button class="toggle-link" @click=${() => this._toggleMode()}>
          ${mode === 'password' ? 'Sign in with OIDC instead' : 'Sign in with password instead'}
        </button>` : ''}

        ${error ? html`<div class="error">${error}</div>` : ''}
      </div>
    `;
  }
}

customElements.define('login-page', LoginPage);
