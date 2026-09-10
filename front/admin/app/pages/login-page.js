import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { authService } from '../auth/auth-service.js';

class LoginPage extends BaseComponent {
  constructor() {
    super();
    const query = new URLSearchParams(window.location.search);
    this._returnTo = query.get('return_to');
    this._continueTo = query.get('continue_to');
    this._initialActionToken = query.get('action_token');
    try {
      const request = this._returnTo ? new URL(this._returnTo, window.location.origin) : null;
      this._authContext = request ? {
        client_id: request.searchParams.get('client_id') || 'admin-ui',
        requested_scopes: (request.searchParams.get('scope') || '').split(' ').filter(Boolean),
        requested_acr_values: (request.searchParams.get('acr_values') || '').split(' ').filter(Boolean),
      } : {};
    } catch { this._authContext = {}; }
    this._state = { error: null, loading: false, mode: 'password', realm: query.get('realm') || 'master', mfa: null, mfaMethod: null, actions: null, totpSetup: null };
    this._primary = null;
  }

  _finishNavigation() {
    if (this._returnTo) { window.location.href = this._returnTo; return; }
    window.location.href = authService.hasAdminAccess() ? '/' : '/account';
  }

  connectedCallback() {
    super.connectedCallback();
    if (this._initialActionToken) this._loadRequiredActions(this._initialActionToken);
    // Handle OIDC callback
    if (window.location.pathname === '/callback' || window.location.pathname === '/admin/callback' || window.location.search.includes('code=')) {
      this._handleCallback();
    }
  }

  async _loadRequiredActions(actionToken) {
    this.setState({loading:true,error:null});
    try {
      const status=await authService.requiredAction('status',{action_token:actionToken});
      if(status.complete){if(this._continueTo)window.location.href=this._continueTo;return;}
      this._primary={email:status.user_email,password:null,realm:status.realm};
      this.setState({loading:false,actions:{...status,action_token:actionToken,required_actions_pending:true}});
    } catch(err){this.setState({loading:false,error:err.message});}
  }

  async _handleCallback() {
    this.setState({ loading: true, error: null });
    try {
      await authService.handleCallback();
      this._finishNavigation();
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
      const result = await authService.loginWithPassword(email, password, realm, null, this._authContext);
      this._primary = { email, password, realm };
      if (result.mfa_required) {
        const methods = result.challenge.methods;
        this.setState({ loading: false, mfa: result.challenge, mfaMethod: methods.includes('webauthn') ? 'webauthn' : methods[0] });
        if (methods.includes('webauthn')) await this._completePasskey();
        return;
      }
      if (result.required_actions_pending) {
        this.setState({ loading: false, actions: result, mfa: null });
        return;
      }
      this._primary = null;
      this._finishNavigation();
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
      const result = await authService.loginWithPassword(this._primary.email, this._primary.password, this._primary.realm, { ceremony_token: this._state.mfa.ceremony_token, ...proof }, this._authContext);
      if (result.mfa_required) throw new Error('A new MFA challenge was requested');
      if (result.required_actions_pending) { this.setState({ loading:false,mfa:null,actions:result }); return; }
      this._primary = null; this._finishNavigation();
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

  async _applyAction(path, payload = {}, nextPassword = null) {
    const actionToken = this._state.actions.action_token;
    this.setState({ loading:true,error:null });
    try {
      const status = await authService.requiredAction(path,{ action_token:actionToken,...payload });
      if (nextPassword) this._primary.password = nextPassword;
      if (status.complete) {
        if (this._continueTo) { window.location.href=this._continueTo; return; }
        const result = await authService.loginWithPassword(this._primary.email,this._primary.password,this._primary.realm,null,this._authContext);
        if (result.mfa_required) {
          const methods=result.challenge.methods;
          this.setState({loading:false,actions:null,mfa:result.challenge,mfaMethod:methods.includes('webauthn')?'webauthn':methods[0]});
          if(methods.includes('webauthn')) await this._completePasskey();
        } else if (result.required_actions_pending) this.setState({loading:false,actions:result});
        else this._finishNavigation();
      } else this.setState({loading:false,actions:{...this._state.actions,...status}});
    } catch(err) { this.setState({loading:false,error:err.message}); }
  }

  _currentAction() { return this._state.actions?.required_actions?.[0]; }

  async _submitRequiredAction(e) {
    e.preventDefault();
    const action=this._currentAction();
    if(action==='update_password') {
      const password=this.shadowRoot.querySelector('#action-password').value;
      const confirm=this.shadowRoot.querySelector('#action-password-confirm').value;
      if(password!==confirm){this.setState({error:'Passwords do not match'});return;}
      await this._applyAction('password',{new_password:password},password);
    } else if(action==='update_profile') {
      await this._applyAction('profile',{
        given_name:this.shadowRoot.querySelector('#action-given-name').value,
        family_name:this.shadowRoot.querySelector('#action-family-name').value,
        username:this.shadowRoot.querySelector('#action-username').value||null,
      });
    } else if(action==='accept_terms') {
      const accepted=this.shadowRoot.querySelector('#action-terms').checked;
      await this._applyAction('terms',{version:this._state.actions.terms.version,accepted});
    } else if(action==='verify_email') {
      const token=this.shadowRoot.querySelector('#verification-token').value.trim();
      if(!token){this.setState({error:'Open the verification link from your email, or paste its token here.'});return;}
      const response=await fetch('/oidc/email-verification/confirm',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token})});
      if(!response.ok){this.setState({error:'The verification link is invalid or expired'});return;}
      await this._applyAction('status');
    } else if(action==='configure_mfa') {
      if(!this._state.totpSetup){
        try { const setup=await authService.mfaEnrollment('totp/start',this._state.actions.action_token); this.setState({loading:false,totpSetup:setup,error:null}); }
        catch(err){this.setState({loading:false,error:err.message});}
      } else {
        try {
          const code=this.shadowRoot.querySelector('#action-totp-code').value.trim();
          await authService.mfaEnrollment('totp/finish',this._state.actions.action_token,{ceremony_token:this._state.totpSetup.ceremony_token,code,label:'Authenticator app'});
          this.setState({totpSetup:null}); await this._applyAction('mfa');
        } catch(err){this.setState({loading:false,error:err.message});}
      }
    }
  }

  async _sendVerification() {
    this.setState({loading:true,error:null});
    try {
      await fetch('/oidc/email-verification/request',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:this._state.actions.user_email||this._primary.email,realm:this._state.actions.realm||this._primary.realm})});
      this.setState({loading:false,error:null});
    } catch(err){this.setState({loading:false,error:err.message});}
  }

  _requiredActionTemplate() {
    const action=this._currentAction(); const terms=this._state.actions.terms;
    const titles={update_password:'Choose a new password',verify_email:'Verify your email',update_profile:'Complete your profile',configure_mfa:'Protect your account',accept_terms:'Review the terms'};
    return html`<h2 class="login-title">${titles[action]||'Complete your account'}</h2><p class="login-subtitle">Step 1 of ${this._state.actions.required_actions.length}</p>
      <form class="login-form" @submit=${e=>this._submitRequiredAction(e)}>
      ${action==='update_password'?html`<div class="form-group"><label>New password</label><input id="action-password" type="password" minlength="8" required></div><div class="form-group"><label>Confirm password</label><input id="action-password-confirm" type="password" required></div>`:''}
      ${action==='update_profile'?html`<div class="form-group"><label>First name</label><input id="action-given-name" required></div><div class="form-group"><label>Last name</label><input id="action-family-name" required></div><div class="form-group"><label>Username</label><input id="action-username"></div>`:''}
      ${action==='verify_email'?html`<p>We will send a verification link to <strong>${this._state.actions.user_email||this._primary.email}</strong>.</p><button type="button" class="toggle-link" @click=${()=>this._sendVerification()}>Send verification email</button><div class="form-group"><label>Verification token</label><input id="verification-token"></div>`:''}
      ${action==='accept_terms'?html`<div class="terms-box">${terms?.text||'Please accept the current terms of service.'}</div><label class="checkbox-row"><input id="action-terms" type="checkbox" required> I have read and accept these terms</label>`:''}
      ${action==='configure_mfa'?(this._state.totpSetup?html`<p>Add this secret to your authenticator app:</p><code class="setup-secret">${this._state.totpSetup.secret}</code><div class="form-group"><label>6-digit code</label><input id="action-totp-code" inputmode="numeric" autocomplete="one-time-code" required></div>`:html`<p>Set up an authenticator app to continue. Recovery codes will be created when enrollment finishes.</p>`):''}
      <button class="login-btn" type="submit" ?disabled=${this._state.loading}>${this._state.loading?'Saving...':action==='configure_mfa'&&!this._state.totpSetup?'Start setup':'Continue'}</button></form>`;
  }

  template() {
    const { error, loading, mode, realm, mfa, mfaMethod, actions } = this._state;
    return html`
      <div class="login-box">
        ${actions?this._requiredActionTemplate():html`<h1 class="login-title">OpenID Connect Hub</h1><p class="login-subtitle">Account and administration console</p>`}

        ${actions?'':mfa ? html`
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

        ${!mfa && !actions ? html`<div class="divider">or</div>

        <button class="toggle-link" @click=${() => this._toggleMode()}>
          ${mode === 'password' ? 'Sign in with OIDC instead' : 'Sign in with password instead'}
        </button>` : ''}

        ${error ? html`<div class="error">${error}</div>` : ''}
      </div>
    `;
  }
}

customElements.define('login-page', LoginPage);
