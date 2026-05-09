/**
 * OIDC Auth Service — Authorization Code + PKCE.
 */

const STORAGE_KEY = 'oidc_tokens';
const STATE_KEY = 'oidc_state';
const VERIFIER_KEY = 'oidc_code_verifier';

class AuthService {
  constructor() {
    this.config = {
      authority: (typeof window !== 'undefined' && window.__OIDC_AUTHORITY__) || '/oidc',
      client_id: 'admin-ui',
      redirect_uri: `${typeof window !== 'undefined' ? window.location.origin : ''}/callback`,
      response_type: 'code',
      scope: 'openid profile email',
    };
    this.tokens = null;
    this._loadTokens();
  }

  _loadTokens() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        this.tokens = JSON.parse(raw);
      }
    } catch {
      this.tokens = null;
    }
  }

  _saveTokens() {
    if (this.tokens) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this.tokens));
    } else {
      localStorage.removeItem(STORAGE_KEY);
    }
  }

  isAuthenticated() {
    return this.tokens && this.tokens.expires_at > Date.now();
  }

  async getAccessToken() {
    if (!this.tokens) return null;
    if (this.tokens.expires_at - Date.now() < 60000) {
      await this._refresh();
    }
    return this.tokens.access_token;
  }

  async loginWithPassword(email, password) {
    const response = await fetch(`${this.config.authority}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, client_id: this.config.client_id }),
    });

    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.error_description || body.error || `Login failed: ${response.status}`);
    }

    const data = await response.json();
    this.tokens = {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      id_token: data.id_token,
      expires_in: data.expires_in,
      expires_at: Date.now() + data.expires_in * 1000,
    };
    this._saveTokens();
    return data;
  }

  async login() {
    const state = this._randomString(32);
    const { verifier, challenge } = await this._generatePKCE();
    sessionStorage.setItem(STATE_KEY, state);
    sessionStorage.setItem(VERIFIER_KEY, verifier);

    const url = new URL(`${this.config.authority}/authorize`, window.location.origin);
    url.searchParams.set('client_id', this.config.client_id);
    url.searchParams.set('redirect_uri', this.config.redirect_uri);
    url.searchParams.set('response_type', this.config.response_type);
    url.searchParams.set('scope', this.config.scope);
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', challenge);
    url.searchParams.set('code_challenge_method', 'S256');

    window.location.href = url.toString();
  }

  async handleCallback() {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');
    const error = params.get('error');

    if (error) {
      throw new Error(`OIDC error: ${error}`);
    }

    if (!code || !state) {
      throw new Error('Missing code or state parameter');
    }

    const savedState = sessionStorage.getItem(STATE_KEY);
    if (state !== savedState) {
      throw new Error('Invalid state parameter');
    }

    const verifier = sessionStorage.getItem(VERIFIER_KEY);
    if (!verifier) {
      throw new Error('Missing code verifier');
    }

    const response = await fetch(`${this.config.authority}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: this.config.redirect_uri,
        client_id: this.config.client_id,
        code_verifier: verifier,
      }),
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`Token exchange failed: ${response.status} ${body}`);
    }

    this.tokens = await response.json();
    this.tokens.expires_at = Date.now() + this.tokens.expires_in * 1000;
    this._saveTokens();

    sessionStorage.removeItem(STATE_KEY);
    sessionStorage.removeItem(VERIFIER_KEY);

    window.history.replaceState({}, '', '/');
  }

  async _refresh() {
    if (!this.tokens || !this.tokens.refresh_token) return;

    const response = await fetch(`${this.config.authority}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: this.tokens.refresh_token,
        client_id: this.config.client_id,
      }),
    });

    if (!response.ok) {
      this.logout();
      throw new Error('Token refresh failed');
    }

    this.tokens = await response.json();
    this.tokens.expires_at = Date.now() + this.tokens.expires_in * 1000;
    this._saveTokens();
  }

  logout() {
    this.tokens = null;
    localStorage.removeItem(STORAGE_KEY);
    const redirect = encodeURIComponent(window.location.origin);
    window.location.href = `${this.config.authority}/logout?post_logout_redirect_uri=${redirect}`;
  }

  _randomString(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    let result = '';
    const randomValues = new Uint8Array(length);
    crypto.getRandomValues(randomValues);
    for (let i = 0; i < length; i++) {
      result += chars[randomValues[i] % chars.length];
    }
    return result;
  }

  async _generatePKCE() {
    const verifier = this._randomString(128);
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const digest = await crypto.subtle.digest('SHA-256', data);
    const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    return { verifier, challenge };
  }
}

export const authService = new AuthService();
