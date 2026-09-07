import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { authService } from '../auth/auth-service.js';
import { showToast } from '../components/ui/toast.js';
import { handleApiError } from '../utils/error-handler.js';
import {
  changePassword, getAccount, listAccountSessions, listApplications,
  listLinkedIdentities, revokeAccountSession, revokeApplication,
  unlinkIdentity, updateAccount,
} from '../services/account-service.js';

const PROFILE_FIELDS = [
  ['username', 'Username'], ['given_name', 'First name'], ['middle_name', 'Middle name'],
  ['family_name', 'Last name'], ['nickname', 'Nickname'],
  ['preferred_username', 'Preferred username'], ['phone_number', 'Phone number'],
  ['locale', 'Language'], ['zoneinfo', 'Time zone'], ['website', 'Website'],
  ['picture', 'Picture URL'], ['birthdate', 'Birthdate'], ['street_address', 'Street address'],
  ['locality', 'City'], ['region', 'Region'], ['postal_code', 'Postal code'], ['country', 'Country'],
];

class AccountPage extends BaseComponent {
  constructor() {
    super();
    this._state = { loading: true, profile: null, sessions: [], identities: [], applications: [], section: 'profile' };
  }

  connectedCallback() { super.connectedCallback(); this._load(); }

  async _load() {
    this.setState({ loading: true });
    try {
      const [profile, sessions, identities, applications] = await Promise.all([
        getAccount(this.signal), listAccountSessions(this.signal),
        listLinkedIdentities(this.signal), listApplications(this.signal),
      ]);
      authService.setAdministrationAccess(profile.administration_access);
      this.setState({ profile, sessions: sessions.items || [], identities: identities.items || [], applications: applications.items || [], loading: false });
    } catch (error) {
      if (error.name !== 'AbortError') handleApiError(error, 'Could not load your account');
      this.setState({ loading: false });
    }
  }

  _field(name, value) {
    this.setState({ profile: { ...this._state.profile, [name]: value } });
  }

  async _saveProfile(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const body = Object.fromEntries(new FormData(form));
    try {
      const profile = await updateAccount(body);
      this.setState({ profile });
      showToast('Profile saved', 'success');
    } catch (error) { handleApiError(error, 'Could not save your profile'); }
  }

  async _changePassword(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const body = Object.fromEntries(new FormData(form));
    if (body.new_password !== body.confirm_password) {
      showToast('The new passwords do not match', 'error'); return;
    }
    delete body.confirm_password;
    try {
      await changePassword(body);
      form.reset();
      showToast('Password changed and other sessions signed out', 'success');
      await this._load();
    } catch (error) { handleApiError(error, 'Could not change your password'); }
  }

  async _revokeSession(session) {
    if (!confirm('Sign out this session?')) return;
    try {
      const result = await revokeAccountSession(session.id);
      if (result.current) { authService.logout(); return; }
      showToast('Session signed out', 'success'); await this._load();
    } catch (error) { handleApiError(error, 'Could not sign out the session'); }
  }

  async _unlink(identity) {
    if (!confirm(`Unlink ${identity.provider}?`)) return;
    try { await unlinkIdentity(identity.id); showToast('Sign-in method unlinked', 'success'); await this._load(); }
    catch (error) { handleApiError(error, 'Could not unlink the sign-in method'); }
  }

  async _revokeApplication(application) {
    if (!confirm(`Remove access for ${application.name}? Its active sessions will be signed out.`)) return;
    try { await revokeApplication(application.id); showToast('Application access removed', 'success'); await this._load(); }
    catch (error) { handleApiError(error, 'Could not remove application access'); }
  }

  _nav() {
    const sections = [['profile', 'Profile'], ['password', 'Password'], ['sessions', 'Sessions'], ['applications', 'Applications'], ['identities', 'Linked identities']];
    return html`<nav class="account-tabs" aria-label="Account sections">${sections.map(([id, label]) => html`<button class=${this._state.section === id ? 'active' : ''} @click=${() => this.setState({ section: id })}>${label}</button>`)}<a href="/security">Sign-in security</a></nav>`;
  }

  _profile() {
    const profile = this._state.profile;
    return html`<section class="card account-card"><h2>Personal information</h2><p>Keep the information shared with approved applications up to date.</p>
      <form class="account-form" @submit=${event => this._saveProfile(event)}>
        <div class="field"><label class="field-label" for="account-email">Email</label><input class="field-input" id="account-email" name="email" type="email" .value=${profile.email || ''}></div>
        <div class="field"><label class="field-label" for="account-current-password">Current password <span class="hint">required when changing email</span></label><input class="field-input" id="account-current-password" name="current_password" type="password" autocomplete="current-password"></div>
        ${PROFILE_FIELDS.map(([name, label]) => html`<div class="field"><label class="field-label" for=${`account-${name}`}>${label}</label><input class="field-input" id=${`account-${name}`} name=${name} .value=${profile[name] || ''}></div>`)}
        <div class="account-actions"><button class="btn btn--primary" type="submit">Save profile</button></div>
      </form></section>`;
  }

  _password() {
    return html`<section class="card account-card"><h2>Change password</h2>${this._state.profile.has_password ? html`<p>Changing your password signs out every other session.</p><form class="account-form narrow" @submit=${event => this._changePassword(event)}><div class="field"><label class="field-label">Current password</label><input class="field-input" name="current_password" type="password" autocomplete="current-password" required></div><div class="field"><label class="field-label">New password</label><input class="field-input" name="new_password" type="password" autocomplete="new-password" minlength="8" required></div><div class="field"><label class="field-label">Confirm new password</label><input class="field-input" name="confirm_password" type="password" autocomplete="new-password" minlength="8" required></div><div class="account-actions"><button class="btn btn--primary" type="submit">Change password</button></div></form>` : html`<p>This account signs in through an external identity provider and has no local password.</p>`}</section>`;
  }

  _sessions() {
    return html`<section class="card account-card"><h2>Active sessions</h2><p>Sign out devices or browsers you no longer use.</p><div class="account-list">${this._state.sessions.length ? this._state.sessions.map(session => html`<article><div><strong>${session.client_name}</strong>${session.current ? html` <span class="badge success">Current session</span>` : ''}<p>Started ${new Date(session.created_at).toLocaleString()} · ${session.authentication_methods.join(', ')}</p></div><button class="btn btn--danger btn--sm" @click=${() => this._revokeSession(session)}>Sign out</button></article>`) : html`<p>No active sessions.</p>`}</div></section>`;
  }

  _applications() {
    return html`<section class="card account-card"><h2>Approved applications</h2><p>Review applications that can access your account information.</p><div class="account-list">${this._state.applications.length ? this._state.applications.map(app => html`<article><div><strong>${app.name}</strong><p>${app.scopes.join(', ')} · ${app.active_sessions} active session(s)</p></div><button class="btn btn--danger btn--sm" @click=${() => this._revokeApplication(app)}>Remove access</button></article>`) : html`<p>No applications have approved access.</p>`}</div></section>`;
  }

  _identities() {
    return html`<section class="card account-card"><h2>Linked identities</h2><p>External accounts that can be used to sign in.</p><div class="account-list">${this._state.identities.length ? this._state.identities.map(identity => html`<article><div><strong>${identity.provider}</strong><p>${identity.email || identity.username || 'Linked account'}</p></div><button class="btn btn--danger btn--sm" @click=${() => this._unlink(identity)}>Unlink</button></article>`) : html`<p>No external identities are linked.</p>`}</div></section>`;
  }

  template() {
    const { loading, profile, section } = this._state;
    return html`<c-page-layout title="My account">${loading || !profile ? html`<p>Loading your account...</p>` : html`${this._nav()}${section === 'profile' ? this._profile() : section === 'password' ? this._password() : section === 'sessions' ? this._sessions() : section === 'applications' ? this._applications() : this._identities()}`}</c-page-layout>`;
  }
}

customElements.define('account-page', AccountPage);
