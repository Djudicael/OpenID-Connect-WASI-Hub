import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { get, put } from '../core/http.js';
import { navigate } from '../core/router.js';
import { showToast } from '../components/ui/toast.js';

class UserDetailPage extends BaseComponent {
  constructor() {
    super();
    this._state = { user: null, savedUser: null, loading: true, saving: false, dirty: false };
    this._onBeforeUnload = this._onBeforeUnload.bind(this);
  }

  connectedCallback() {
    super.connectedCallback();
    if (this.params && this.params.id) {
      this._loadUser(this.params.id);
    }
    window.addEventListener('beforeunload', this._onBeforeUnload);
  }

  disconnectedCallback() {
    window.removeEventListener('beforeunload', this._onBeforeUnload);
  }

  _onBeforeUnload(e) {
    if (this._state.dirty) {
      e.preventDefault();
      e.returnValue = '';
    }
  }

  get _isDirty() {
    const { user, savedUser } = this._state;
    if (!user || !savedUser) return false;
    return (
      user.email !== savedUser.email ||
      user.email_verified !== savedUser.email_verified ||
      user.username !== savedUser.username ||
      user.given_name !== savedUser.given_name ||
      user.family_name !== savedUser.family_name ||
      user.enabled !== savedUser.enabled
    );
  }

  async _loadUser(id) {
    this.setState({ loading: true });
    try {
      const user = await get(`/api/users/${id}`);
      this.setState({ user, savedUser: { ...user }, loading: false, dirty: false });
    } catch (err) {
      showToast('Failed to load user', 'error');
      this.setState({ loading: false });
    }
  }

  async _save() {
    const user = this._state.user;
    if (!user) return;
    this.setState({ saving: true });
    try {
      await put(`/api/users/${user.id}`, {
        email: user.email,
        email_verified: user.email_verified,
        username: user.username,
        given_name: user.given_name,
        family_name: user.family_name,
        enabled: user.enabled,
      });
      showToast('User updated', 'success');
      this.setState({ saving: false, savedUser: { ...user }, dirty: false });
    } catch (err) {
      showToast('Failed to update user', 'error');
      this.setState({ saving: false });
    }
  }

  _updateField(field, value) {
    const user = { ...this._state.user, [field]: value };
    const savedUser = this._state.savedUser;
    const dirty = (
      user.email !== savedUser.email ||
      user.email_verified !== savedUser.email_verified ||
      user.username !== savedUser.username ||
      user.given_name !== savedUser.given_name ||
      user.family_name !== savedUser.family_name ||
      user.enabled !== savedUser.enabled
    );
    this.setState({ user, dirty });
  }

  _navigateAway(path) {
    if (this._state.dirty) {
      if (!confirm('You have unsaved changes. Are you sure you want to leave?')) {
        return;
      }
    }
    // Remove beforeunload before navigating so it doesn't trigger
    this.setState({ dirty: false });
    navigate(path);
  }

  template() {
    const { user, loading, saving, dirty } = this._state;
    return html`
      <style>
        :host { display: block; }
        .back-link {
          display: inline-flex;
          align-items: center;
          gap: 0.25rem;
          color: var(--color-primary);
          text-decoration: none;
          font-size: 0.875rem;
          margin-bottom: 1rem;
          cursor: pointer;
        }
        .dirty-indicator {
          display: inline-block;
          width: 0.5rem;
          height: 0.5rem;
          border-radius: 50%;
          background: var(--color-warning, #f59e0b);
          margin-left: 0.5rem;
          vertical-align: middle;
        }
        .form { max-width: 32rem; }
        .field { margin-bottom: 1rem; }
        .field-label {
          display: block;
          font-size: 0.875rem;
          font-weight: 500;
          margin-bottom: 0.25rem;
        }
        .field-input {
          width: 100%;
          padding: 0.5rem 0.75rem;
          font-size: 0.875rem;
          border: 1px solid #e2e8f0;
          border-radius: var(--radius-sm);
          font-family: inherit;
          box-sizing: border-box;
        }
        .field-input:focus {
          outline: none;
          border-color: var(--color-primary);
        }
        .checkbox-row {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          margin-bottom: 1rem;
        }
        .actions { display: flex; gap: 0.5rem; margin-top: 1.5rem; }
      </style>
      <c-page-layout title="User Details">
        <span class="back-link" @click=${() => this._navigateAway('/users')}>
          &larr; Back to Users
        </span>
        ${loading
        ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>`
        : user
          ? html`
                <div class="form">
                  <div class="field">
                    <label class="field-label">Email</label>
                    <input class="field-input" type="email" .value=${user.email} @input=${(e) => this._updateField('email', e.target.value)} />
                  </div>
                  <div class="field">
                    <label class="field-label">Username</label>
                    <input class="field-input" type="text" .value=${user.username || ''} @input=${(e) => this._updateField('username', e.target.value)} />
                  </div>
                  <div class="field">
                    <label class="field-label">First Name</label>
                    <input class="field-input" type="text" .value=${user.given_name || ''} @input=${(e) => this._updateField('given_name', e.target.value)} />
                  </div>
                  <div class="field">
                    <label class="field-label">Last Name</label>
                    <input class="field-input" type="text" .value=${user.family_name || ''} @input=${(e) => this._updateField('family_name', e.target.value)} />
                  </div>
                  <label class="checkbox-row">
                    <input type="checkbox" ?checked=${user.email_verified} @change=${(e) => this._updateField('email_verified', e.target.checked)} />
                    Email verified
                  </label>
                  <label class="checkbox-row">
                    <input type="checkbox" ?checked=${user.enabled} @change=${(e) => this._updateField('enabled', e.target.checked)} />
                    Enabled
                  </label>
                  <div class="actions">
                    <c-button variant="primary" ?disabled=${saving || !dirty} @click=${() => this._save()}>
                      ${saving ? 'Saving...' : 'Save Changes'}${dirty ? html`<span class="dirty-indicator"></span>` : ''}
                    </c-button>
                    <c-button variant="ghost" @click=${() => this._navigateAway('/users')}>Cancel</c-button>
                  </div>
                </div>
              `
          : html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">User not found.</div>`}
      </c-page-layout>
    `;
  }
}

customElements.define('user-detail-page', UserDetailPage);
