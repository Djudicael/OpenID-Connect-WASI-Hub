import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { get, put } from '../core/http.js';
import { navigate } from '../core/router.js';
import { showToast } from '../components/ui/toast.js';

class RealmDetailPage extends BaseComponent {
  constructor() {
    super();
    this._state = { realm: null, savedRealm: null, loading: true, saving: false, dirty: false };
    this._themeFields = ['login_title', 'logo_url', 'primary_color', 'bg_color'];
    this._onBeforeUnload = this._onBeforeUnload.bind(this);
  }

  connectedCallback() {
    super.connectedCallback();
    if (this.params && this.params.id) {
      this._loadRealm(this.params.id);
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
    const { realm, savedRealm } = this._state;
    if (!realm || !savedRealm) return false;
    const themeDirty = this._themeFields.some(
      (k) => this._getThemeValue(realm, k) !== this._getThemeValue(savedRealm, k)
    );
    return (
      realm.name !== savedRealm.name ||
      realm.display_name !== savedRealm.display_name ||
      realm.enabled !== savedRealm.enabled ||
      themeDirty
    );
  }

  _getThemeValue(realm, key) {
    return realm?.config?.theme?.[key] || '';
  }

  async _loadRealm(id) {
    this.setState({ loading: true });
    try {
      const realm = await get(`/api/realms/${id}`);
      // Ensure config/theme objects exist for binding
      if (!realm.config) realm.config = {};
      if (!realm.config.theme) realm.config.theme = {};
      this.setState({ realm, savedRealm: JSON.parse(JSON.stringify(realm)), loading: false, dirty: false });
    } catch (err) {
      showToast('Failed to load realm', 'error');
      this.setState({ loading: false });
    }
  }

  async _save() {
    const realm = this._state.realm;
    if (!realm) return;
    this.setState({ saving: true });
    try {
      await put(`/api/realms/${realm.id}`, {
        name: realm.name,
        display_name: realm.display_name,
        enabled: realm.enabled,
        config: realm.config,
      });
      showToast('Realm updated', 'success');
      this.setState({ saving: false, savedRealm: JSON.parse(JSON.stringify(realm)), dirty: false });
    } catch (err) {
      showToast('Failed to update realm', 'error');
      this.setState({ saving: false });
    }
  }

  _updateField(field, value) {
    const realm = { ...this._state.realm, [field]: value };
    const savedRealm = this._state.savedRealm;
    const dirty = this._isDirty;
    this.setState({ realm, dirty });
  }

  _updateThemeField(key, value) {
    const realm = { ...this._state.realm };
    realm.config = { ...realm.config };
    realm.config.theme = { ...realm.config.theme, [key]: value };
    this.setState({ realm, dirty: true });
  }

  _navigateAway(path) {
    if (this._state.dirty) {
      if (!confirm('You have unsaved changes. Are you sure you want to leave?')) {
        return;
      }
    }
    this.setState({ dirty: false });
    navigate(path);
  }

  template() {
    const { realm, loading, saving, dirty } = this._state;
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
        .hint {
          font-size: 0.75rem;
          color: var(--color-text-muted);
          margin-top: 0.25rem;
        }
        .checkbox-row {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          margin-bottom: 1rem;
        }
        .realm-id {
          font-size: 0.75rem;
          color: var(--color-text-muted);
          margin-bottom: 1.5rem;
          font-family: monospace;
        }
        .actions { display: flex; gap: 0.5rem; margin-top: 1.5rem; }
      </style>
      <c-page-layout title="Realm Details">
        <span class="back-link" @click=${() => this._navigateAway('/realms')}>
          &larr; Back to Realms
        </span>
        ${loading
        ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>`
        : realm
          ? html`
                <div class="realm-id">ID: ${realm.id}</div>
                <div class="form">
                  <div class="field">
                    <label class="field-label">Name</label>
                    <input class="field-input" type="text" .value=${realm.name || ''} @input=${(e) => this._updateField('name', e.target.value)} />
                    <div class="hint">Machine-readable identifier</div>
                  </div>
                  <div class="field">
                    <label class="field-label">Display Name</label>
                    <input class="field-input" type="text" .value=${realm.display_name || ''} @input=${(e) => this._updateField('display_name', e.target.value)} />
                    <div class="hint">Human-readable name</div>
                  </div>
                  <label class="checkbox-row">
                    <input type="checkbox" ?checked=${realm.enabled} @change=${(e) => this._updateField('enabled', e.target.checked)} />
                    Enabled
                  </label>
                  <hr style="border:none;border-top:1px solid #e2e8f0;margin:1.5rem 0;" />
                  <h3 style="font-size:1rem;font-weight:600;margin:0 0 1rem 0;">Theme</h3>
                  <div class="field">
                    <label class="field-label">Login Title</label>
                    <input class="field-input" type="text" .value=${this._getThemeValue(realm, 'login_title')} @input=${(e) => this._updateThemeField('login_title', e.target.value)} />
                    <div class="hint">Shown on the realm login page (defaults to display name)</div>
                  </div>
                  <div class="field">
                    <label class="field-label">Logo URL</label>
                    <input class="field-input" type="text" .value=${this._getThemeValue(realm, 'logo_url')} @input=${(e) => this._updateThemeField('logo_url', e.target.value)} />
                    <div class="hint">Optional logo image URL for the login page</div>
                  </div>
                  <div class="field">
                    <label class="field-label">Primary Color</label>
                    <input class="field-input" type="color" .value=${this._getThemeValue(realm, 'primary_color') || '#2563eb'} @input=${(e) => this._updateThemeField('primary_color', e.target.value)} />
                    <div class="hint">Button and accent color</div>
                  </div>
                  <div class="field">
                    <label class="field-label">Background Color</label>
                    <input class="field-input" type="color" .value=${this._getThemeValue(realm, 'bg_color') || '#f8fafc'} @input=${(e) => this._updateThemeField('bg_color', e.target.value)} />
                    <div class="hint">Login page background color</div>
                  </div>
                  <div class="actions">
                    <c-button variant="primary" ?disabled=${saving || !dirty} @click=${() => this._save()}>
                      ${saving ? 'Saving...' : 'Save Changes'}${dirty ? html`<span class="dirty-indicator"></span>` : ''}
                    </c-button>
                    <c-button variant="ghost" @click=${() => this._navigateAway('/realms')}>Cancel</c-button>
                  </div>
                </div>
              `
          : html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Realm not found.</div>`}
      </c-page-layout>
    `;
  }
}

customElements.define('realm-detail-page', RealmDetailPage);
