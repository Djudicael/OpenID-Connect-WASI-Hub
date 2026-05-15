import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { listRealms, getRealm } from '../services/realm-service.js';
import { get, put } from '../core/http.js';
import { showToast } from '../components/ui/toast.js';
import { handleApiError } from '../utils/error-handler.js';

class PasswordPoliciesPage extends BaseComponent {
  constructor() {
    super();
    this._state = {
      realms: [],
      realmId: '',
      loading: true,
      saving: false,
      minLength: 8,
      maxLength: 128,
      requireUppercase: false,
      requireLowercase: false,
      requireDigit: false,
      requireSpecial: false,
      minUniqueChars: 0,
      maxConsecutiveIdentical: 0,
      disallowedPasswords: '',
    };
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadRealms();
  }

  async _loadRealms() {
    try {
      const data = await listRealms({ limit: '100' }, this.signal);
      const realms = data.items || [];
      const defaultRealmId = realms.length > 0 ? realms[0].id : '';
      this.setState({ realms, realmId: defaultRealmId });
      if (defaultRealmId) this._loadPolicy(defaultRealmId);
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to load realms');
    }
  }

  async _loadPolicy(realmId) {
    this.setState({ loading: true });
    try {
      const policy = await get(`/api/realms/${realmId}/password-policy`, this.signal);
      this.setState({
        minLength: policy.min_length || 8,
        maxLength: policy.max_length || 128,
        requireUppercase: policy.require_uppercase || false,
        requireLowercase: policy.require_lowercase || false,
        requireDigit: policy.require_digit || false,
        requireSpecial: policy.require_special || false,
        minUniqueChars: policy.min_unique_chars || 0,
        maxConsecutiveIdentical: policy.max_consecutive_identical || 0,
        disallowedPasswords: (policy.disallowed_passwords || []).join('\n'),
        loading: false,
      });
    } catch (err) {
      if (err.name === 'AbortError') return;
      if (err.status === 404) {
        this.setState({ loading: false });
        return;
      }
      handleApiError(err, 'Failed to load password policy');
      this.setState({ loading: false });
    }
  }

  async _onRealmChange(e) {
    const realmId = e.target.value;
    await this.setState({ realmId });
    this._loadPolicy(realmId);
  }

  async _save() {
    const { realmId, minLength, maxLength, requireUppercase, requireLowercase, requireDigit, requireSpecial, minUniqueChars, maxConsecutiveIdentical, disallowedPasswords } = this._state;
    this.setState({ saving: true });
    try {
      const body = {
        min_length: Number(minLength) || 8,
        max_length: Number(maxLength) || 128,
        require_uppercase: requireUppercase,
        require_lowercase: requireLowercase,
        require_digit: requireDigit,
        require_special: requireSpecial,
        min_unique_chars: Number(minUniqueChars) || 0,
        max_consecutive_identical: Number(maxConsecutiveIdentical) || 0,
        disallowed_passwords: disallowedPasswords.split('\n').map(s => s.trim()).filter(Boolean),
      };
      await put(`/api/realms/${realmId}/password-policy`, body);
      showToast('Password policy saved', 'success');
      this.setState({ saving: false });
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to save password policy');
      this.setState({ saving: false });
    }
  }

  template() {
    const { realms, realmId, loading, saving, minLength, maxLength, requireUppercase, requireLowercase, requireDigit, requireSpecial, minUniqueChars, maxConsecutiveIdentical, disallowedPasswords } = this._state;

    return html`
      <style>
        :host { display: block; }
        .toolbar { display: flex; gap: 1rem; margin-bottom: 1rem; align-items: center; }
        .realm-select { padding: 0.375rem 0.75rem; font-size: 0.875rem; border: 1px solid #e2e8f0; border-radius: var(--radius-sm); font-family: inherit; min-width: 12rem; }
        .realm-select:focus { outline: none; border-color: var(--color-primary); }
        .form { max-width: 40rem; }
        .field { margin-bottom: 1rem; }
        .field-label { display: block; font-size: 0.875rem; font-weight: 500; margin-bottom: 0.25rem; }
        .field-input, .field-textarea { width: 100%; padding: 0.5rem 0.75rem; font-size: 0.875rem; border: 1px solid #e2e8f0; border-radius: var(--radius-sm); font-family: inherit; box-sizing: border-box; }
        .field-input:focus, .field-textarea:focus { outline: none; border-color: var(--color-primary); }
        .field-textarea { resize: vertical; min-height: 6rem; font-family: monospace; }
        .hint { font-size: 0.75rem; color: var(--color-text-muted); margin-top: 0.25rem; }
        .field-checkbox { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; }
        .field-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
        .actions { display: flex; gap: 0.5rem; margin-top: 1.5rem; }
        .section-title { font-size: 1rem; font-weight: 600; margin: 1.5rem 0 1rem; padding-top: 1rem; border-top: 1px solid #e2e8f0; }
      </style>
      <c-page-layout title="Password Policies">
        <div class="toolbar">
          <label style="font-size:0.875rem;color:var(--color-text-muted)">
            Realm:
            <select class="realm-select" aria-label="Select realm" .value=${realmId} @change=${(e) => this._onRealmChange(e)}>
              ${realms.map(r => html`<option value=${r.id} ?selected=${realmId === r.id}>${r.display_name || r.name}</option>`)}
            </select>
          </label>
        </div>
        ${loading
        ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>`
        : html`
          <div class="form">
            <div class="section-title">Length Requirements</div>
            <div class="field-row">
              <div class="field">
                <label class="field-label" for="pp-min">Minimum Length</label>
                <input class="field-input" id="pp-min" type="number" min="1" max="128" .value=${minLength} @input=${(e) => this.setState({ minLength: e.target.value })} />
              </div>
              <div class="field">
                <label class="field-label" for="pp-max">Maximum Length</label>
                <input class="field-input" id="pp-max" type="number" min="1" max="256" .value=${maxLength} @input=${(e) => this.setState({ maxLength: e.target.value })} />
              </div>
            </div>

            <div class="section-title">Character Requirements</div>
            <div class="field">
              <label class="field-checkbox">
                <input type="checkbox" id="pp-upper" ?checked=${requireUppercase} @change=${(e) => this.setState({ requireUppercase: e.target.checked })} />
                Require uppercase letter
              </label>
              <label class="field-checkbox">
                <input type="checkbox" id="pp-lower" ?checked=${requireLowercase} @change=${(e) => this.setState({ requireLowercase: e.target.checked })} />
                Require lowercase letter
              </label>
              <label class="field-checkbox">
                <input type="checkbox" id="pp-digit" ?checked=${requireDigit} @change=${(e) => this.setState({ requireDigit: e.target.checked })} />
                Require digit
              </label>
              <label class="field-checkbox">
                <input type="checkbox" id="pp-special" ?checked=${requireSpecial} @change=${(e) => this.setState({ requireSpecial: e.target.checked })} />
                Require special character
              </label>
            </div>

            <div class="section-title">Complexity</div>
            <div class="field-row">
              <div class="field">
                <label class="field-label" for="pp-unique">Min Unique Characters</label>
                <input class="field-input" id="pp-unique" type="number" min="0" max="128" .value=${minUniqueChars} @input=${(e) => this.setState({ minUniqueChars: e.target.value })} />
                <div class="hint">0 = disabled</div>
              </div>
              <div class="field">
                <label class="field-label" for="pp-consecutive">Max Consecutive Identical</label>
                <input class="field-input" id="pp-consecutive" type="number" min="0" max="128" .value=${maxConsecutiveIdentical} @input=${(e) => this.setState({ maxConsecutiveIdentical: e.target.value })} />
                <div class="hint">0 = disabled</div>
              </div>
            </div>

            <div class="section-title">Disallowed Passwords</div>
            <div class="field">
              <label class="field-label" for="pp-disallowed">Blocked Passwords</label>
              <textarea class="field-textarea" id="pp-disallowed" placeholder="password123&#10;admin&#10;qwerty" .value=${disallowedPasswords} @input=${(e) => this.setState({ disallowedPasswords: e.target.value })}></textarea>
              <div class="hint">One password per line. Case-insensitive matching.</div>
            </div>

            <div class="actions">
              <c-button variant="primary" ?disabled=${saving} @click=${() => this._save()}>
                ${saving ? 'Saving...' : 'Save Policy'}
              </c-button>
            </div>
          </div>
        `}
      </c-page-layout>
    `;
  }
}

customElements.define('password-policies-page', PasswordPoliciesPage);
