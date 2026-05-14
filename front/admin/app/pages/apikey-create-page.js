import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { listRealms } from '../services/realm-service.js';
import { listScopes } from '../services/scope-service.js';
import { createApiKey } from '../services/apikey-service.js';
import { navigate } from '../core/router.js';
import { showToast } from '../components/ui/toast.js';

class ApiKeyCreatePage extends BaseComponent {
  constructor() {
    super();
    this._state = {
      name: '',
      selectedScopes: ['admin'],
      availableScopes: [],
      expiresInDays: '',
      realms: [],
      realmId: '',
      loading: false,
      createdKey: null,
    };
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadRealms();
  }

  async _loadRealms() {
    try {
      const data = await listRealms({ limit: '100' });
      const realms = data.items || [];
      const defaultRealmId = realms.length > 0 ? realms[0].id : '00000000-0000-0000-0000-000000000000';
      this.setState({ realms, realmId: defaultRealmId });
      if (defaultRealmId) this._loadScopes(defaultRealmId);
    } catch (err) {
      showToast('Failed to load realms', 'error');
      this.setState({ realms: [], realmId: '00000000-0000-0000-0000-000000000000' });
    }
  }

  async _loadScopes(realmId) {
    try {
      const data = await listScopes(realmId);
      const scopes = (data.items || []).map(s => s.name);
      this.setState({ availableScopes: scopes });
    } catch (err) {
      showToast('Failed to load scopes', 'error');
      this.setState({ availableScopes: [] });
    }
  }

  _onRealmChange(e) {
    const realmId = e.target.value;
    this.setState({ realmId });
    this._loadScopes(realmId);
  }

  _toggleScope(scope) {
    const { selectedScopes } = this._state;
    const next = selectedScopes.includes(scope)
      ? selectedScopes.filter(s => s !== scope)
      : [...selectedScopes, scope];
    this.setState({ selectedScopes: next });
  }

  async _createKey() {
    const { name, selectedScopes, expiresInDays, realmId } = this._state;
    if (!name.trim()) {
      showToast('Name is required', 'error');
      return;
    }
    if (selectedScopes.length === 0) {
      showToast('At least one scope is required', 'error');
      return;
    }

    this.setState({ loading: true });
    try {
      const data = await createApiKey({
        realm_id: realmId,
        name: name.trim(),
        scopes: selectedScopes,
        expires_in_days: expiresInDays ? Number(expiresInDays) : null,
      });
      this.setState({ createdKey: data, loading: false });
      showToast('API key created successfully', 'success');
    } catch (err) {
      showToast(err.body?.error || 'Failed to create API key', 'error');
      this.setState({ loading: false });
    }
  }

  _copyKey() {
    const rawKey = this._state.createdKey?.raw_key;
    if (!rawKey) return;
    navigator.clipboard.writeText(rawKey).then(() => {
      showToast('Copied to clipboard', 'success');
    });
  }

  template() {
    const { name, selectedScopes, availableScopes, expiresInDays, realms, realmId, loading, createdKey } = this._state;

    if (createdKey) {
      return html`
        <style>
          :host { display: block; }
          .key-display {
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            border-radius: var(--radius-md);
            padding: 1.5rem;
            margin-bottom: 1.5rem;
          }
          .key-warning {
            color: var(--color-danger);
            font-size: 0.875rem;
            margin-bottom: 1rem;
            font-weight: 500;
          }
          .key-value {
            font-family: monospace;
            font-size: 0.875rem;
            background: var(--color-surface);
            padding: 0.75rem;
            border-radius: var(--radius-sm);
            border: 1px solid #e2e8f0;
            word-break: break-all;
            margin-bottom: 1rem;
          }
          .actions { display: flex; gap: 0.5rem; }
        </style>
        <c-page-layout title="API Key Created">
          <div class="key-warning">
            Copy this key now. It will never be shown again.
          </div>
          <div class="key-display">
            <div><strong>Name:</strong> ${createdKey.name}</div>
            <div><strong>Prefix:</strong> ${createdKey.prefix}</div>
            <div><strong>Scopes:</strong> ${createdKey.scopes.join(', ')}</div>
          </div>
          <div class="key-value">${createdKey.raw_key}</div>
          <div class="actions">
            <c-button variant="primary" @click=${() => this._copyKey()}>Copy to Clipboard</c-button>
            <c-button variant="secondary" @click=${() => navigate('/api-keys')}>Back to API Keys</c-button>
          </div>
        </c-page-layout>
      `;
    }

    return html`
      <style>
        :host { display: block; }
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
        .scope-list {
          display: flex;
          flex-wrap: wrap;
          gap: 0.5rem;
          margin-bottom: 0.25rem;
        }
        .scope-chip {
          display: inline-flex;
          align-items: center;
          gap: 0.375rem;
          padding: 0.375rem 0.75rem;
          background: #f1f5f9;
          border: 1px solid #e2e8f0;
          border-radius: var(--radius-sm);
          font-size: 0.875rem;
          cursor: pointer;
          user-select: none;
          transition: background 0.15s, border-color 0.15s;
        }
        .scope-chip:hover {
          background: #e2e8f0;
        }
        .scope-chip input[type="checkbox"] {
          margin: 0;
          cursor: pointer;
        }
        .scope-chip:has(input:checked) {
          background: var(--color-primary);
          color: #fff;
          border-color: var(--color-primary);
        }
        .scope-chip:has(input:checked) input {
          accent-color: #fff;
        }
        .field-select {
          width: 100%;
          padding: 0.5rem 0.75rem;
          font-size: 0.875rem;
          border: 1px solid #e2e8f0;
          border-radius: var(--radius-sm);
          font-family: inherit;
          box-sizing: border-box;
          background: var(--color-surface, #fff);
          color: var(--color-text, #1e293b);
          appearance: none;
          background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%2364748b' d='M6 8L1 3h10z'/%3E%3C/svg%3E");
          background-repeat: no-repeat;
          background-position: right 0.75rem center;
          padding-right: 2rem;
        }
        .field-select:focus {
          outline: none;
          border-color: var(--color-primary);
        }
        .hint {
          font-size: 0.75rem;
          color: var(--color-text-muted);
          margin-top: 0.25rem;
        }
        .actions { display: flex; gap: 0.5rem; margin-top: 1.5rem; }
      </style>
      <c-page-layout title="Create API Key">
        <div class="form">
          <div class="field">
            <label class="field-label">Name *</label>
            <input
              class="field-input"
              type="text"
              placeholder="e.g. Production Service Key"
              .value=${name}
              @input=${(e) => this.setState({ name: e.target.value })}
            />
          </div>
          <div class="field">
            <label class="field-label">Realm *</label>
            <select
              class="field-select"
              .value=${realmId}
              @change=${(e) => this._onRealmChange(e)}
            >
              ${realms.map(r => html`<option value=${r.id} ?selected=${realmId === r.id}>${r.display_name || r.name}</option>`)}
            </select>
          </div>
          <div class="field">
            <label class="field-label">Scopes *</label>
            <div class="scope-list">
              ${availableScopes.length === 0
        ? html`<div class="hint">No scopes available for this realm</div>`
        : availableScopes.map(scope => html`
                    <label class="scope-chip">
                      <input
                        type="checkbox"
                        ?checked=${selectedScopes.includes(scope)}
                        @change=${() => this._toggleScope(scope)}
                      />
                      <span>${scope}</span>
                    </label>
                  `)}
            </div>
            <div class="hint">Select at least one scope</div>
          </div>
          <div class="field">
            <label class="field-label">Expires In (days)</label>
            <input
              class="field-input"
              type="number"
              placeholder="Leave empty for no expiration"
              .value=${expiresInDays}
              @input=${(e) => this.setState({ expiresInDays: e.target.value })}
            />
          </div>
          <div class="actions">
            <c-button variant="primary" ?disabled=${loading || !name.trim()} @click=${() => this._createKey()}>
              ${loading ? 'Creating...' : 'Create Key'}
            </c-button>
            <c-button variant="ghost" @click=${() => navigate('/api-keys')}>Cancel</c-button>
          </div>
        </div>
      </c-page-layout>
    `;
  }
}

customElements.define('apikey-create-page', ApiKeyCreatePage);
