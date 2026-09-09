import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { listAllRealms } from '../services/realm-service.js';
import { resolveSelectedRealmId, setSelectedRealmId } from '../core/realm-context.js';
import { createApiKey } from '../services/apikey-service.js';
import { navigate } from '../core/router.js';
import { showToast } from '../components/ui/toast.js';

const ADMIN_PERMISSIONS = [
  'stats:read',
  'users:read', 'users:write', 'users:impersonate',
  'clients:read', 'clients:write',
  'realms:read', 'realms:write',
  'sessions:read', 'sessions:revoke',
  'audit:read',
  'scopes:read', 'scopes:write',
  'roles:read', 'roles:write',
  'groups:read', 'groups:write',
  'identity_providers:read', 'identity_providers:write',
  'user_federation:read', 'user_federation:write',
  'api_keys:read', 'api_keys:write',
  'authorization:read', 'authorization:write',
  'workflows:read', 'workflows:write', 'workflows:execute',
  'organizations:view', 'organizations:manage', 'organizations:members',
  'maintenance:execute',
  'admin',
];

class ApiKeyCreatePage extends BaseComponent {
  constructor() {
    super();
    this._state = {
      name: '',
      selectedScopes: ['workflows:execute'],
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
      const realms = await listAllRealms(this.signal);
      const realmId = resolveSelectedRealmId(realms, this._state.realmId) || '00000000-0000-0000-0000-000000000000';
      setSelectedRealmId(realmId);
      this.setState({ realms, realmId });
      if (realmId) this._loadScopes(realmId);
    } catch (err) {
      showToast('Failed to load realms', 'error');
      this.setState({ realms: [], realmId: '00000000-0000-0000-0000-000000000000' });
    }
  }

  _loadScopes() {
    this.setState({ availableScopes: ADMIN_PERMISSIONS });
  }

  _onRealmChange(e) {
    const realmId = e.target.value;
    setSelectedRealmId(realmId);
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
            <label class="field-label">Permissions *</label>
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
            <div class="hint"><code>workflows:execute</code> is sufficient for a workflow scheduler. <code>admin</code> grants full administration access.</div>
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
