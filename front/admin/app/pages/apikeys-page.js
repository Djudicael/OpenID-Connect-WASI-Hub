import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { listApiKeys, deleteApiKey, rotateApiKey } from '../services/apikey-service.js';
import { listRealms } from '../services/realm-service.js';
import { navigate } from '../core/router.js';
import { formatDate, formatRelativeTime } from '../utils/format.js';
import { showToast } from '../components/ui/toast.js';

class ApiKeysPage extends BaseComponent {
  constructor() {
    super();
    this._state = {
      keys: [],
      loading: true,
      realms: [],
      realmId: '',
      includeRevoked: false,
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
      this._loadKeys();
    } catch (err) {
      showToast('Failed to load realms', 'error');
      this.setState({ realms: [], realmId: '00000000-0000-0000-0000-000000000000' });
      this._loadKeys();
    }
  }

  async _loadKeys() {
    this.setState({ loading: true });
    try {
      const data = await listApiKeys({
        realm_id: this._state.realmId,
        include_revoked: String(this._state.includeRevoked),
      });
      this.setState({ keys: data.items || [], loading: false });
    } catch (err) {
      showToast('Failed to load API keys', 'error');
      this.setState({ keys: [], loading: false });
    }
  }

  async _revokeKey(id) {
    if (!confirm('Are you sure you want to revoke this API key?')) return;
    try {
      await deleteApiKey(id);
      showToast('API key revoked', 'success');
      this._loadKeys();
    } catch (err) {
      showToast('Failed to revoke API key', 'error');
    }
  }

  async _rotateKey(id) {
    if (!confirm('Rotate this API key? The old key will stop working immediately.')) return;
    try {
      const data = await rotateApiKey(id);
      showToast('API key rotated! New key copied to clipboard.', 'success');
      const rawKey = data.raw_key;
      const copied = await navigator.clipboard.writeText(rawKey).catch(() => false);
      if (!copied) {
        const input = document.createElement('input');
        input.value = rawKey;
        input.style.cssText = 'position:fixed;left:-9999px';
        document.body.appendChild(input);
        input.select();
        document.execCommand('copy');
        document.body.removeChild(input);
      }
      this._loadKeys();
    } catch (err) {
      showToast('Failed to rotate API key', 'error');
    }
  }

  _onRealmChange(e) {
    const realmId = e.target.value;
    this.setState({ realmId });
    // Use requestAnimationFrame to ensure state is committed before loading
    requestAnimationFrame(() => this._loadKeys());
  }

  template() {
    const { keys, loading, realms, realmId, includeRevoked } = this._state;
    const columns = [
      { key: 'name', label: 'Name', render: (v, row) => html`<a href="/api-keys/${row.id}" style="color:var(--color-primary);text-decoration:none;cursor:pointer" @click=${(e) => { e.preventDefault(); navigate(`/api-keys/${row.id}`); }}>${v}</a>` },
      { key: 'prefix', label: 'Prefix' },
      { key: 'scopes', label: 'Scopes', render: (v) => Array.isArray(v) ? v.join(', ') : v },
      { key: 'expires_at', label: 'Expires', render: (v) => v ? formatRelativeTime(v) : 'Never' },
      { key: 'request_count', label: 'Uses' },
      { key: 'revoked', label: 'Status', render: (v) => v ? html`<span style="color:var(--color-danger)">Revoked</span>` : 'Active' },
      {
        key: 'id',
        label: 'Actions',
        render: (_, row) => html`
          <div style="display:flex;gap:0.5rem">
            ${!row.revoked ? html`
              <c-button size="sm" variant="secondary" @click=${() => this._rotateKey(row.id)}>Rotate</c-button>
              <c-button size="sm" variant="danger" @click=${() => this._revokeKey(row.id)}>Revoke</c-button>
            ` : html`<span style="color:var(--color-text-muted);font-size:0.75rem">Revoked</span>`}
          </div>
        `,
      },
    ];

    return html`
      <style>
        :host { display: block; }
        .toolbar {
          display: flex;
          gap: 1rem;
          margin-bottom: 1rem;
          align-items: center;
          flex-wrap: wrap;
        }
        .filter-label {
          font-size: 0.875rem;
          color: var(--color-text-muted);
        }
        .realm-select {
          padding: 0.375rem 0.75rem;
          font-size: 0.875rem;
          border: 1px solid #e2e8f0;
          border-radius: var(--radius-sm, 0.25rem);
          font-family: inherit;
          background: var(--color-surface, #fff);
          color: var(--color-text, #1e293b);
          min-width: 12rem;
        }
        .realm-select:focus {
          outline: none;
          border-color: var(--color-primary, #3b82f6);
        }
      </style>
      <c-page-layout title="API Keys">
        <div slot="actions">
          <c-button variant="primary" @click=${() => navigate('/api-keys/create')}>+ Create Key</c-button>
        </div>
        <div class="toolbar">
          <label class="filter-label">
            Realm:
            <select class="realm-select" .value=${realmId} @change=${(e) => this._onRealmChange(e)}>
              ${realms.map(r => html`<option value=${r.id} ?selected=${realmId === r.id}>${r.display_name || r.name}</option>`)}
            </select>
          </label>
          <label class="filter-label">
            <input
              type="checkbox"
              ?checked=${includeRevoked}
              @change=${(e) => { this.setState({ includeRevoked: e.target.checked }); this._loadKeys(); }}
            />
            Include revoked
          </label>
        </div>
        ${loading
        ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>`
        : html`<c-table .columns=${columns} .rows=${keys}></c-table>`}
      </c-page-layout>
    `;
  }
}

customElements.define('apikeys-page', ApiKeysPage);
