import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { get, del, post } from '../core/http.js';
import { navigate } from '../core/router.js';
import { formatDate, formatRelativeTime } from '../utils/format.js';
import { showToast } from '../components/ui/toast.js';

class ApiKeysPage extends BaseComponent {
  constructor() {
    super();
    this._state = {
      keys: [],
      loading: true,
      realmId: '00000000-0000-0000-0000-000000000000',
      includeRevoked: false,
    };
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadKeys();
  }

  async _loadKeys() {
    this.setState({ loading: true });
    try {
      const data = await get(`/api/keys?realm_id=${this._state.realmId}&include_revoked=${this._state.includeRevoked}`);
      this.setState({ keys: data.items || [], loading: false });
    } catch (err) {
      showToast('Failed to load API keys', 'error');
      this.setState({ keys: [], loading: false });
    }
  }

  async _revokeKey(id) {
    if (!confirm('Are you sure you want to revoke this API key?')) return;
    try {
      await del(`/api/keys/${id}`);
      showToast('API key revoked', 'success');
      this._loadKeys();
    } catch (err) {
      showToast('Failed to revoke API key', 'error');
    }
  }

  async _rotateKey(id) {
    if (!confirm('Rotate this API key? The old key will stop working immediately.')) return;
    try {
      const data = await post(`/api/keys/${id}/rotate`);
      showToast('API key rotated. New key displayed once.', 'success');
      // Show the new raw key in a modal or alert
      alert(`New API Key (copy now - shown once only):\n\n${data.raw_key}`);
      this._loadKeys();
    } catch (err) {
      showToast('Failed to rotate API key', 'error');
    }
  }

  template() {
    const { keys, loading, includeRevoked } = this._state;
    const columns = [
      { key: 'name', label: 'Name' },
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
      </style>
      <c-page-layout title="API Keys">
        <div slot="actions">
          <c-button variant="primary" @click=${() => navigate('/api-keys/create')}>+ Create Key</c-button>
        </div>
        <div class="toolbar">
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
