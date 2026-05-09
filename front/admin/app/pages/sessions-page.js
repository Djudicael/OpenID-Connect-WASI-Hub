import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { get, post } from '../core/http.js';
import { showToast } from '../components/ui/toast.js';

class SessionsPage extends BaseComponent {
  constructor() {
    super();
    this._state = {
      sessions: [],
      loading: false,
      page: 1,
      pageSize: 20,
      total: 0,
      showRevoked: false,
    };
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadSessions();
  }

  async _loadSessions() {
    this.setState({ loading: true });
    try {
      const { page, pageSize, showRevoked } = this._state;
      const offset = (page - 1) * pageSize;
      const params = new URLSearchParams();
      params.set('limit', String(pageSize));
      params.set('offset', String(offset));
      if (!showRevoked) params.set('revoked', 'false');

      const data = await get(`/api/sessions?${params.toString()}`);
      this.setState({
        sessions: data.items || [],
        total: data.total || 0,
        loading: false,
      });
    } catch (err) {
      showToast('Failed to load sessions', 'error');
      this.setState({ sessions: [], loading: false });
    }
  }

  _onPageChange(e) {
    this.setState({ page: e.detail.page }, this._loadSessions());
  }

  async _revokeSession(id) {
    if (!confirm('Revoke this session? The user will be forced to re-authenticate.')) return;
    try {
      await post(`/api/sessions/${id}/revoke`);
      showToast('Session revoked', 'success');
      this._loadSessions();
    } catch (err) {
      showToast('Failed to revoke session', 'error');
    }
  }

  template() {
    const { sessions, loading, page, pageSize, total, showRevoked } = this._state;
    const columns = [
      { key: 'user_id', label: 'User ID', render: (v) => v.slice(0, 8) + '...' },
      { key: 'client_id', label: 'Client ID', render: (v) => v.slice(0, 8) + '...' },
      { key: 'grant_type', label: 'Grant' },
      { key: 'scope', label: 'Scopes', render: (v) => Array.isArray(v) ? v.join(', ') : v },
      { key: 'revoked', label: 'Status', render: (v) => v ? html`<span style="color:var(--color-danger)">Revoked</span>` : html`<span style="color:var(--color-success)">Active</span>` },
      {
        key: 'id',
        label: 'Actions',
        render: (_, row) => html`
          <div style="display:flex;gap:0.5rem">
            ${!row.revoked ? html`
              <c-button size="sm" variant="danger" @click=${() => this._revokeSession(row.id)}>Revoke</c-button>
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
        }
        .filter-label {
          font-size: 0.875rem;
          color: var(--color-text-muted);
        }
      </style>
      <c-page-layout title="Sessions">
        <div class="toolbar">
          <label class="filter-label">
            <input
              type="checkbox"
              ?checked=${showRevoked}
              @change=${(e) => { this.setState({ showRevoked: e.target.checked, page: 1 }); this._loadSessions(); }}
            />
            Include revoked
          </label>
        </div>
        ${loading
        ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>`
        : html`<c-table .columns=${columns} .rows=${sessions}></c-table>`}
        <c-pagination
          .page=${page}
          .pageSize=${pageSize}
          .total=${total}
          @page-change=${(e) => this._onPageChange(e)}
        ></c-pagination>
      </c-page-layout>
    `;
  }
}

customElements.define('sessions-page', SessionsPage);
