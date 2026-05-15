import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { listSessions, revokeSession } from '../services/session-service.js';
import { showToast } from '../components/ui/toast.js';
import { handleApiError } from '../utils/error-handler.js';

const ConfirmDialog = customElements.get('c-modal');

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
      selectedIds: new Set(),
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
      const data = await listSessions({
        limit: String(pageSize),
        offset: String(offset),
        ...(!showRevoked ? { revoked: 'false' } : {}),
      }, this.signal);
      this.setState({
        sessions: data.items || [],
        total: data.total || 0,
        loading: false,
        selectedIds: new Set(),
      });
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to load sessions');
      this.setState({ sessions: [], loading: false });
    }
  }

  async _onPageChange(e) {
    await this.setState({ page: e.detail.page });
    this._loadSessions();
  }

  _toggleSelect(id) {
    const selected = new Set(this._state.selectedIds);
    if (selected.has(id)) { selected.delete(id); } else { selected.add(id); }
    this.setState({ selectedIds: selected });
  }

  _toggleSelectAll() {
    const { sessions, selectedIds } = this._state;
    const activeSessions = sessions.filter(s => !s.revoked);
    if (selectedIds.size === activeSessions.length && activeSessions.length > 0) {
      this.setState({ selectedIds: new Set() });
    } else {
      this.setState({ selectedIds: new Set(activeSessions.map(s => s.id)) });
    }
  }

  async _bulkRevoke() {
    const { selectedIds } = this._state;
    if (selectedIds.size === 0) return;
    const confirmed = await ConfirmDialog.confirm(`Revoke ${selectedIds.size} session(s)? Users will be forced to re-authenticate.`, 'Bulk Revoke');
    if (!confirmed) return;
    let success = 0;
    for (const id of selectedIds) {
      try {
        await revokeSession(id);
        success++;
      } catch (err) {
        if (err.name === 'AbortError') return;
      }
    }
    showToast(`${success} session(s) revoked`, 'success');
    this._loadSessions();
  }

  async _revokeSession(id) {
    const confirmed = await ConfirmDialog.confirm('Revoke this session? The user will be forced to re-authenticate.', 'Revoke Session');
    if (!confirmed) return;
    try {
      await revokeSession(id);
      showToast('Session revoked', 'success');
      this._loadSessions();
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to revoke session');
    }
  }

  template() {
    const { sessions, loading, page, pageSize, total, showRevoked, selectedIds } = this._state;
    const columns = [
      {
        key: 'select',
        label: html`<input type="checkbox" aria-label="Select all sessions" ?checked=${selectedIds.size === sessions.filter(s => !s.revoked).length && sessions.filter(s => !s.revoked).length > 0} @change=${() => this._toggleSelectAll()} />`,
        render: (_, row) => row.revoked ? '' : html`<input type="checkbox" aria-label="Select session" ?checked=${selectedIds.has(row.id)} @change=${() => this._toggleSelect(row.id)} />`,
      },
      { key: 'user_id', label: 'User ID', render: (v) => v ? v.slice(0, 8) + '...' : '-' },
      { key: 'client_id', label: 'Client ID', render: (v) => v ? v.slice(0, 8) + '...' : '-' },
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
          flex-wrap: wrap;
        }
        .filter-label {
          font-size: 0.875rem;
          color: var(--color-text-muted);
        }
        .bulk-bar {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          padding: 0.5rem 1rem;
          background: #fef2f2;
          border: 1px solid #fecaca;
          border-radius: var(--radius-sm);
          margin-bottom: 1rem;
          font-size: 0.875rem;
        }
        .bulk-bar span { color: var(--color-danger); font-weight: 500; }
        .empty-state {
          text-align: center;
          padding: 3rem 1rem;
          color: var(--color-text-muted);
        }
        .empty-state-icon { font-size: 2.5rem; margin-bottom: 0.75rem; opacity: 0.5; }
        .empty-state-text { font-size: 1rem; margin-bottom: 1rem; }
      </style>
      <c-page-layout title="Sessions">
        <div class="toolbar">
          <label class="filter-label">
            <input
              type="checkbox"
              aria-label="Include revoked sessions"
              ?checked=${showRevoked}
              @change=${(e) => { this.setState({ showRevoked: e.target.checked, page: 1 }); this._loadSessions(); }}
            />
            Include revoked
          </label>
        </div>
        ${selectedIds.size > 0 ? html`
          <div class="bulk-bar">
            <span>${selectedIds.size} selected</span>
            <c-button size="sm" variant="danger" @click=${() => this._bulkRevoke()}>Revoke Selected</c-button>
            <c-button size="sm" variant="ghost" @click=${() => this.setState({ selectedIds: new Set() })}>Clear</c-button>
          </div>
        ` : ''}
        ${loading
        ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>`
        : sessions.length === 0
          ? html`<div class="empty-state"><div class="empty-state-icon">&#128274;</div><div class="empty-state-text">No active sessions</div></div>`
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
