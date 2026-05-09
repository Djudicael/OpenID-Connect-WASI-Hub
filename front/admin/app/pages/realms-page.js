import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { get, del } from '../core/http.js';
import { showToast } from '../components/ui/toast.js';

class RealmsPage extends BaseComponent {
  constructor() {
    super();
    this._state = {
      realms: [],
      loading: false,
      page: 1,
      pageSize: 20,
      total: 0,
    };
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadRealms();
  }

  async _loadRealms() {
    this.setState({ loading: true });
    try {
      const { page, pageSize } = this._state;
      const offset = (page - 1) * pageSize;
      const params = new URLSearchParams();
      params.set('limit', String(pageSize));
      params.set('offset', String(offset));

      const data = await get(`/api/realms?${params.toString()}`);
      this.setState({
        realms: data.items || [],
        total: data.total || 0,
        loading: false,
      });
    } catch (err) {
      showToast('Failed to load realms', 'error');
      this.setState({ realms: [], loading: false });
    }
  }

  _onPageChange(e) {
    this.setState({ page: e.detail.page }, this._loadRealms());
  }

  async _deleteRealm(id) {
    if (!confirm('Are you sure you want to delete this realm? This will cascade to all users, clients, and sessions.')) return;
    try {
      await del(`/api/realms/${id}`);
      showToast('Realm deleted', 'success');
      this._loadRealms();
    } catch (err) {
      showToast('Failed to delete realm', 'error');
    }
  }

  template() {
    const { realms, loading, page, pageSize, total } = this._state;
    const columns = [
      { key: 'name', label: 'Name' },
      { key: 'display_name', label: 'Display Name' },
      { key: 'enabled', label: 'Enabled', render: (v) => v ? html`<span style="color:var(--color-success)">Yes</span>` : html`<span style="color:var(--color-danger)">No</span>` },
      {
        key: 'id',
        label: 'Actions',
        render: (_, row) => html`
          <div style="display:flex;gap:0.5rem">
            <c-button size="sm" variant="danger" @click=${() => this._deleteRealm(row.id)}>Delete</c-button>
          </div>
        `,
      },
    ];

    return html`
      <style>
        :host { display: block; }
      </style>
      <c-page-layout title="Realms">
        <div slot="actions">
          <c-button variant="primary" @click=${() => showToast('Realm creation not yet implemented', 'warning')}>
            + Add Realm
          </c-button>
        </div>
        ${loading
        ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>`
        : html`<c-table .columns=${columns} .rows=${realms}></c-table>`}
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

customElements.define('realms-page', RealmsPage);
