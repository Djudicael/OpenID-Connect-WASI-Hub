import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { get, del } from '../core/http.js';
import { showToast } from '../components/ui/toast.js';

class ClientsPage extends BaseComponent {
  constructor() {
    super();
    this._state = {
      clients: [],
      loading: false,
      search: '',
      page: 1,
      pageSize: 20,
      total: 0,
    };
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadClients();
  }

  async _loadClients() {
    this.setState({ loading: true });
    try {
      const { search, page, pageSize } = this._state;
      const offset = (page - 1) * pageSize;
      const params = new URLSearchParams();
      if (search) params.set('search', search);
      params.set('limit', String(pageSize));
      params.set('offset', String(offset));

      const data = await get(`/api/clients?${params.toString()}`);
      this.setState({
        clients: data.items || [],
        total: data.total || 0,
        loading: false,
      });
    } catch (err) {
      showToast('Failed to load clients', 'error');
      this.setState({ clients: [], loading: false });
    }
  }

  _onSearch(e) {
    this.setState({ search: e.target.value, page: 1 }, this._loadClients());
  }

  _onPageChange(e) {
    this.setState({ page: e.detail.page }, this._loadClients());
  }

  async _deleteClient(id) {
    if (!confirm('Are you sure you want to delete this client?')) return;
    try {
      await del(`/api/clients/${id}`);
      showToast('Client deleted', 'success');
      this._loadClients();
    } catch (err) {
      showToast('Failed to delete client', 'error');
    }
  }

  template() {
    const { clients, loading, search, page, pageSize, total } = this._state;
    const columns = [
      { key: 'client_id', label: 'Client ID' },
      { key: 'name', label: 'Name' },
      { key: 'client_type', label: 'Type' },
      { key: 'pkce_required', label: 'PKCE', render: (v) => v ? 'Yes' : 'No' },
      { key: 'enabled', label: 'Enabled', render: (v) => v ? html`<span style="color:var(--color-success)">Yes</span>` : html`<span style="color:var(--color-danger)">No</span>` },
      {
        key: 'id',
        label: 'Actions',
        render: (_, row) => html`
          <div style="display:flex;gap:0.5rem">
            <c-button size="sm" variant="danger" @click=${() => this._deleteClient(row.id)}>Delete</c-button>
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
        .search-input {
          flex: 1;
          max-width: 24rem;
          padding: 0.5rem 0.75rem;
          font-size: 0.875rem;
          border: 1px solid #e2e8f0;
          border-radius: var(--radius-sm);
          font-family: inherit;
        }
        .search-input:focus {
          outline: none;
          border-color: var(--color-primary);
        }
      </style>
      <c-page-layout title="Clients">
        <div slot="actions">
          <c-button variant="primary" @click=${() => showToast('Client creation not yet implemented', 'warning')}>
            + Add Client
          </c-button>
        </div>
        <div class="toolbar">
          <input
            class="search-input"
            type="text"
            placeholder="Search clients..."
            .value=${search}
            @input=${(e) => this._onSearch(e)}
          />
        </div>
        ${loading
        ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>`
        : html`<c-table .columns=${columns} .rows=${clients}></c-table>`}
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

customElements.define('clients-page', ClientsPage);
