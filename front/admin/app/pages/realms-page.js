import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { listRealms, createRealm, deleteRealm } from '../services/realm-service.js';
import { navigate } from '../core/router.js';
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
      showCreateModal: false,
      createName: '',
      createDisplayName: '',
      createEnabled: true,
      createLoading: false,
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

      const data = await listRealms({ limit: String(pageSize), offset: String(offset) });
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
      await deleteRealm(id);
      showToast('Realm deleted', 'success');
      this._loadRealms();
    } catch (err) {
      showToast('Failed to delete realm', 'error');
    }
  }

  _openCreateModal() {
    this.setState({
      showCreateModal: true,
      createName: '',
      createDisplayName: '',
      createEnabled: true,
      createLoading: false,
    });
    requestAnimationFrame(() => {
      const modal = this.shadowRoot.querySelector('c-modal');
      if (modal) modal.open();
    });
  }

  _closeCreateModal() {
    this.shadowRoot.querySelector('c-modal').close();
    this.setState({ showCreateModal: false });
  }

  async _createRealm() {
    const { createName, createDisplayName, createEnabled } = this._state;
    if (!createName.trim() || !createDisplayName.trim()) return;

    this.setState({ createLoading: true });
    try {
      await createRealm({
        name: createName.trim(),
        display_name: createDisplayName.trim(),
        enabled: createEnabled,
      });
      this._closeCreateModal();
      showToast('Realm created successfully', 'success');
      this._loadRealms();
    } catch (err) {
      showToast(err.body?.error || 'Failed to create realm', 'error');
      this.setState({ createLoading: false });
    }
  }

  template() {
    const { realms, loading, page, pageSize, total, showCreateModal, createName, createDisplayName, createEnabled, createLoading } = this._state;
    const columns = [
      { key: 'name', label: 'Name' },
      { key: 'display_name', label: 'Display Name' },
      { key: 'enabled', label: 'Enabled', render: (v) => v ? html`<span style="color:var(--color-success)">Yes</span>` : html`<span style="color:var(--color-danger)">No</span>` },
      {
        key: 'id',
        label: 'Actions',
        render: (_, row) => html`
          <div style="display:flex;gap:0.5rem">
            <c-button size="sm" variant="secondary" @click=${() => navigate(`/realms/${row.id}`)}>Edit</c-button>
            <c-button size="sm" variant="danger" @click=${() => this._deleteRealm(row.id)}>Delete</c-button>
          </div>
        `,
      },
    ];

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
        .hint {
          font-size: 0.75rem;
          color: var(--color-text-muted);
          margin-top: 0.25rem;
        }
        .field-checkbox {
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }
        .field-checkbox input {
          width: 1rem;
          height: 1rem;
        }
      </style>
      <c-page-layout title="Realms">
        <div slot="actions">
          <c-button variant="primary" @click=${() => this._openCreateModal()}>
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

      <c-modal title="Create Realm" @close=${() => this._closeCreateModal()}>
        ${showCreateModal ? html`
          <div class="form">
            <div class="field">
              <label class="field-label">Name *</label>
              <input
                class="field-input"
                type="text"
                placeholder="e.g. production"
                .value=${createName}
                @input=${(e) => this.setState({ createName: e.target.value })}
              />
              <div class="hint">Machine-readable identifier</div>
            </div>
            <div class="field">
              <label class="field-label">Display Name *</label>
              <input
                class="field-input"
                type="text"
                placeholder="e.g. Production"
                .value=${createDisplayName}
                @input=${(e) => this.setState({ createDisplayName: e.target.value })}
              />
              <div class="hint">Human-readable name</div>
            </div>
            <div class="field">
              <label class="field-checkbox">
                <input
                  type="checkbox"
                  ?checked=${createEnabled}
                  @change=${(e) => this.setState({ createEnabled: e.target.checked })}
                />
                Enabled
              </label>
            </div>
          </div>
        ` : ''}
        <div slot="footer">
          <c-button variant="secondary" @click=${() => this._closeCreateModal()}>Cancel</c-button>
          <c-button variant="primary" ?disabled=${createLoading || !createName.trim() || !createDisplayName.trim()} @click=${() => this._createRealm()}>
            ${createLoading ? 'Creating...' : 'Create'}
          </c-button>
        </div>
      </c-modal>
    `;
  }
}

customElements.define('realms-page', RealmsPage);
