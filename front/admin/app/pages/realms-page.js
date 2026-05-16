import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { listRealms, createRealm, deleteRealm } from '../services/realm-service.js';
import { navigate } from '../core/router.js';
import { showToast } from '../components/ui/toast.js';
import { handleApiError } from '../utils/error-handler.js';
import { isRequired } from '../utils/validators.js';

const ConfirmDialog = customElements.get('c-modal');

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
      selectedIds: new Set(),
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
      const data = await listRealms({ limit: String(pageSize), offset: String(offset) }, this.signal);
      this.setState({
        realms: data.items || [],
        total: data.total || 0,
        loading: false,
        selectedIds: new Set(),
      });
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to load realms');
      this.setState({ realms: [], loading: false });
    }
  }

  async _onPageChange(e) {
    await this.setState({ page: e.detail.page });
    this._loadRealms();
  }

  _toggleSelect(id) {
    const selected = new Set(this._state.selectedIds);
    if (selected.has(id)) { selected.delete(id); } else { selected.add(id); }
    this.setState({ selectedIds: selected });
  }

  _toggleSelectAll() {
    const { realms, selectedIds } = this._state;
    if (selectedIds.size === realms.length && realms.length > 0) {
      this.setState({ selectedIds: new Set() });
    } else {
      this.setState({ selectedIds: new Set(realms.map(r => r.id)) });
    }
  }

  async _deleteRealm(id) {
    const confirmed = await ConfirmDialog.confirm('Are you sure you want to delete this realm? This will cascade to all users, clients, and sessions.', 'Delete Realm');
    if (!confirmed) return;
    try {
      await deleteRealm(id);
      showToast('Realm deleted', 'success');
      this._loadRealms();
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to delete realm');
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
    const modal = this.shadowRoot.querySelector('c-modal');
    if (modal) modal.close();
    this.setState({ showCreateModal: false });
  }

  async _createRealm() {
    const { createName, createDisplayName, createEnabled } = this._state;
    if (!isRequired(createName) || !isRequired(createDisplayName)) return;

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
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to create realm');
      this.setState({ createLoading: false });
    }
  }

  template() {
    const { realms, loading, page, pageSize, total, showCreateModal, createName, createDisplayName, createEnabled, createLoading, selectedIds } = this._state;
    const columns = [
      {
        key: 'select',
        label: html`<input type="checkbox" aria-label="Select all realms" ?checked=${selectedIds.size === realms.length && realms.length > 0} @change=${() => this._toggleSelectAll()} />`,
        render: (_, row) => html`<input type="checkbox" aria-label="Select realm ${row.name}" ?checked=${selectedIds.has(row.id)} @change=${() => this._toggleSelect(row.id)} />`,
      },
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
      <c-page-layout title="Realms">
        <div slot="actions">
          <c-button variant="primary" @click=${() => this._openCreateModal()}>
            + Add Realm
          </c-button>
        </div>
        ${selectedIds.size > 0 ? html`
          <div class="bulk-bar">
            <span>${selectedIds.size} selected</span>
            <span style="color:var(--color-text-muted);font-size:0.75rem">Bulk delete not available for realms (cascade risk)</span>
            <c-button size="sm" variant="ghost" @click=${() => this.setState({ selectedIds: new Set() })}>Clear</c-button>
          </div>
        ` : ''}
        ${loading
        ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>`
        : realms.length === 0
          ? html`<div class="empty-state"><div class="empty-state-icon">&#127758;</div><div class="empty-state-text">No realms yet</div><c-button variant="primary" @click=${() => this._openCreateModal()}>+ Add Realm</c-button></div>`
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
              <label class="field-label" for="create-realm-name">Name *</label>
              <input
                class="field-input"
                id="create-realm-name"
                type="text"
                placeholder="e.g. production"
                .value=${createName}
                @input=${(e) => this.setState({ createName: e.target.value })}
              />
              <div class="hint">Machine-readable identifier</div>
            </div>
            <div class="field">
              <label class="field-label" for="create-realm-display">Display Name *</label>
              <input
                class="field-input"
                id="create-realm-display"
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
                  id="create-realm-enabled"
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
