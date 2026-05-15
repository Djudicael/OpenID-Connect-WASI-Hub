import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { listRoles, createRole, deleteRole } from '../services/role-service.js';
import { listRealms } from '../services/realm-service.js';
import { navigate } from '../core/router.js';
import { showToast } from '../components/ui/toast.js';
import { handleApiError } from '../utils/error-handler.js';
import { isRequired } from '../utils/validators.js';

const ConfirmDialog = customElements.get('c-modal');

class RolesPage extends BaseComponent {
  constructor() {
    super();
    this._searchTimer = null;
    this._state = {
      roles: [],
      loading: false,
      search: '',
      page: 1,
      pageSize: 20,
      total: 0,
      showCreateModal: false,
      createRealmId: '',
      createName: '',
      createDescription: '',
      createPermissions: '',
      createLoading: false,
      realms: [],
      selectedIds: new Set(),
    };
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadRoles();
    this._loadRealms();
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    clearTimeout(this._searchTimer);
  }

  async _loadRealms() {
    try {
      const data = await listRealms({ limit: '100' }, this.signal);
      const realms = data.items || [];
      const defaultRealmId = realms.length > 0 ? realms[0].id : '';
      this.setState({ realms, createRealmId: defaultRealmId });
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to load realms');
      this.setState({ realms: [] });
    }
  }

  async _loadRoles() {
    this.setState({ loading: true });
    try {
      const { search, page, pageSize } = this._state;
      const offset = (page - 1) * pageSize;
      const data = await listRoles({
        ...(search ? { search } : {}),
        limit: String(pageSize),
        offset: String(offset),
      }, this.signal);
      this.setState({
        roles: data.items || [],
        total: data.total || 0,
        loading: false,
        selectedIds: new Set(),
      });
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to load roles');
      this.setState({ roles: [], loading: false });
    }
  }

  _onSearch(e) {
    const value = e.target.value;
    this.setState({ search: value, page: 1 });
    clearTimeout(this._searchTimer);
    this._searchTimer = setTimeout(() => this._loadRoles(), 300);
  }

  async _onPageChange(e) {
    await this.setState({ page: e.detail.page });
    this._loadRoles();
  }

  _toggleSelect(id) {
    const selected = new Set(this._state.selectedIds);
    if (selected.has(id)) { selected.delete(id); } else { selected.add(id); }
    this.setState({ selectedIds: selected });
  }

  _toggleSelectAll() {
    const { roles, selectedIds } = this._state;
    if (selectedIds.size === roles.length && roles.length > 0) {
      this.setState({ selectedIds: new Set() });
    } else {
      this.setState({ selectedIds: new Set(roles.map(r => r.id)) });
    }
  }

  async _bulkDelete() {
    const { selectedIds } = this._state;
    if (selectedIds.size === 0) return;
    const confirmed = await ConfirmDialog.confirm(`Delete ${selectedIds.size} role(s)? This cannot be undone.`, 'Bulk Delete');
    if (!confirmed) return;
    let success = 0;
    for (const id of selectedIds) {
      try {
        await deleteRole(id);
        success++;
      } catch (err) {
        if (err.name === 'AbortError') return;
      }
    }
    showToast(`${success} role(s) deleted`, 'success');
    this._loadRoles();
  }

  async _deleteRole(id) {
    const confirmed = await ConfirmDialog.confirm('Are you sure you want to delete this role?', 'Delete Role');
    if (!confirmed) return;
    try {
      await deleteRole(id);
      showToast('Role deleted', 'success');
      this._loadRoles();
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to delete role');
    }
  }

  _openCreateModal() {
    this.setState({
      showCreateModal: true,
      createName: '',
      createDescription: '',
      createPermissions: '',
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

  async _createRole() {
    const { createRealmId, createName, createDescription, createPermissions } = this._state;
    if (!isRequired(createRealmId) || !isRequired(createName)) return;

    this.setState({ createLoading: true });
    try {
      await createRole({
        realm_id: createRealmId.trim(),
        name: createName.trim(),
        description: createDescription.trim() || undefined,
        permissions: createPermissions.trim()
          ? createPermissions.split(',').map(p => p.trim()).filter(Boolean)
          : undefined,
      });
      this._closeCreateModal();
      showToast('Role created successfully', 'success');
      this._loadRoles();
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to create role');
      this.setState({ createLoading: false });
    }
  }

  template() {
    const { roles, loading, search, page, pageSize, total, showCreateModal, createRealmId, createName, createDescription, createPermissions, createLoading, realms, selectedIds } = this._state;
    const columns = [
      {
        key: 'select',
        label: html`<input type="checkbox" aria-label="Select all roles" ?checked=${selectedIds.size === roles.length && roles.length > 0} @change=${() => this._toggleSelectAll()} />`,
        render: (_, row) => html`<input type="checkbox" aria-label="Select role ${row.name}" ?checked=${selectedIds.has(row.id)} @change=${() => this._toggleSelect(row.id)} />`,
      },
      { key: 'name', label: 'Name' },
      { key: 'description', label: 'Description' },
      {
        key: 'permissions',
        label: 'Permissions',
        render: (v) => Array.isArray(v) ? v.join(', ') : (v || '-'),
      },
      {
        key: 'id',
        label: 'Actions',
        render: (_, row) => html`
          <div style="display:flex;gap:0.5rem">
            <c-button size="sm" variant="secondary" @click=${() => navigate(`/roles/${row.id}`)}>View</c-button>
            <c-button size="sm" variant="danger" @click=${() => this._deleteRole(row.id)}>Delete</c-button>
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
        .bulk-bar {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          padding: 0.5rem 1rem;
          background: #eff6ff;
          border: 1px solid #bfdbfe;
          border-radius: var(--radius-sm);
          margin-bottom: 1rem;
          font-size: 0.875rem;
        }
        .bulk-bar span { color: var(--color-primary); font-weight: 500; }
        .form { max-width: 32rem; }
        .field { margin-bottom: 1rem; }
        .field-label {
          display: block;
          font-size: 0.875rem;
          font-weight: 500;
          margin-bottom: 0.25rem;
        }
        .field-input, .field-select {
          width: 100%;
          padding: 0.5rem 0.75rem;
          font-size: 0.875rem;
          border: 1px solid #e2e8f0;
          border-radius: var(--radius-sm);
          font-family: inherit;
          box-sizing: border-box;
        }
        .field-input:focus, .field-select:focus {
          outline: none;
          border-color: var(--color-primary);
        }
        .hint {
          font-size: 0.75rem;
          color: var(--color-text-muted);
          margin-top: 0.25rem;
        }
        .empty-state {
          text-align: center;
          padding: 3rem 1rem;
          color: var(--color-text-muted);
        }
        .empty-state-icon { font-size: 2.5rem; margin-bottom: 0.75rem; opacity: 0.5; }
        .empty-state-text { font-size: 1rem; margin-bottom: 1rem; }
      </style>
      <c-page-layout title="Roles">
        <div slot="actions">
          <c-button variant="primary" @click=${() => this._openCreateModal()}>
            + Add Role
          </c-button>
        </div>
        <div class="toolbar">
          <input
            class="search-input"
            type="text"
            placeholder="Search roles..."
            aria-label="Search roles"
            .value=${search}
            @input=${(e) => this._onSearch(e)}
          />
        </div>
        ${selectedIds.size > 0 ? html`
          <div class="bulk-bar">
            <span>${selectedIds.size} selected</span>
            <c-button size="sm" variant="danger" @click=${() => this._bulkDelete()}>Delete Selected</c-button>
            <c-button size="sm" variant="ghost" @click=${() => this.setState({ selectedIds: new Set() })}>Clear</c-button>
          </div>
        ` : ''}
        ${loading
        ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>`
        : roles.length === 0
          ? html`<div class="empty-state"><div class="empty-state-icon">&#128273;</div><div class="empty-state-text">${search ? 'No roles match your search' : 'No roles yet'}</div>${!search ? html`<c-button variant="primary" @click=${() => this._openCreateModal()}>+ Add Role</c-button>` : ''}</div>`
          : html`<c-table .columns=${columns} .rows=${roles}></c-table>`}
        <c-pagination
          .page=${page}
          .pageSize=${pageSize}
          .total=${total}
          @page-change=${(e) => this._onPageChange(e)}
        ></c-pagination>
      </c-page-layout>

      <c-modal title="Create Role" @close=${() => this._closeCreateModal()}>
        ${showCreateModal ? html`
          <div class="form">
            <div class="field">
              <label class="field-label" for="create-role-realm">Realm *</label>
              <select
                class="field-select"
                id="create-role-realm"
                .value=${createRealmId}
                @change=${(e) => this.setState({ createRealmId: e.target.value })}
              >
                ${realms.map(r => html`<option value=${r.id} ?selected=${createRealmId === r.id}>${r.display_name || r.name}</option>`)}
              </select>
            </div>
            <div class="field">
              <label class="field-label" for="create-role-name">Name *</label>
              <input
                class="field-input"
                id="create-role-name"
                type="text"
                placeholder="e.g. admin"
                .value=${createName}
                @input=${(e) => this.setState({ createName: e.target.value })}
              />
            </div>
            <div class="field">
              <label class="field-label" for="create-role-desc">Description</label>
              <input
                class="field-input"
                id="create-role-desc"
                type="text"
                placeholder="Optional description"
                .value=${createDescription}
                @input=${(e) => this.setState({ createDescription: e.target.value })}
              />
            </div>
            <div class="field">
              <label class="field-label" for="create-role-perms">Permissions</label>
              <input
                class="field-input"
                id="create-role-perms"
                type="text"
                placeholder="e.g. users:read, users:write"
                .value=${createPermissions}
                @input=${(e) => this.setState({ createPermissions: e.target.value })}
              />
              <div class="hint">Comma-separated list of permissions</div>
            </div>
          </div>
        ` : ''}
        <div slot="footer">
          <c-button variant="secondary" @click=${() => this._closeCreateModal()}>Cancel</c-button>
          <c-button variant="primary" ?disabled=${createLoading || !createRealmId.trim() || !createName.trim()} @click=${() => this._createRole()}>
            ${createLoading ? 'Creating...' : 'Create'}
          </c-button>
        </div>
      </c-modal>
    `;
  }
}

customElements.define('roles-page', RolesPage);
