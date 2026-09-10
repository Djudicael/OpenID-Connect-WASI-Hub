import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { listRoles, createRole, deleteRole } from '../services/role-service.js';
import { listAllRealms } from '../services/realm-service.js';
import { listClients } from '../services/client-service.js';
import { resolveSelectedRealmId, setSelectedRealmId } from '../core/realm-context.js';
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
      realmId: '',
      createRealmId: '',
      createName: '',
      createDescription: '',
      createPermissions: '',
      createType: 'realm',
      createClientId: '',
      createLoading: false,
      realms: [],
      clients: [],
      selectedIds: new Set(),
    };
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadRealms();
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    clearTimeout(this._searchTimer);
  }

  async _loadRealms() {
    try {
      const realms = await listAllRealms(this.signal);
      const realmId = resolveSelectedRealmId(realms, this._state.realmId || this._state.createRealmId);
      setSelectedRealmId(realmId);
      await this.setState({ realms, realmId, createRealmId: realmId });
      await this._loadClients(realmId);
      this._loadRoles();
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to load realms');
      this.setState({ realms: [], realmId: '', createRealmId: '' });
      this._loadRoles();
    }
  }

  async _loadClients(realmId) {
    if (!realmId) return this.setState({ clients: [] });
    try {
      const data = await listClients({ realm_id: realmId, limit: '1000', offset: '0' }, this.signal);
      this.setState({ clients: data.items || [] });
    } catch (err) {
      if (err.name !== 'AbortError') handleApiError(err, 'Failed to load clients');
      this.setState({ clients: [] });
    }
  }

  async _loadRoles() {
    this.setState({ loading: true });
    try {
      const { search, page, pageSize, realmId } = this._state;
      const offset = (page - 1) * pageSize;
      const data = await listRoles({
        ...(realmId ? { realm_id: realmId } : {}),
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

  async _onRealmChange(e) {
    const realmId = e.target.value;
    setSelectedRealmId(realmId);
    await this.setState({ realmId, createRealmId: realmId, page: 1 });
    await this._loadClients(realmId);
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
      createRealmId: this._state.realmId,
      createName: '',
      createDescription: '',
      createPermissions: '',
      createType: 'realm',
      createClientId: '',
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
    const { createRealmId, createName, createDescription, createPermissions, createType, createClientId } = this._state;
    if (!isRequired(createRealmId) || !isRequired(createName)) return;
    if (createType === 'client' && !isRequired(createClientId)) return;

    this.setState({ createLoading: true });
    try {
      await createRole({
        realm_id: createRealmId.trim(),
        name: createName.trim(),
        description: createDescription.trim() || undefined,
        permissions: createPermissions.trim()
          ? createPermissions.split(',').map(p => p.trim()).filter(Boolean)
          : [],
        client_id: createType === 'client' ? createClientId : undefined,
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
    const { roles, loading, search, page, pageSize, total, showCreateModal, realmId, createRealmId, createName, createDescription, createPermissions, createType, createClientId, createLoading, realms, clients, selectedIds } = this._state;
    const clientNames = new Map(clients.map(client => [client.id, client.client_id || client.name]));
    const columns = [
      {
        key: 'select',
        label: html`<input type="checkbox" aria-label="Select all roles" ?checked=${selectedIds.size === roles.length && roles.length > 0} @change=${() => this._toggleSelectAll()} />`,
        render: (_, row) => html`<input type="checkbox" aria-label="Select role ${row.name}" ?checked=${selectedIds.has(row.id)} @change=${() => this._toggleSelect(row.id)} />`,
      },
      { key: 'name', label: 'Name' },
      { key: 'description', label: 'Description' },
      {
        key: 'client_id',
        label: 'Scope',
        render: (value) => value ? `Client: ${clientNames.get(value) || value}` : 'Realm',
      },
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
      <c-page-layout title="Roles">
        <div slot="actions">
          <c-button variant="primary" @click=${() => this._openCreateModal()}>
            + Add Role
          </c-button>
        </div>
        <div class="toolbar">
          <label style="font-size:0.875rem;color:var(--color-text-muted)">
            Realm:
            <select class="realm-select" aria-label="Select realm" .value=${realmId} @change=${(e) => this._onRealmChange(e)}>
              ${realms.map(r => html`<option value=${r.id} ?selected=${realmId === r.id}>${r.display_name || r.name}</option>`)}
            </select>
          </label>
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
                @change=${async (e) => { await this.setState({ createRealmId: e.target.value, createClientId: '' }); this._loadClients(e.target.value); }}
              >
                ${realms.map(r => html`<option value=${r.id} ?selected=${createRealmId === r.id}>${r.display_name || r.name}</option>`)}
              </select>
            </div>
            <div class="field">
              <label class="field-label" for="create-role-type">Role type *</label>
              <select class="field-select" id="create-role-type" .value=${createType} @change=${(e) => this.setState({ createType: e.target.value, createClientId: '' })}>
                <option value="realm">Realm role</option>
                <option value="client">Client role</option>
              </select>
              <div class="hint">Realm roles apply across the realm. Client roles apply to one application.</div>
            </div>
            ${createType === 'client' ? html`<div class="field">
              <label class="field-label" for="create-role-client">Client *</label>
              <select class="field-select" id="create-role-client" .value=${createClientId} @change=${(e) => this.setState({ createClientId: e.target.value })}>
                <option value="">Select a client</option>
                ${clients.map(client => html`<option value=${client.id}>${client.client_id || client.name}</option>`)}
              </select>
            </div>` : ''}
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
              <div class="hint">Comma-separated, for example users:read, clients:read, or users:*</div>
            </div>
          </div>
        ` : ''}
        <div slot="footer">
          <c-button variant="secondary" @click=${() => this._closeCreateModal()}>Cancel</c-button>
          <c-button variant="primary" ?disabled=${createLoading || !createRealmId.trim() || !createName.trim() || (createType === 'client' && !createClientId)} @click=${() => this._createRole()}>
            ${createLoading ? 'Creating...' : 'Create'}
          </c-button>
        </div>
      </c-modal>
    `;
  }
}

customElements.define('roles-page', RolesPage);
