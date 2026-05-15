import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { listRoles, createRole, deleteRole } from '../services/role-service.js';
import { listRealms } from '../services/realm-service.js';
import { navigate } from '../core/router.js';
import { showToast } from '../components/ui/toast.js';

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
    };
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadRoles();
    this._loadRealms();
  }

  async _loadRealms() {
    try {
      const data = await listRealms({ limit: '100' });
      const realms = data.items || [];
      const defaultRealmId = realms.length > 0 ? realms[0].id : '';
      this.setState({ realms, createRealmId: defaultRealmId });
    } catch (err) {
      showToast('Failed to load realms', 'error');
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
      });
      this.setState({
        roles: data.items || [],
        total: data.total || 0,
        loading: false,
      });
    } catch (err) {
      showToast('Failed to load roles', 'error');
      this.setState({ roles: [], loading: false });
    }
  }

  _onSearch(e) {
    const value = e.target.value;
    this.setState({ search: value, page: 1 });
    clearTimeout(this._searchTimer);
    this._searchTimer = setTimeout(() => this._loadRoles(), 300);
  }

  _onPageChange(e) {
    this.setState({ page: e.detail.page }, this._loadRoles());
  }

  async _deleteRole(id) {
    if (!confirm('Are you sure you want to delete this role?')) return;
    try {
      await deleteRole(id);
      showToast('Role deleted', 'success');
      this._loadRoles();
    } catch (err) {
      showToast('Failed to delete role', 'error');
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
    this.shadowRoot.querySelector('c-modal').close();
    this.setState({ showCreateModal: false });
  }

  async _createRole() {
    const { createRealmId, createName, createDescription, createPermissions } = this._state;
    if (!createRealmId.trim() || !createName.trim()) return;

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
      showToast(err.body?.error || 'Failed to create role', 'error');
      this.setState({ createLoading: false });
    }
  }

  template() {
    const { roles, loading, search, page, pageSize, total, showCreateModal, createRealmId, createName, createDescription, createPermissions, createLoading, realms } = this._state;
    const columns = [
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
            .value=${search}
            @input=${(e) => this._onSearch(e)}
          />
        </div>
        ${loading
        ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>`
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
              <label class="field-label">Realm *</label>
              <select
                class="field-select"
                .value=${createRealmId}
                @change=${(e) => this.setState({ createRealmId: e.target.value })}
              >
                ${realms.map(r => html`<option value=${r.id} ?selected=${createRealmId === r.id}>${r.display_name || r.name}</option>`)}
              </select>
            </div>
            <div class="field">
              <label class="field-label">Name *</label>
              <input
                class="field-input"
                type="text"
                placeholder="e.g. admin"
                .value=${createName}
                @input=${(e) => this.setState({ createName: e.target.value })}
              />
            </div>
            <div class="field">
              <label class="field-label">Description</label>
              <input
                class="field-input"
                type="text"
                placeholder="Optional description"
                .value=${createDescription}
                @input=${(e) => this.setState({ createDescription: e.target.value })}
              />
            </div>
            <div class="field">
              <label class="field-label">Permissions</label>
              <input
                class="field-input"
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
