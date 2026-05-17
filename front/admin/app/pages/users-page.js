import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { listUsers, createUser, deleteUser } from '../services/user-service.js';
import { listAllRealms } from '../services/realm-service.js';
import { resolveSelectedRealmId, setSelectedRealmId } from '../core/realm-context.js';
import { navigate } from '../core/router.js';
import { formatDate } from '../utils/format.js';
import { showToast } from '../components/ui/toast.js';
import { handleApiError } from '../utils/error-handler.js';
import { isEmail, isRequired, minLength } from '../utils/validators.js';

const ConfirmDialog = customElements.get('c-modal');

class UsersPage extends BaseComponent {
  constructor() {
    super();
    this._searchTimer = null;
    this._state = {
      users: [],
      loading: false,
      search: '',
      page: 1,
      pageSize: 20,
      total: 0,
      showCreateModal: false,
      realmId: '',
      createRealmId: '',
      createEmail: '',
      createPassword: '',
      createUsername: '',
      createFirstName: '',
      createLastName: '',
      createEnabled: true,
      createLoading: false,
      createErrors: {},
      realms: [],
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
      this._loadUsers();
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to load realms');
      this.setState({ realms: [], realmId: '', createRealmId: '' });
      this._loadUsers();
    }
  }

  async _loadUsers() {
    this.setState({ loading: true });
    try {
      const { search, page, pageSize, realmId } = this._state;
      const offset = (page - 1) * pageSize;
      const data = await listUsers({
        ...(realmId ? { realm_id: realmId } : {}),
        ...(search ? { search } : {}),
        limit: String(pageSize),
        offset: String(offset),
      }, this.signal);
      this.setState({
        users: data.items || [],
        total: data.total || 0,
        loading: false,
        selectedIds: new Set(),
      });
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to load users');
      this.setState({ users: [], loading: false });
    }
  }

  _onSearch(e) {
    const value = e.target.value;
    this.setState({ search: value, page: 1 });
    clearTimeout(this._searchTimer);
    this._searchTimer = setTimeout(() => this._loadUsers(), 300);
  }

  async _onPageChange(e) {
    await this.setState({ page: e.detail.page });
    this._loadUsers();
  }

  async _onRealmChange(e) {
    const realmId = e.target.value;
    setSelectedRealmId(realmId);
    await this.setState({ realmId, createRealmId: realmId, page: 1 });
    this._loadUsers();
  }

  _toggleSelect(id) {
    const selected = new Set(this._state.selectedIds);
    if (selected.has(id)) { selected.delete(id); } else { selected.add(id); }
    this.setState({ selectedIds: selected });
  }

  _toggleSelectAll() {
    const { users, selectedIds } = this._state;
    if (selectedIds.size === users.length && users.length > 0) {
      this.setState({ selectedIds: new Set() });
    } else {
      this.setState({ selectedIds: new Set(users.map(u => u.id)) });
    }
  }

  async _bulkDelete() {
    const { selectedIds } = this._state;
    if (selectedIds.size === 0) return;
    const confirmed = await ConfirmDialog.confirm(`Delete ${selectedIds.size} user(s)? This cannot be undone.`, 'Bulk Delete');
    if (!confirmed) return;
    let success = 0;
    for (const id of selectedIds) {
      try {
        await deleteUser(id);
        success++;
      } catch (err) {
        if (err.name === 'AbortError') return;
      }
    }
    showToast(`${success} user(s) deleted`, 'success');
    this._loadUsers();
  }

  async _deleteUser(id) {
    const confirmed = await ConfirmDialog.confirm('Are you sure you want to delete this user?', 'Delete User');
    if (!confirmed) return;
    try {
      await deleteUser(id);
      showToast('User deleted', 'success');
      this._loadUsers();
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to delete user');
    }
  }

  _openCreateModal() {
    this.setState({
      showCreateModal: true,
      createRealmId: this._state.realmId,
      createEmail: '',
      createPassword: '',
      createUsername: '',
      createFirstName: '',
      createLastName: '',
      createEnabled: true,
      createLoading: false,
      createErrors: {},
    });
    requestAnimationFrame(() => {
      const modal = this.shadowRoot.querySelector('c-modal');
      if (modal) modal.open();
    });
  }

  _closeCreateModal() {
    const modal = this.shadowRoot.querySelector('c-modal');
    if (modal) modal.close();
    this.setState({ showCreateModal: false, createErrors: {} });
  }

  _validateCreateForm() {
    const { createEmail, createPassword, createRealmId } = this._state;
    const errors = {};
    if (!isRequired(createRealmId)) errors.realm = 'Realm is required';
    if (!isEmail(createEmail)) errors.email = 'Valid email is required';
    if (!minLength(createPassword, 8)) errors.password = 'Password must be at least 8 characters';
    this.setState({ createErrors: errors });
    return Object.keys(errors).length === 0;
  }

  async _createUser() {
    if (!this._validateCreateForm()) return;
    const { createRealmId, createEmail, createPassword, createUsername, createFirstName, createLastName, createEnabled } = this._state;

    this.setState({ createLoading: true });
    try {
      await createUser({
        realm_id: createRealmId.trim(),
        email: createEmail.trim(),
        password: createPassword,
        username: createUsername.trim() || undefined,
        given_name: createFirstName.trim() || undefined,
        family_name: createLastName.trim() || undefined,
        enabled: createEnabled,
      });
      this._closeCreateModal();
      showToast('User created successfully', 'success');
      this._loadUsers();
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to create user');
      this.setState({ createLoading: false });
    }
  }

  template() {
    const { users, loading, search, page, pageSize, total, showCreateModal, realmId, createRealmId, createEmail, createPassword, createUsername, createFirstName, createLastName, createEnabled, createLoading, createErrors, realms, selectedIds } = this._state;
    const columns = [
      {
        key: 'select',
        label: html`<input type="checkbox" aria-label="Select all users" ?checked=${selectedIds.size === users.length && users.length > 0} @change=${() => this._toggleSelectAll()} />`,
        render: (_, row) => html`<input type="checkbox" aria-label="Select user ${row.email}" ?checked=${selectedIds.has(row.id)} @change=${() => this._toggleSelect(row.id)} />`,
      },
      { key: 'email', label: 'Email' },
      { key: 'username', label: 'Username' },
      { key: 'given_name', label: 'First Name' },
      { key: 'family_name', label: 'Last Name' },
      { key: 'enabled', label: 'Enabled', render: (v) => v ? html`<span style="color:var(--color-success)">Yes</span>` : html`<span style="color:var(--color-danger)">No</span>` },
      {
        key: 'id',
        label: 'Actions',
        render: (_, row) => html`
          <div style="display:flex;gap:0.5rem">
            <c-button size="sm" variant="secondary" @click=${() => navigate(`/users/${row.id}`)}>View</c-button>
            <c-button size="sm" variant="danger" @click=${() => this._deleteUser(row.id)}>Delete</c-button>
          </div>
        `,
      },
    ];

    return html`
      <c-page-layout title="Users">
        <div slot="actions">
          <c-button variant="primary" @click=${() => this._openCreateModal()}>
            + Add User
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
            placeholder="Search users..."
            aria-label="Search users"
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
        : users.length === 0
          ? html`
              <div class="empty-state">
                <div class="empty-state-icon">&#128100;</div>
                <div class="empty-state-text">${search ? 'No users match your search' : 'No users yet'}</div>
                ${!search ? html`<c-button variant="primary" @click=${() => this._openCreateModal()}>+ Add User</c-button>` : ''}
              </div>
            `
          : html`<c-table .columns=${columns} .rows=${users}></c-table>`}
        <c-pagination
          .page=${page}
          .pageSize=${pageSize}
          .total=${total}
          @page-change=${(e) => this._onPageChange(e)}
        ></c-pagination>
      </c-page-layout>

      <c-modal title="Create User" @close=${() => this._closeCreateModal()}>
        ${showCreateModal ? html`
          <div class="form">
            <div class="field">
              <label class="field-label" for="create-realm">Realm *</label>
              <select
                class="field-select ${createErrors.realm ? 'error' : ''}"
                id="create-realm"
                .value=${createRealmId}
                @change=${(e) => this.setState({ createRealmId: e.target.value, createErrors: { ...createErrors, realm: null } })}
              >
                ${realms.map(r => html`<option value=${r.id} ?selected=${createRealmId === r.id}>${r.display_name || r.name}</option>`)}
              </select>
              ${createErrors.realm ? html`<div class="field-error">${createErrors.realm}</div>` : ''}
            </div>
            <div class="field">
              <label class="field-label" for="create-email">Email *</label>
              <input
                class="field-input ${createErrors.email ? 'error' : ''}"
                id="create-email"
                type="email"
                placeholder="user@example.com"
                .value=${createEmail}
                @input=${(e) => this.setState({ createEmail: e.target.value, createErrors: { ...createErrors, email: null } })}
              />
              ${createErrors.email ? html`<div class="field-error">${createErrors.email}</div>` : ''}
            </div>
            <div class="field">
              <label class="field-label" for="create-password">Password *</label>
              <input
                class="field-input ${createErrors.password ? 'error' : ''}"
                id="create-password"
                type="password"
                placeholder="At least 8 characters"
                .value=${createPassword}
                @input=${(e) => this.setState({ createPassword: e.target.value, createErrors: { ...createErrors, password: null } })}
              />
              ${createErrors.password ? html`<div class="field-error">${createErrors.password}</div>` : ''}
              <div class="hint">Minimum 8 characters</div>
            </div>
            <div class="field">
              <label class="field-label" for="create-username">Username</label>
              <input
                class="field-input"
                id="create-username"
                type="text"
                placeholder="Optional"
                .value=${createUsername}
                @input=${(e) => this.setState({ createUsername: e.target.value })}
              />
            </div>
            <div class="field">
              <label class="field-label" for="create-firstname">First Name</label>
              <input
                class="field-input"
                id="create-firstname"
                type="text"
                placeholder="Optional"
                .value=${createFirstName}
                @input=${(e) => this.setState({ createFirstName: e.target.value })}
              />
            </div>
            <div class="field">
              <label class="field-label" for="create-lastname">Last Name</label>
              <input
                class="field-input"
                id="create-lastname"
                type="text"
                placeholder="Optional"
                .value=${createLastName}
                @input=${(e) => this.setState({ createLastName: e.target.value })}
              />
            </div>
            <div class="field">
              <label class="field-checkbox">
                <input
                  type="checkbox"
                  id="create-enabled"
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
          <c-button variant="primary" ?disabled=${createLoading} @click=${() => this._createUser()}>
            ${createLoading ? 'Creating...' : 'Create'}
          </c-button>
        </div>
      </c-modal>
    `;
  }
}

customElements.define('users-page', UsersPage);
