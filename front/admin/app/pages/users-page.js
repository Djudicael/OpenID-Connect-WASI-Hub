import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { get, post, del } from '../core/http.js';
import { navigate } from '../core/router.js';
import { formatDate } from '../utils/format.js';
import { showToast } from '../components/ui/toast.js';

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
      createRealmId: '',
      createEmail: '',
      createPassword: '',
      createUsername: '',
      createFirstName: '',
      createLastName: '',
      createEnabled: true,
      createLoading: false,
    };
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadUsers();
  }

  async _loadUsers() {
    this.setState({ loading: true });
    try {
      const { search, page, pageSize } = this._state;
      const offset = (page - 1) * pageSize;
      const params = new URLSearchParams();
      if (search) params.set('search', search);
      params.set('limit', String(pageSize));
      params.set('offset', String(offset));

      const data = await get(`/api/users?${params.toString()}`);
      this.setState({
        users: data.items || [],
        total: data.total || 0,
        loading: false,
      });
    } catch (err) {
      showToast('Failed to load users', 'error');
      this.setState({ users: [], loading: false });
    }
  }

  _onSearch(e) {
    const value = e.target.value;
    this.setState({ search: value, page: 1 });
    clearTimeout(this._searchTimer);
    this._searchTimer = setTimeout(() => this._loadUsers(), 300);
  }

  _onPageChange(e) {
    this.setState({ page: e.detail.page }, this._loadUsers());
  }

  async _deleteUser(id) {
    if (!confirm('Are you sure you want to delete this user?')) return;
    try {
      await del(`/api/users/${id}`);
      showToast('User deleted', 'success');
      this._loadUsers();
    } catch (err) {
      showToast('Failed to delete user', 'error');
    }
  }

  _openCreateModal() {
    this.setState({
      showCreateModal: true,
      createRealmId: '',
      createEmail: '',
      createPassword: '',
      createUsername: '',
      createFirstName: '',
      createLastName: '',
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

  async _createUser() {
    const { createRealmId, createEmail, createPassword, createUsername, createFirstName, createLastName, createEnabled } = this._state;
    if (!createRealmId.trim() || !createEmail.trim() || !createPassword.trim()) return;

    this.setState({ createLoading: true });
    try {
      await post('/api/users', {
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
      showToast(err.body?.error || 'Failed to create user', 'error');
      this.setState({ createLoading: false });
    }
  }

  template() {
    const { users, loading, search, page, pageSize, total, showCreateModal, createRealmId, createEmail, createPassword, createUsername, createFirstName, createLastName, createEnabled, createLoading } = this._state;
    const columns = [
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
      <c-page-layout title="Users">
        <div slot="actions">
          <c-button variant="primary" @click=${() => this._openCreateModal()}>
            + Add User
          </c-button>
        </div>
        <div class="toolbar">
          <input
            class="search-input"
            type="text"
            placeholder="Search users..."
            .value=${search}
            @input=${(e) => this._onSearch(e)}
          />
        </div>
        ${loading
        ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>`
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
              <label class="field-label">Realm ID *</label>
              <input
                class="field-input"
                type="text"
                placeholder="Enter realm UUID"
                .value=${createRealmId}
                @input=${(e) => this.setState({ createRealmId: e.target.value })}
              />
            </div>
            <div class="field">
              <label class="field-label">Email *</label>
              <input
                class="field-input"
                type="email"
                placeholder="user@example.com"
                .value=${createEmail}
                @input=${(e) => this.setState({ createEmail: e.target.value })}
              />
            </div>
            <div class="field">
              <label class="field-label">Password *</label>
              <input
                class="field-input"
                type="password"
                placeholder="Password"
                .value=${createPassword}
                @input=${(e) => this.setState({ createPassword: e.target.value })}
              />
            </div>
            <div class="field">
              <label class="field-label">Username</label>
              <input
                class="field-input"
                type="text"
                placeholder="Optional"
                .value=${createUsername}
                @input=${(e) => this.setState({ createUsername: e.target.value })}
              />
            </div>
            <div class="field">
              <label class="field-label">First Name</label>
              <input
                class="field-input"
                type="text"
                placeholder="Optional"
                .value=${createFirstName}
                @input=${(e) => this.setState({ createFirstName: e.target.value })}
              />
            </div>
            <div class="field">
              <label class="field-label">Last Name</label>
              <input
                class="field-input"
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
          <c-button variant="primary" ?disabled=${createLoading || !createRealmId.trim() || !createEmail.trim() || !createPassword.trim()} @click=${() => this._createUser()}>
            ${createLoading ? 'Creating...' : 'Create'}
          </c-button>
        </div>
      </c-modal>
    `;
  }
}

customElements.define('users-page', UsersPage);
