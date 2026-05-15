import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { listGroups, createGroup, deleteGroup } from '../services/group-service.js';
import { listRealms } from '../services/realm-service.js';
import { navigate } from '../core/router.js';
import { showToast } from '../components/ui/toast.js';

class GroupsPage extends BaseComponent {
  constructor() {
    super();
    this._searchTimer = null;
    this._state = {
      groups: [],
      loading: false,
      search: '',
      page: 1,
      pageSize: 20,
      total: 0,
      showCreateModal: false,
      createRealmId: '',
      createName: '',
      createDescription: '',
      createParentId: '',
      createLoading: false,
      realms: [],
      allGroups: [],
    };
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadGroups();
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

  async _loadGroups() {
    this.setState({ loading: true });
    try {
      const { search, page, pageSize } = this._state;
      const offset = (page - 1) * pageSize;
      const data = await listGroups({
        ...(search ? { search } : {}),
        limit: String(pageSize),
        offset: String(offset),
      });
      this.setState({
        groups: data.items || [],
        total: data.total || 0,
        loading: false,
      });
      // Also load all groups for parent dropdown
      const allData = await listGroups({ limit: '100' });
      this.setState({ allGroups: allData.items || [] });
    } catch (err) {
      showToast('Failed to load groups', 'error');
      this.setState({ groups: [], loading: false });
    }
  }

  _onSearch(e) {
    const value = e.target.value;
    this.setState({ search: value, page: 1 });
    clearTimeout(this._searchTimer);
    this._searchTimer = setTimeout(() => this._loadGroups(), 300);
  }

  _onPageChange(e) {
    this.setState({ page: e.detail.page }, this._loadGroups());
  }

  async _deleteGroup(id) {
    if (!confirm('Are you sure you want to delete this group?')) return;
    try {
      await deleteGroup(id);
      showToast('Group deleted', 'success');
      this._loadGroups();
    } catch (err) {
      showToast('Failed to delete group', 'error');
    }
  }

  _openCreateModal() {
    this.setState({
      showCreateModal: true,
      createName: '',
      createDescription: '',
      createParentId: '',
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

  async _createGroup() {
    const { createRealmId, createName, createDescription, createParentId } = this._state;
    if (!createRealmId.trim() || !createName.trim()) return;

    this.setState({ createLoading: true });
    try {
      await createGroup({
        realm_id: createRealmId.trim(),
        name: createName.trim(),
        description: createDescription.trim() || undefined,
        parent_id: createParentId.trim() || undefined,
      });
      this._closeCreateModal();
      showToast('Group created successfully', 'success');
      this._loadGroups();
    } catch (err) {
      showToast(err.body?.error || 'Failed to create group', 'error');
      this.setState({ createLoading: false });
    }
  }

  template() {
    const { groups, loading, search, page, pageSize, total, showCreateModal, createRealmId, createName, createDescription, createParentId, createLoading, realms, allGroups } = this._state;
    const columns = [
      { key: 'name', label: 'Name' },
      { key: 'description', label: 'Description' },
      {
        key: 'parent_id',
        label: 'Parent',
        render: (v) => {
          if (!v) return '-';
          const parent = allGroups.find(g => g.id === v);
          return parent ? parent.name : v;
        },
      },
      {
        key: 'id',
        label: 'Actions',
        render: (_, row) => html`
          <div style="display:flex;gap:0.5rem">
            <c-button size="sm" variant="secondary" @click=${() => navigate(`/groups/${row.id}`)}>View</c-button>
            <c-button size="sm" variant="danger" @click=${() => this._deleteGroup(row.id)}>Delete</c-button>
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
      <c-page-layout title="Groups">
        <div slot="actions">
          <c-button variant="primary" @click=${() => this._openCreateModal()}>
            + Add Group
          </c-button>
        </div>
        <div class="toolbar">
          <input
            class="search-input"
            type="text"
            placeholder="Search groups..."
            .value=${search}
            @input=${(e) => this._onSearch(e)}
          />
        </div>
        ${loading
        ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>`
        : html`<c-table .columns=${columns} .rows=${groups}></c-table>`}
        <c-pagination
          .page=${page}
          .pageSize=${pageSize}
          .total=${total}
          @page-change=${(e) => this._onPageChange(e)}
        ></c-pagination>
      </c-page-layout>

      <c-modal title="Create Group" @close=${() => this._closeCreateModal()}>
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
                placeholder="e.g. engineering"
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
              <label class="field-label">Parent Group</label>
              <select
                class="field-select"
                .value=${createParentId}
                @change=${(e) => this.setState({ createParentId: e.target.value })}
              >
                <option value="">None</option>
                ${allGroups.map(g => html`<option value=${g.id} ?selected=${createParentId === g.id}>${g.name}</option>`)}
              </select>
              <div class="hint">Optional parent group</div>
            </div>
          </div>
        ` : ''}
        <div slot="footer">
          <c-button variant="secondary" @click=${() => this._closeCreateModal()}>Cancel</c-button>
          <c-button variant="primary" ?disabled=${createLoading || !createRealmId.trim() || !createName.trim()} @click=${() => this._createGroup()}>
            ${createLoading ? 'Creating...' : 'Create'}
          </c-button>
        </div>
      </c-modal>
    `;
  }
}

customElements.define('groups-page', GroupsPage);
