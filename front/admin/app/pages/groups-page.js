import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { listGroups, createGroup, deleteGroup } from '../services/group-service.js';
import { listAllRealms } from '../services/realm-service.js';
import { resolveSelectedRealmId, setSelectedRealmId } from '../core/realm-context.js';
import { listAllPages } from '../utils/http-utils.js';
import { navigate } from '../core/router.js';
import { showToast } from '../components/ui/toast.js';
import { handleApiError } from '../utils/error-handler.js';
import { isRequired } from '../utils/validators.js';

const ConfirmDialog = customElements.get('c-modal');

class GroupsPage extends BaseComponent {
  constructor() {
    super();
    this._searchTimer = null;
    this._parentSearchTimer = null;
    this._state = {
      groups: [],
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
      createParentId: '',
      createLoading: false,
      realms: [],
      allGroups: [],
      createParentOptions: [],
      createParentSearch: '',
      createParentPage: 1,
      createParentPageSize: 20,
      createParentTotal: 0,
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
    clearTimeout(this._parentSearchTimer);
  }

  async _loadRealms() {
    try {
      const realms = await listAllRealms(this.signal);
      const realmId = resolveSelectedRealmId(realms, this._state.realmId || this._state.createRealmId);
      setSelectedRealmId(realmId);
      await this.setState({ realms, realmId, createRealmId: realmId });
      this._loadGroups();
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to load realms');
      this.setState({ realms: [], realmId: '', createRealmId: '' });
      this._loadGroups();
    }
  }

  async _loadGroups() {
    this.setState({ loading: true });
    try {
      const { search, page, pageSize, realmId } = this._state;
      const offset = (page - 1) * pageSize;
      const data = await listGroups({
        ...(realmId ? { realm_id: realmId } : {}),
        ...(search ? { search } : {}),
        limit: String(pageSize),
        offset: String(offset),
      }, this.signal);
      this.setState({
        groups: data.items || [],
        total: data.total || 0,
        loading: false,
        selectedIds: new Set(),
      });
      const allGroups = await listAllPages(
        listGroups,
        realmId ? { realm_id: realmId } : {},
        this.signal,
      );
      this.setState({ allGroups });
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to load groups');
      this.setState({ groups: [], loading: false });
    }
  }

  _onSearch(e) {
    const value = e.target.value;
    this.setState({ search: value, page: 1 });
    clearTimeout(this._searchTimer);
    this._searchTimer = setTimeout(() => this._loadGroups(), 300);
  }

  async _onPageChange(e) {
    await this.setState({ page: e.detail.page });
    this._loadGroups();
  }

  async _onRealmChange(e) {
    const realmId = e.target.value;
    setSelectedRealmId(realmId);
    await this.setState({ realmId, createRealmId: realmId, page: 1 });
    this._loadGroups();
  }

  _toggleSelect(id) {
    const selected = new Set(this._state.selectedIds);
    if (selected.has(id)) { selected.delete(id); } else { selected.add(id); }
    this.setState({ selectedIds: selected });
  }

  _toggleSelectAll() {
    const { groups, selectedIds } = this._state;
    if (selectedIds.size === groups.length && groups.length > 0) {
      this.setState({ selectedIds: new Set() });
    } else {
      this.setState({ selectedIds: new Set(groups.map(g => g.id)) });
    }
  }

  async _bulkDelete() {
    const { selectedIds } = this._state;
    if (selectedIds.size === 0) return;
    const confirmed = await ConfirmDialog.confirm(`Delete ${selectedIds.size} group(s)? This cannot be undone.`, 'Bulk Delete');
    if (!confirmed) return;
    let success = 0;
    for (const id of selectedIds) {
      try {
        await deleteGroup(id);
        success++;
      } catch (err) {
        if (err.name === 'AbortError') return;
      }
    }
    showToast(`${success} group(s) deleted`, 'success');
    this._loadGroups();
  }

  async _deleteGroup(id) {
    const confirmed = await ConfirmDialog.confirm('Are you sure you want to delete this group?', 'Delete Group');
    if (!confirmed) return;
    try {
      await deleteGroup(id);
      showToast('Group deleted', 'success');
      this._loadGroups();
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to delete group');
    }
  }

  _openCreateModal() {
    this.setState({
      showCreateModal: true,
      createRealmId: this._state.realmId,
      createName: '',
      createDescription: '',
      createParentId: '',
      createParentSearch: '',
      createParentPage: 1,
      createLoading: false,
    });
    requestAnimationFrame(() => {
      const modal = this.shadowRoot.querySelector('c-modal');
      if (modal) modal.open();
    });
    this._loadCreateParentOptions(this._state.realmId, '', 1);
  }

  _closeCreateModal() {
    const modal = this.shadowRoot.querySelector('c-modal');
    if (modal) modal.close();
    this.setState({ showCreateModal: false });
  }

  async _loadCreateParentOptions(realmId = this._state.createRealmId, search = this._state.createParentSearch, page = this._state.createParentPage) {
    if (!realmId) {
      this.setState({ createParentOptions: [], createParentTotal: 0 });
      return;
    }

    const pageSize = this._state.createParentPageSize;
    const offset = (page - 1) * pageSize;
    try {
      const data = await listGroups({
        realm_id: realmId,
        ...(search ? { search } : {}),
        limit: String(pageSize),
        offset: String(offset),
      }, this.signal);
      this.setState({
        createParentOptions: data.items || [],
        createParentTotal: data.total || 0,
        createParentPage: page,
      });
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to load parent groups');
      this.setState({ createParentOptions: [], createParentTotal: 0 });
    }
  }

  async _onCreateRealmChange(e) {
    const createRealmId = e.target.value;
    await this.setState({
      createRealmId,
      createParentId: '',
      createParentSearch: '',
      createParentPage: 1,
    });
    this._loadCreateParentOptions(createRealmId, '', 1);
  }

  _onCreateParentSearch(e) {
    const value = e.target.value;
    this.setState({ createParentSearch: value, createParentPage: 1 });
    clearTimeout(this._parentSearchTimer);
    this._parentSearchTimer = setTimeout(() => this._loadCreateParentOptions(this._state.createRealmId, value, 1), 300);
  }

  async _onCreateParentPageChange(e) {
    const nextPage = e.detail.page;
    await this.setState({ createParentPage: nextPage });
    this._loadCreateParentOptions(this._state.createRealmId, this._state.createParentSearch, nextPage);
  }

  async _createGroup() {
    const { createRealmId, createName, createDescription, createParentId } = this._state;
    if (!isRequired(createRealmId) || !isRequired(createName)) return;

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
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to create group');
      this.setState({ createLoading: false });
    }
  }

  template() {
    const { groups, loading, search, page, pageSize, total, showCreateModal, realmId, createRealmId, createName, createDescription, createParentId, createLoading, realms, allGroups, createParentOptions, createParentSearch, createParentPage, createParentPageSize, createParentTotal, selectedIds } = this._state;
    const columns = [
      {
        key: 'select',
        label: html`<input type="checkbox" aria-label="Select all groups" ?checked=${selectedIds.size === groups.length && groups.length > 0} @change=${() => this._toggleSelectAll()} />`,
        render: (_, row) => html`<input type="checkbox" aria-label="Select group ${row.name}" ?checked=${selectedIds.has(row.id)} @change=${() => this._toggleSelect(row.id)} />`,
      },
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
      <c-page-layout title="Groups">
        <div slot="actions">
          <c-button variant="primary" @click=${() => this._openCreateModal()}>
            + Add Group
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
            placeholder="Search groups..."
            aria-label="Search groups"
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
        : groups.length === 0
          ? html`<div class="empty-state"><div class="empty-state-icon">&#128101;</div><div class="empty-state-text">${search ? 'No groups match your search' : 'No groups yet'}</div>${!search ? html`<c-button variant="primary" @click=${() => this._openCreateModal()}>+ Add Group</c-button>` : ''}</div>`
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
              <label class="field-label" for="create-group-realm">Realm *</label>
              <select
                class="field-select"
                id="create-group-realm"
                .value=${createRealmId}
                @change=${(e) => this._onCreateRealmChange(e)}
              >
                ${realms.map(r => html`<option value=${r.id} ?selected=${createRealmId === r.id}>${r.display_name || r.name}</option>`)}
              </select>
            </div>
            <div class="field">
              <label class="field-label" for="create-group-name">Name *</label>
              <input
                class="field-input"
                id="create-group-name"
                type="text"
                placeholder="e.g. engineering"
                .value=${createName}
                @input=${(e) => this.setState({ createName: e.target.value })}
              />
            </div>
            <div class="field">
              <label class="field-label" for="create-group-desc">Description</label>
              <input
                class="field-input"
                id="create-group-desc"
                type="text"
                placeholder="Optional description"
                .value=${createDescription}
                @input=${(e) => this.setState({ createDescription: e.target.value })}
              />
            </div>
            <div class="field">
              <label class="field-label" for="create-group-parent-search">Parent Group</label>
              <input
                class="field-input"
                id="create-group-parent-search"
                type="text"
                placeholder="Search parent groups..."
                .value=${createParentSearch}
                @input=${(e) => this._onCreateParentSearch(e)}
              />
              <select
                class="field-select"
                id="create-group-parent"
                .value=${createParentId}
                @change=${(e) => this.setState({ createParentId: e.target.value })}
              >
                <option value="">None</option>
                ${createParentOptions.map(g => html`<option value=${g.id} ?selected=${createParentId === g.id}>${g.name}</option>`)}
              </select>
              <div class="hint">Optional parent group. Search and page through groups in the selected realm.</div>
              <c-pagination
                .page=${createParentPage}
                .pageSize=${createParentPageSize}
                .total=${createParentTotal}
                @page-change=${(e) => this._onCreateParentPageChange(e)}
              ></c-pagination>
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
