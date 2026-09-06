import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { resolveSelectedRealmId, setSelectedRealmId } from '../core/realm-context.js';
import { listAllRealms } from '../services/realm-service.js';
import {
  createOrganization,
  deleteOrganization,
  listOrganizations,
} from '../services/organization-service.js';
import { showToast } from '../components/ui/toast.js';
import { handleApiError } from '../utils/error-handler.js';
import { navigate } from '../core/router.js';

const ConfirmDialog = customElements.get('c-modal');

class OrganizationsPage extends BaseComponent {
  constructor() {
    super();
    this._searchTimer = null;
    this._state = {
      organizations: [], realms: [], realmId: '', search: '', loading: true,
      page: 1, pageSize: 20, total: 0, showCreateModal: false,
      createName: '', createAlias: '', createLoading: false,
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
      const realmId = resolveSelectedRealmId(realms, this._state.realmId);
      setSelectedRealmId(realmId);
      await this.setState({ realms, realmId });
      this._loadOrganizations();
    } catch (error) {
      if (error.name === 'AbortError') return;
      handleApiError(error, 'Failed to load realms');
      this.setState({ realms: [], loading: false });
    }
  }

  async _loadOrganizations() {
    if (!this._state.realmId) {
      this.setState({ organizations: [], total: 0, loading: false });
      return;
    }
    this.setState({ loading: true });
    try {
      const { realmId, search, page, pageSize } = this._state;
      const data = await listOrganizations({
        realm_id: realmId,
        ...(search ? { search } : {}),
        limit: pageSize,
        offset: (page - 1) * pageSize,
      }, this.signal);
      this.setState({
        organizations: data.items || [], total: data.total || 0, loading: false,
      });
    } catch (error) {
      if (error.name === 'AbortError') return;
      handleApiError(error, 'Failed to load organizations');
      this.setState({ organizations: [], loading: false });
    }
  }

  async _onRealmChange(event) {
    const realmId = event.target.value;
    setSelectedRealmId(realmId);
    await this.setState({ realmId, page: 1 });
    this._loadOrganizations();
  }

  _onSearch(event) {
    this.setState({ search: event.target.value, page: 1 });
    clearTimeout(this._searchTimer);
    this._searchTimer = setTimeout(() => this._loadOrganizations(), 300);
  }

  _openCreate() {
    this.setState({ showCreateModal: true, createName: '', createAlias: '' });
    requestAnimationFrame(() => this.shadowRoot.querySelector('c-modal')?.open());
  }

  _closeCreate() {
    this.shadowRoot.querySelector('c-modal')?.close();
    this.setState({ showCreateModal: false, createLoading: false });
  }

  async _create() {
    const { realmId, createName, createAlias } = this._state;
    if (!realmId || !createName.trim() || !createAlias.trim()) return;
    this.setState({ createLoading: true });
    try {
      await createOrganization({
        realm_id: realmId,
        name: createName.trim(),
        alias: createAlias.trim().toLowerCase(),
      });
      this._closeCreate();
      showToast('Organization created', 'success');
      this._loadOrganizations();
    } catch (error) {
      if (error.name === 'AbortError') return;
      handleApiError(error, 'Failed to create organization');
      this.setState({ createLoading: false });
    }
  }

  async _delete(id) {
    const confirmed = await ConfirmDialog.confirm(
      'Delete this organization? Its memberships, domains, links, and invitations will be removed.',
      'Delete Organization',
    );
    if (!confirmed) return;
    try {
      await deleteOrganization(id);
      showToast('Organization deleted', 'success');
      this._loadOrganizations();
    } catch (error) {
      if (error.name === 'AbortError') return;
      handleApiError(error, 'Failed to delete organization');
    }
  }

  template() {
    const {
      organizations, realms, realmId, search, loading, page, pageSize, total,
      showCreateModal, createName, createAlias, createLoading,
    } = this._state;
    const columns = [
      { key: 'name', label: 'Name' },
      { key: 'alias', label: 'Alias' },
      {
        key: 'enabled', label: 'Enabled',
        render: (value) => value ? 'Yes' : 'No',
      },
      {
        key: 'id', label: 'Actions',
        render: (_, row) => html`
          <c-button size="sm" variant="secondary" @click=${() => navigate(`/organizations/${row.id}`)}>
            Manage
          </c-button>
          <c-button size="sm" variant="danger" @click=${() => this._delete(row.id)}>
            Delete
          </c-button>
        `,
      },
    ];

    return html`
      <c-page-layout title="Organizations">
        <div slot="actions">
          <c-button variant="primary" @click=${() => this._openCreate()}>+ Add Organization</c-button>
        </div>
        <div class="toolbar">
          <label style="font-size:0.875rem;color:var(--color-text-muted)">
            Realm:
            <select class="realm-select" aria-label="Select realm" .value=${realmId}
              @change=${(event) => this._onRealmChange(event)}>
              ${realms.map((realm) => html`
                <option value=${realm.id} ?selected=${realm.id === realmId}>
                  ${realm.display_name || realm.name}
                </option>
              `)}
            </select>
          </label>
          <input class="search-input" type="search" placeholder="Search organizations..."
            aria-label="Search organizations" .value=${search}
            @input=${(event) => this._onSearch(event)} />
        </div>
        ${loading
          ? html`<div class="empty-state"><div class="empty-state-text">Loading...</div></div>`
          : organizations.length
            ? html`<c-table .columns=${columns} .rows=${organizations}></c-table>`
            : html`<div class="empty-state">
                <div class="empty-state-icon">&#127970;</div>
                <div class="empty-state-text">${search ? 'No organizations match your search' : 'No organizations yet'}</div>
              </div>`}
        <c-pagination .page=${page} .pageSize=${pageSize} .total=${total}
          @page-change=${async (event) => {
            await this.setState({ page: event.detail.page });
            this._loadOrganizations();
          }}></c-pagination>
      </c-page-layout>

      <c-modal title="Create Organization" @close=${() => this._closeCreate()}>
        ${showCreateModal ? html`<div class="form">
          <div class="field">
            <label class="field-label" for="organization-name">Name *</label>
            <input id="organization-name" class="field-input" .value=${createName}
              @input=${(event) => this.setState({ createName: event.target.value })}
              placeholder="Acme Corporation" />
          </div>
          <div class="field">
            <label class="field-label" for="organization-alias">Alias *</label>
            <input id="organization-alias" class="field-input" .value=${createAlias}
              @input=${(event) => this.setState({ createAlias: event.target.value })}
              pattern="[a-z0-9]+(?:-[a-z0-9]+)*" placeholder="acme-corp" />
            <div class="hint">Lowercase letters, numbers, and internal hyphens.</div>
          </div>
        </div>` : ''}
        <div slot="footer">
          <c-button variant="secondary" @click=${() => this._closeCreate()}>Cancel</c-button>
          <c-button variant="primary" ?disabled=${createLoading || !createName.trim() || !createAlias.trim()}
            @click=${() => this._create()}>${createLoading ? 'Creating...' : 'Create'}</c-button>
        </div>
      </c-modal>
    `;
  }
}

customElements.define('organizations-page', OrganizationsPage);
