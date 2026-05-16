import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { listScopes, createScope, deleteScope } from '../services/scope-service.js';
import { listRealms } from '../services/realm-service.js';
import { showToast } from '../components/ui/toast.js';

class ScopesPage extends BaseComponent {
  constructor() {
    super();
    this._state = {
      scopes: [],
      realms: [],
      realmId: '',
      loading: false,
      showCreateModal: false,
      createName: '',
      createDescription: '',
      createEnabled: true,
      createLoading: false,
    };
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadRealms();
  }

  async _loadRealms() {
    try {
      const data = await listRealms({ limit: '100' });
      const realms = data.items || [];
      const defaultRealmId = realms.length > 0 ? realms[0].id : '';
      this.setState({ realms, realmId: defaultRealmId });
      if (defaultRealmId) this._loadScopes();
    } catch (err) {
      showToast('Failed to load realms', 'error');
    }
  }

  async _loadScopes() {
    const { realmId } = this._state;
    if (!realmId) return;
    this.setState({ loading: true });
    try {
      const data = await listScopes(realmId);
      this.setState({ scopes: data.items || [], loading: false });
    } catch (err) {
      showToast('Failed to load scopes', 'error');
      this.setState({ scopes: [], loading: false });
    }
  }

  _onRealmChange(e) {
    this.setState({ realmId: e.target.value });
    requestAnimationFrame(() => this._loadScopes());
  }

  _openCreateModal() {
    this.setState({ showCreateModal: true, createName: '', createDescription: '', createEnabled: true, createLoading: false });
    requestAnimationFrame(() => {
      const modal = this.shadowRoot.querySelector('c-modal');
      if (modal) modal.open();
    });
  }

  _closeCreateModal() {
    this.shadowRoot.querySelector('c-modal').close();
    this.setState({ showCreateModal: false });
  }

  async _createScope() {
    const { realmId, createName, createDescription, createEnabled } = this._state;
    if (!createName.trim()) return;
    this.setState({ createLoading: true });
    try {
      await createScope({ realm_id: realmId, name: createName.trim(), description: createDescription.trim() || null, enabled: createEnabled });
      this._closeCreateModal();
      showToast('Scope created', 'success');
      this._loadScopes();
    } catch (err) {
      showToast(err.body?.error || 'Failed to create scope', 'error');
      this.setState({ createLoading: false });
    }
  }

  async _deleteScope(id) {
    if (!confirm('Delete this scope? Clients using it will lose access.')) return;
    try {
      await deleteScope(id);
      showToast('Scope deleted', 'success');
      this._loadScopes();
    } catch (err) {
      showToast('Failed to delete scope', 'error');
    }
  }

  template() {
    const { scopes, realms, realmId, loading, showCreateModal, createName, createDescription, createEnabled, createLoading } = this._state;
    const columns = [
      { key: 'name', label: 'Name' },
      { key: 'description', label: 'Description', render: (v) => v || '-' },
      { key: 'enabled', label: 'Enabled', render: (v) => v ? html`<span style="color:var(--color-success)">Yes</span>` : html`<span style="color:var(--color-danger)">No</span>` },
      { key: 'id', label: 'Actions', render: (_, row) => html`<div style="display:flex;gap:0.5rem"><c-button size="sm" variant="danger" @click=${() => this._deleteScope(row.id)}>Delete</c-button></div>` },
    ];

    return html`<c-page-layout title="Scopes">
        <div slot="actions"><c-button variant="primary" @click=${() => this._openCreateModal()}>+ Add Scope</c-button></div>
        <div class="toolbar">
          <label style="font-size:.875rem;color:var(--color-text-muted)">Realm:
            <select class="realm-select" .value=${realmId} @change=${(e) => this._onRealmChange(e)}>${realms.map(r => html`<option value=${r.id}>${r.display_name || r.name}</option>`)}</select>
          </label>
        </div>
        ${loading ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>` : html`<c-table .columns=${columns} .rows=${scopes}></c-table>`}
      </c-page-layout>
      <c-modal title="Create Scope" @close=${() => this._closeCreateModal()}>
        ${showCreateModal ? html`<div class="form">
          <div class="field"><label class="field-label">Name *</label><input class="field-input" type="text" placeholder="e.g. admin, read:users" .value=${createName} @input=${(e) => this.setState({ createName: e.target.value })}/></div>
          <div class="field"><label class="field-label">Description</label><input class="field-input" type="text" placeholder="Optional" .value=${createDescription} @input=${(e) => this.setState({ createDescription: e.target.value })}/></div>
          <div class="field"><label class="field-checkbox"><input type="checkbox" ?checked=${createEnabled} @change=${(e) => this.setState({ createEnabled: e.target.checked })}/>Enabled</label></div>
        </div>` : ''}
        <div slot="footer"><c-button variant="secondary" @click=${() => this._closeCreateModal()}>Cancel</c-button><c-button variant="primary" ?disabled=${createLoading || !createName.trim()} @click=${() => this._createScope()}>${createLoading ? 'Creating...' : 'Create'}</c-button></div>
      </c-modal>`;
  }
}
customElements.define('scopes-page', ScopesPage);
