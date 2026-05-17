import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { listClients, createClient, deleteClient } from '../services/client-service.js';
import { listAllRealms } from '../services/realm-service.js';
import { resolveSelectedRealmId, setSelectedRealmId } from '../core/realm-context.js';
import { listScopes } from '../services/scope-service.js';
import { navigate } from '../core/router.js';
import { showToast } from '../components/ui/toast.js';
import { handleApiError } from '../utils/error-handler.js';
import { isRequired, minLength, isEmail } from '../utils/validators.js';

const ConfirmDialog = customElements.get('c-modal');

class ClientsPage extends BaseComponent {
  constructor() {
    super();
    this._searchTimer = null;
    this._state = {
      clients: [],
      loading: false,
      search: '',
      page: 1,
      pageSize: 20,
      total: 0,
      showCreateModal: false,
      realmId: '',
      createRealmId: '',
      createClientId: '',
      createName: '',
      createClientType: 'confidential',
      createClientSecret: '',
      createRedirectUris: '',
      createAllowedScopes: 'openid',
      createAllowedGrantTypes: ['authorization_code'],
      createPkceRequired: true,
      createEnabled: true,
      createLoading: false,
      realms: [],
      availableScopes: [],
      selectedScopes: [],
      selectedIds: new Set(),
    };
  }

  static get GRANT_TYPES() {
    return [
      { value: 'authorization_code', label: 'Authorization Code', desc: 'Standard web app flow (recommended)' },
      { value: 'refresh_token', label: 'Refresh Token', desc: 'Long-lived sessions' },
      { value: 'client_credentials', label: 'Client Credentials', desc: 'Server-to-server (no user)' },
      { value: 'device_code', label: 'Device Code', desc: 'TVs, IoT, CLI apps' },
      { value: 'authorization_code_oidc', label: 'Auth Code + OIDC', desc: 'Authorization Code with OpenID Connect' },
    ];
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
      this._loadScopesForRealm(realmId);
      this._loadClients();
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to load realms');
      this.setState({ realms: [], realmId: '', createRealmId: '' });
      this._loadClients();
    }
  }

  async _loadScopesForRealm(realmId) {
    if (!realmId) return;
    try {
      const data = await listScopes(realmId, this.signal);
      const scopes = (data.items || []).filter(s => s.enabled);
      const names = scopes.map(s => s.name);
      this.setState({ availableScopes: scopes, selectedScopes: names, createAllowedScopes: names.join(', ') });
    } catch (_) {
      // Scopes endpoint may not exist yet
    }
  }

  async _loadClients() {
    this.setState({ loading: true });
    try {
      const { search, page, pageSize, realmId } = this._state;
      const offset = (page - 1) * pageSize;
      const data = await listClients({
        ...(realmId ? { realm_id: realmId } : {}),
        ...(search ? { search } : {}),
        limit: String(pageSize),
        offset: String(offset),
      }, this.signal);
      this.setState({ clients: data.items || [], total: data.total || 0, loading: false, selectedIds: new Set() });
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to load clients');
      this.setState({ clients: [], loading: false });
    }
  }

  _onSearch(e) {
    const value = e.target.value;
    this.setState({ search: value, page: 1 });
    clearTimeout(this._searchTimer);
    this._searchTimer = setTimeout(() => this._loadClients(), 300);
  }

  async _onPageChange(e) {
    await this.setState({ page: e.detail.page });
    this._loadClients();
  }

  async _onRealmChange(e) {
    const realmId = e.target.value;
    setSelectedRealmId(realmId);
    await this.setState({ realmId, createRealmId: realmId, page: 1 });
    this._loadScopesForRealm(realmId);
    this._loadClients();
  }

  _toggleSelect(id) {
    const selected = new Set(this._state.selectedIds);
    if (selected.has(id)) { selected.delete(id); } else { selected.add(id); }
    this.setState({ selectedIds: selected });
  }

  _toggleSelectAll() {
    const { clients, selectedIds } = this._state;
    if (selectedIds.size === clients.length && clients.length > 0) {
      this.setState({ selectedIds: new Set() });
    } else {
      this.setState({ selectedIds: new Set(clients.map(c => c.id)) });
    }
  }

  async _bulkDelete() {
    const { selectedIds } = this._state;
    if (selectedIds.size === 0) return;
    const confirmed = await ConfirmDialog.confirm(`Delete ${selectedIds.size} client(s)? This cannot be undone.`, 'Bulk Delete');
    if (!confirmed) return;
    let success = 0;
    for (const id of selectedIds) {
      try {
        await deleteClient(id);
        success++;
      } catch (err) {
        if (err.name === 'AbortError') return;
      }
    }
    showToast(`${success} client(s) deleted`, 'success');
    this._loadClients();
  }

  async _deleteClient(id) {
    const confirmed = await ConfirmDialog.confirm('Are you sure you want to delete this client?', 'Delete Client');
    if (!confirmed) return;
    try {
      await deleteClient(id);
      showToast('Client deleted', 'success');
      this._loadClients();
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to delete client');
    }
  }

  _openCreateModal() {
    this.setState({
      showCreateModal: true,
      createRealmId: this._state.realmId,
      createClientId: '',
      createName: '',
      createClientType: 'confidential',
      createClientSecret: '',
      createRedirectUris: '',
      createAllowedScopes: 'openid',
      createAllowedGrantTypes: ['authorization_code'],
      createPkceRequired: true,
      createEnabled: true,
      createLoading: false,
    });
    this._loadScopesForRealm(this._state.createRealmId);
    requestAnimationFrame(() => {
      const modal = this.shadowRoot.querySelector('c-modal');
      if (modal) modal.open();
    });
  }

  _closeCreateModal() {
    this.shadowRoot.querySelector('c-modal').close();
    this.setState({ showCreateModal: false });
  }

  _toggleScope(name, checked) {
    const selected = [...this._state.selectedScopes];
    if (checked) { if (!selected.includes(name)) selected.push(name); }
    else { const i = selected.indexOf(name); if (i >= 0) selected.splice(i, 1); }
    this.setState({ selectedScopes: selected, createAllowedScopes: selected.join(', ') });
  }

  _toggleGrantType(value, checked) {
    const selected = [...this._state.createAllowedGrantTypes];
    if (checked) { if (!selected.includes(value)) selected.push(value); }
    else { const i = selected.indexOf(value); if (i >= 0) selected.splice(i, 1); }
    this.setState({ createAllowedGrantTypes: selected });
  }

  async _createClient() {
    const { createRealmId, createClientId, createName, createClientType, createClientSecret, createRedirectUris, createAllowedScopes, createAllowedGrantTypes, createPkceRequired, createEnabled } = this._state;
    if (!isRequired(createClientId)) { showToast('Client ID is required', 'error'); return; }
    if (!minLength(createClientId, 3)) { showToast('Client ID must be at least 3 chars', 'error'); return; }
    if (!isRequired(createName)) { showToast('Name is required', 'error'); return; }
    if (!minLength(createName, 2)) { showToast('Name must be at least 2 chars', 'error'); return; }
    if (createRedirectUris.trim()) {
      const uris = createRedirectUris.split('\n').map(s => s.trim()).filter(Boolean);
      for (const uri of uris) {
        try { new URL(uri); } catch { showToast('Invalid redirect URI: ' + uri, 'error'); return; }
      }
    }
    if (createAllowedGrantTypes.length === 0) { showToast('At least one grant type is required', 'error'); return; }
    const body = {
      realm_id: createRealmId.trim(),
      client_id: createClientId.trim(),
      name: createName.trim(),
      client_type: createClientType,
      redirect_uris: createRedirectUris.split('\n').map(s => s.trim()).filter(Boolean),
      allowed_scopes: createAllowedScopes.split(',').map(s => s.trim()).filter(Boolean),
      allowed_grant_types: createAllowedGrantTypes,
      pkce_required: createPkceRequired,
      enabled: createEnabled,
    };
    if (createClientType === 'confidential' && createClientSecret.trim()) body.client_secret = createClientSecret.trim();
    this.setState({ createLoading: true });
    try {
      const data = await createClient(body);
      this._closeCreateModal();
      showToast('Client created', 'success');
      if (data.client_secret) {
        const s = data.client_secret;
        navigator.clipboard.writeText(s).catch(() => { const inp = document.createElement('input'); inp.value = s; inp.style.cssText = 'position:fixed;left:-9999px'; document.body.appendChild(inp); inp.select(); document.execCommand('copy'); document.body.removeChild(inp); });
        showToast('Secret copied to clipboard', 'success');
      }
      this._loadClients();
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to create client');
      this.setState({ createLoading: false });
    }
  }

  template() {
    const { clients, loading, search, page, pageSize, total, showCreateModal, realmId, createRealmId, createClientId, createName, createClientType, createClientSecret, createRedirectUris, createAllowedScopes, createAllowedGrantTypes, createPkceRequired, createEnabled, createLoading, realms, availableScopes, selectedScopes, selectedIds } = this._state;
    const columns = [
      {
        key: 'select',
        label: html`<input type="checkbox" aria-label="Select all clients" ?checked=${selectedIds.size === clients.length && clients.length > 0} @change=${() => this._toggleSelectAll()} />`,
        render: (_, row) => html`<input type="checkbox" aria-label="Select client ${row.client_id}" ?checked=${selectedIds.has(row.id)} @change=${() => this._toggleSelect(row.id)} />`,
      },
      { key: 'client_id', label: 'Client ID' },
      { key: 'name', label: 'Name' },
      { key: 'client_type', label: 'Type' },
      { key: 'pkce_required', label: 'PKCE', render: (v) => v ? 'Yes' : 'No' },
      { key: 'enabled', label: 'Enabled', render: (v) => v ? html`<span style="color:var(--color-success)">Yes</span>` : html`<span style="color:var(--color-danger)">No</span>` },
      { key: 'id', label: 'Actions', render: (_, row) => html`<div style="display:flex;gap:0.5rem"><c-button size="sm" variant="secondary" @click=${() => navigate('/clients/' + row.id)}>Edit</c-button><c-button size="sm" variant="danger" @click=${() => this._deleteClient(row.id)}>Delete</c-button></div>` },
    ];
    return html`<c-page-layout title="Clients">
        <div slot="actions"><c-button variant="primary" @click=${() => this._openCreateModal()}>+ Add Client</c-button></div>
        <div class="toolbar">
          <label style="font-size:0.875rem;color:var(--color-text-muted)">
            Realm:
            <select class="realm-select" aria-label="Select realm" .value=${realmId} @change=${(e) => this._onRealmChange(e)}>
              ${realms.map(r => html`<option value=${r.id} ?selected=${realmId === r.id}>${r.display_name || r.name}</option>`)}
            </select>
          </label>
          <input class="search-input" type="text" placeholder="Search clients..." aria-label="Search clients" .value=${search} @input=${(e) => this._onSearch(e)}/>
        </div>
        ${selectedIds.size > 0 ? html`<div class="bulk-bar"><span>${selectedIds.size} selected</span><c-button size="sm" variant="danger" @click=${() => this._bulkDelete()}>Delete Selected</c-button><c-button size="sm" variant="ghost" @click=${() => this.setState({ selectedIds: new Set() })}>Clear</c-button></div>` : ''}
        ${loading ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>`
        : clients.length === 0 ? html`<div class="empty-state"><div class="empty-state-icon">&#128220;</div><div class="empty-state-text">${search ? 'No clients match your search' : 'No clients yet'}</div>${!search ? html`<c-button variant="primary" @click=${() => this._openCreateModal()}>+ Add Client</c-button>` : ''}</div>`
          : html`<c-table .columns=${columns} .rows=${clients}></c-table>`}
        <c-pagination .page=${page} .pageSize=${pageSize} .total=${total} @page-change=${(e) => this._onPageChange(e)}></c-pagination>
      </c-page-layout>
      <c-modal title="Create Client" @close=${() => this._closeCreateModal()}>
        ${showCreateModal ? html`<div class="form">
          <div class="field"><label class="field-label">Realm *</label><select class="field-select" .value=${createRealmId} @change=${(e) => { this.setState({ createRealmId: e.target.value }); this._loadScopesForRealm(e.target.value); }}>${realms.map(r => html`<option value=${r.id} ?selected=${createRealmId === r.id}>${r.display_name || r.name}</option>`)}</select></div>
          <div class="field"><label class="field-label">Client ID *</label><input class="field-input" type="text" placeholder="e.g. my-web-app" .value=${createClientId} @input=${(e) => this.setState({ createClientId: e.target.value })}/><div class="hint">The OAuth2 client_id string</div></div>
          <div class="field"><label class="field-label">Name *</label><input class="field-input" type="text" placeholder="e.g. My Web App" .value=${createName} @input=${(e) => this.setState({ createName: e.target.value })}/><div class="hint">Human-readable name</div></div>
          <div class="field"><label class="field-label">Client Type</label><select class="field-select" .value=${createClientType} @change=${(e) => this.setState({ createClientType: e.target.value })}><option value="confidential">Confidential</option><option value="public">Public</option></select></div>
          ${createClientType === 'confidential' ? html`<div class="field"><label class="field-label">Client Secret</label><input class="field-input" type="text" placeholder="Leave empty to auto-generate" .value=${createClientSecret} @input=${(e) => this.setState({ createClientSecret: e.target.value })}/><div class="hint">Leave empty to auto-generate</div></div>` : ''}
          <div class="field"><label class="field-label">Redirect URIs</label><textarea class="field-textarea" placeholder="https://example.com/callback" .value=${createRedirectUris} @input=${(e) => this.setState({ createRedirectUris: e.target.value })}></textarea><div class="hint">One URI per line</div></div>
          <div class="field"><label class="field-label">Allowed Scopes</label>
            ${availableScopes.length > 0 ? html`<div class="scope-list">${availableScopes.map(s => html`<label class="field-checkbox" style="margin-bottom:.25rem"><input type="checkbox" ?checked=${selectedScopes.includes(s.name)} @change=${(e) => this._toggleScope(s.name, e.target.checked)}/><span style="font-size:.875rem">${s.name}</span>${s.description ? html`<span style="font-size:.75rem;color:var(--color-text-muted);margin-left:.25rem">- ${s.description}</span>` : ''}</label>`)}</div>` : html`<input class="field-input" type="text" placeholder="openid, profile, email" .value=${createAllowedScopes} @input=${(e) => this.setState({ createAllowedScopes: e.target.value })}/><div class="hint">Comma-separated. Create scopes in Scopes page first.</div>`}
          </div>
          <div class="field"><label class="field-label">Allowed Grant Types</label>
            <div class="grant-type-list">${this.constructor.GRANT_TYPES.map(gt => html`
              <label class="field-checkbox" style="margin-bottom:.25rem">
                <input type="checkbox" ?checked=${createAllowedGrantTypes.includes(gt.value)} @change=${(e) => this._toggleGrantType(gt.value, e.target.checked)}/>
                <span style="font-size:.875rem">${gt.label}</span>
                <span style="font-size:.75rem;color:var(--color-text-muted);margin-left:.25rem">- ${gt.desc}</span>
              </label>
            `)}</div>
          </div>
          <div class="field"><label class="field-checkbox"><input type="checkbox" ?checked=${createPkceRequired} @change=${(e) => this.setState({ createPkceRequired: e.target.checked })}/> PKCE Required</label></div>
          <div class="field"><label class="field-checkbox"><input type="checkbox" ?checked=${createEnabled} @change=${(e) => this.setState({ createEnabled: e.target.checked })}/> Enabled</label></div>
        </div>` : ''}
        <div slot="footer"><c-button variant="secondary" @click=${() => this._closeCreateModal()}>Cancel</c-button><c-button variant="primary" ?disabled=${createLoading || !createClientId.trim() || !createName.trim()} @click=${() => this._createClient()}>${createLoading ? 'Creating...' : 'Create'}</c-button></div>
      </c-modal>`;
  }
}
customElements.define('clients-page', ClientsPage);
