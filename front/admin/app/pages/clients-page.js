import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { listClients, createClient, deleteClient } from '../services/client-service.js';
import { listRealms } from '../services/realm-service.js';
import { listScopes } from '../services/scope-service.js';
import { navigate } from '../core/router.js';
import { showToast } from '../components/ui/toast.js';
import { isRequired, minLength, isEmail } from '../utils/validators.js';

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
      createRealmId: '',
      createClientId: '',
      createName: '',
      createClientType: 'confidential',
      createClientSecret: '',
      createRedirectUris: '',
      createAllowedScopes: 'openid',
      createAllowedGrantTypes: 'authorization_code',
      createPkceRequired: true,
      createEnabled: true,
      createLoading: false,
      realms: [],
      availableScopes: [],
      selectedScopes: [],
    };
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadClients();
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

  async _loadScopesForRealm(realmId) {
    if (!realmId) return;
    try {
      const data = await listScopes(realmId);
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
      const { search, page, pageSize } = this._state;
      const offset = (page - 1) * pageSize;
      const params = new URLSearchParams();
      if (search) params.set('search', search);
      params.set('limit', String(pageSize));
      params.set('offset', String(offset));
      const data = await listClients({
        ...(search ? { search } : {}),
        limit: String(pageSize),
        offset: String(offset),
      });
      this.setState({ clients: data.items || [], total: data.total || 0, loading: false });
    } catch (err) {
      showToast('Failed to load clients', 'error');
      this.setState({ clients: [], loading: false });
    }
  }

  _onSearch(e) {
    const value = e.target.value;
    this.setState({ search: value, page: 1 });
    clearTimeout(this._searchTimer);
    this._searchTimer = setTimeout(() => this._loadClients(), 300);
  }

  _onPageChange(e) {
    this.setState({ page: e.detail.page }, this._loadClients());
  }

  async _deleteClient(id) {
    if (!confirm('Are you sure you want to delete this client?')) return;
    try {
      await deleteClient(id);
      showToast('Client deleted', 'success');
      this._loadClients();
    } catch (err) {
      showToast('Failed to delete client', 'error');
    }
  }

  _openCreateModal() {
    this.setState({
      showCreateModal: true,
      createClientId: '',
      createName: '',
      createClientType: 'confidential',
      createClientSecret: '',
      createRedirectUris: '',
      createAllowedScopes: 'openid',
      createAllowedGrantTypes: 'authorization_code',
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
    const body = {
      realm_id: createRealmId.trim(),
      client_id: createClientId.trim(),
      name: createName.trim(),
      client_type: createClientType,
      redirect_uris: createRedirectUris.split('\n').map(s => s.trim()).filter(Boolean),
      allowed_scopes: createAllowedScopes.split(',').map(s => s.trim()).filter(Boolean),
      allowed_grant_types: createAllowedGrantTypes.split(',').map(s => s.trim()).filter(Boolean),
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
      showToast(err.body?.error || 'Failed to create client', 'error');
      this.setState({ createLoading: false });
    }
  }

  template() {
    const { clients, loading, search, page, pageSize, total, showCreateModal, createRealmId, createClientId, createName, createClientType, createClientSecret, createRedirectUris, createAllowedScopes, createAllowedGrantTypes, createPkceRequired, createEnabled, createLoading, realms, availableScopes, selectedScopes } = this._state;
    const columns = [
      { key: 'client_id', label: 'Client ID' },
      { key: 'name', label: 'Name' },
      { key: 'client_type', label: 'Type' },
      { key: 'pkce_required', label: 'PKCE', render: (v) => v ? 'Yes' : 'No' },
      { key: 'enabled', label: 'Enabled', render: (v) => v ? html`<span style="color:var(--color-success)">Yes</span>` : html`<span style="color:var(--color-danger)">No</span>` },
      { key: 'id', label: 'Actions', render: (_, row) => html`<div style="display:flex;gap:0.5rem"><c-button size="sm" variant="secondary" @click=${() => navigate('/clients/' + row.id)}>Edit</c-button><c-button size="sm" variant="danger" @click=${() => this._deleteClient(row.id)}>Delete</c-button></div>` },
    ];
    return html`<style>:host{display:block}.toolbar{display:flex;gap:1rem;margin-bottom:1rem;align-items:center}.search-input{flex:1;max-width:24rem;padding:.5rem .75rem;font-size:.875rem;border:1px solid #e2e8f0;border-radius:var(--radius-sm);font-family:inherit}.search-input:focus{outline:none;border-color:var(--color-primary)}.form{max-width:32rem}.field{margin-bottom:1rem}.field-label{display:block;font-size:.875rem;font-weight:500;margin-bottom:.25rem}.field-input,.field-select,.field-textarea{width:100%;padding:.5rem .75rem;font-size:.875rem;border:1px solid #e2e8f0;border-radius:var(--radius-sm);font-family:inherit;box-sizing:border-box}.field-input:focus,.field-select:focus,.field-textarea:focus{outline:none;border-color:var(--color-primary)}.field-textarea{resize:vertical;min-height:4rem}.hint{font-size:.75rem;color:var(--color-text-muted);margin-top:.25rem}.field-checkbox{display:flex;align-items:center;gap:.5rem}.field-checkbox input{width:1rem;height:1rem}.scope-list{max-height:10rem;overflow-y:auto;border:1px solid #e2e8f0;border-radius:var(--radius-sm);padding:.5rem}</style>
      <c-page-layout title="Clients">
        <div slot="actions"><c-button variant="primary" @click=${() => this._openCreateModal()}>+ Add Client</c-button></div>
        <div class="toolbar"><input class="search-input" type="text" placeholder="Search clients..." .value=${search} @input=${(e) => this._onSearch(e)}/></div>
        ${loading ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>` : html`<c-table .columns=${columns} .rows=${clients}></c-table>`}
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
          <div class="field"><label class="field-label">Allowed Grant Types</label><input class="field-input" type="text" placeholder="authorization_code, refresh_token" .value=${createAllowedGrantTypes} @input=${(e) => this.setState({ createAllowedGrantTypes: e.target.value })}/><div class="hint">Comma-separated list of grant types</div></div>
          <div class="field"><label class="field-checkbox"><input type="checkbox" ?checked=${createPkceRequired} @change=${(e) => this.setState({ createPkceRequired: e.target.checked })}/> PKCE Required</label></div>
          <div class="field"><label class="field-checkbox"><input type="checkbox" ?checked=${createEnabled} @change=${(e) => this.setState({ createEnabled: e.target.checked })}/> Enabled</label></div>
        </div>` : ''}
        <div slot="footer"><c-button variant="secondary" @click=${() => this._closeCreateModal()}>Cancel</c-button><c-button variant="primary" ?disabled=${createLoading || !createClientId.trim() || !createName.trim()} @click=${() => this._createClient()}>${createLoading ? 'Creating...' : 'Create'}</c-button></div>
      </c-modal>`;
  }
}
customElements.define('clients-page', ClientsPage);
