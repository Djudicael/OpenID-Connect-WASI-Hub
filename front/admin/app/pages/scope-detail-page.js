import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { navigate } from '../core/router.js';
import { listClients } from '../services/client-service.js';
import { getScope, listProtocolMappers, createProtocolMapper, updateProtocolMapper, deleteProtocolMapper, listClientScopes, assignClientScope, unassignClientScope } from '../services/scope-service.js';
import { showToast } from '../components/ui/toast.js';

const mapperLabels = {
  user_property: 'User property', user_attribute: 'User attribute', hardcoded_claim: 'Fixed claim',
  audience: 'Audience', realm_roles: 'Realm roles', client_roles: 'Client roles',
};

class ScopeDetailPage extends BaseComponent {
  constructor() {
    super();
    this._state = {
      scope: null, mappers: [], clients: [], assignments: [], loading: true,
      showMapper: false, mapperId: null, mapperName: '', mapperType: 'user_attribute', claimName: '', source: '', claimValue: '',
      multivalued: false, accessToken: true, idToken: true, userinfo: true, mapperLoading: false,
      selectedClient: '', assignmentType: 'optional', assignmentLoading: false,
    };
  }

  connectedCallback() { super.connectedCallback(); if (this.params?.id) this._load(); }

  async _load() {
    this.setState({ loading: true });
    try {
      const scope = await getScope(this.params.id, this.signal);
      const [mapperData, clientData] = await Promise.all([
        listProtocolMappers(scope.id, this.signal), listClients({ realm_id: scope.realm_id, limit: '1000', offset: '0' }, this.signal),
      ]);
      const clients = clientData.items || [];
      const clientScopeData = await Promise.all(clients.map(client => listClientScopes(client.id, this.signal)));
      const assignments = clients.flatMap((client, index) => (clientScopeData[index].items || [])
        .filter(item => item.scope_id === scope.id).map(item => ({ ...item, client_id: client.id, client_name: client.name, oauth_client_id: client.client_id })));
      this.setState({ scope, mappers: mapperData.items || [], clients, assignments, loading: false, selectedClient: clients[0]?.id || '' });
    } catch (error) {
      if (error.name !== 'AbortError') showToast('Failed to load client scope', 'error');
      this.setState({ loading: false });
    }
  }

  _openMapper(mapper = null) {
    const value = mapper?.claim_value;
    this.setState({ showMapper: true, mapperId: mapper?.id || null, mapperName: mapper?.name || '', mapperType: mapper?.mapper_type || 'user_attribute', claimName: mapper?.claim_name || '', source: mapper?.source || '', claimValue: value == null ? '' : (typeof value === 'string' ? value : JSON.stringify(value)), multivalued: mapper?.multivalued || false, accessToken: mapper?.add_to_access_token ?? true, idToken: mapper?.add_to_id_token ?? true, userinfo: mapper?.add_to_userinfo ?? true });
    requestAnimationFrame(() => this.shadowRoot.querySelector('c-modal')?.open());
  }

  _closeMapper() { this.shadowRoot.querySelector('c-modal')?.close(); this.setState({ showMapper: false }); }

  async _createMapper() {
    const s = this._state;
    if (!s.mapperName.trim()) return;
    let claimValue;
    if (s.mapperType === 'hardcoded_claim') {
      try { claimValue = JSON.parse(s.claimValue); } catch { claimValue = s.claimValue; }
    } else if (s.mapperType === 'audience') claimValue = s.claimValue.trim();
    this.setState({ mapperLoading: true });
    try {
      const body = {
        name: s.mapperName.trim(), mapper_type: s.mapperType,
        claim_name: s.mapperType === 'audience' ? null : s.claimName.trim(),
        source: ['user_property', 'user_attribute', 'client_roles'].includes(s.mapperType) ? s.source.trim() : null,
        claim_value: claimValue, multivalued: s.multivalued,
        add_to_access_token: s.accessToken, add_to_id_token: s.idToken, add_to_userinfo: s.userinfo,
      };
      if (s.mapperId) await updateProtocolMapper(s.scope.id, s.mapperId, body);
      else await createProtocolMapper(s.scope.id, body);
      this._closeMapper(); showToast(`Protocol mapper ${s.mapperId ? 'updated' : 'created'}`, 'success'); await this._load();
    } catch (error) { showToast(error.body?.error || 'Failed to create protocol mapper', 'error'); this.setState({ mapperLoading: false }); }
  }

  async _deleteMapper(id) {
    if (!confirm('Delete this protocol mapper?')) return;
    try { await deleteProtocolMapper(this._state.scope.id, id); showToast('Protocol mapper deleted', 'success'); await this._load(); }
    catch { showToast('Failed to delete protocol mapper', 'error'); }
  }

  async _assign() {
    const { selectedClient, scope, assignmentType } = this._state;
    if (!selectedClient) return;
    this.setState({ assignmentLoading: true });
    try { await assignClientScope(selectedClient, scope.id, assignmentType); showToast('Client scope assigned', 'success'); await this._load(); }
    catch (error) { showToast(error.body?.error || 'Failed to assign client scope', 'error'); this.setState({ assignmentLoading: false }); }
  }

  async _unassign(clientId) {
    try { await unassignClientScope(clientId, this._state.scope.id); showToast('Client scope removed', 'success'); await this._load(); }
    catch { showToast('Failed to remove client scope', 'error'); }
  }

  template() {
    const s = this._state;
    if (s.loading) return html`<c-page-layout title="Client scope"><div style="padding:2rem">Loading...</div></c-page-layout>`;
    if (!s.scope) return html`<c-page-layout title="Client scope"><p>Client scope not found.</p></c-page-layout>`;
    const needsSource = ['user_property', 'user_attribute', 'client_roles'].includes(s.mapperType);
    const needsValue = ['hardcoded_claim', 'audience'].includes(s.mapperType);
    return html`
      <c-page-layout title=${s.scope.name}>
        <div slot="actions"><c-button variant="secondary" @click=${() => navigate('/scopes')}>Back to scopes</c-button></div>
        <p style="color:var(--color-text-muted)">${s.scope.description || 'Configure which clients use this scope and which claims it contributes.'}</p>
        <section class="card" style="margin-bottom:1rem"><h2>Assigned clients</h2>
          <div class="form-row" style="align-items:end">
            <div class="field"><label class="field-label">Client</label><select class="field-input" .value=${s.selectedClient} @change=${e => this.setState({ selectedClient: e.target.value })}>${s.clients.map(client => html`<option value=${client.id}>${client.name} (${client.client_id})</option>`)}</select></div>
            <div class="field"><label class="field-label">Use</label><select class="field-input" .value=${s.assignmentType} @change=${e => this.setState({ assignmentType: e.target.value })}><option value="optional">Optional</option><option value="default">Default</option></select></div>
            <c-button variant="primary" ?disabled=${s.assignmentLoading || !s.selectedClient} @click=${() => this._assign()}>Assign</c-button>
          </div>
          <table class="data-table"><thead><tr><th>Client</th><th>Use</th><th></th></tr></thead><tbody>${s.assignments.length ? s.assignments.map(item => html`<tr><td>${item.client_name} <span style="color:var(--color-text-muted)">(${item.oauth_client_id})</span></td><td>${item.assignment_type === 'default' ? 'Default' : 'Optional'}</td><td><c-button size="sm" variant="danger" @click=${() => this._unassign(item.client_id)}>Remove</c-button></td></tr>`) : html`<tr><td colspan="3">No clients use this scope yet.</td></tr>`}</tbody></table>
        </section>
        <section class="card"><div style="display:flex;justify-content:space-between;align-items:center"><div><h2>Protocol mappers</h2><p style="color:var(--color-text-muted)">Add claims when this scope is granted.</p></div><c-button variant="primary" @click=${() => this._openMapper()}>+ Add mapper</c-button></div>
          <table class="data-table"><thead><tr><th>Name</th><th>Type</th><th>Claim</th><th>Included in</th><th></th></tr></thead><tbody>${s.mappers.length ? s.mappers.map(mapper => html`<tr><td>${mapper.name}</td><td>${mapperLabels[mapper.mapper_type]}</td><td>${mapper.mapper_type === 'audience' ? mapper.claim_value : mapper.claim_name}</td><td>${[mapper.add_to_access_token && 'Access token', mapper.add_to_id_token && 'ID token', mapper.add_to_userinfo && 'UserInfo'].filter(Boolean).join(', ')}</td><td><div style="display:flex;gap:.5rem"><c-button size="sm" @click=${() => this._openMapper(mapper)}>Edit</c-button><c-button size="sm" variant="danger" @click=${() => this._deleteMapper(mapper.id)}>Delete</c-button></div></td></tr>`) : html`<tr><td colspan="5">No protocol mappers configured.</td></tr>`}</tbody></table>
        </section>
      </c-page-layout>
      <c-modal title=${s.mapperId ? 'Edit protocol mapper' : 'Create protocol mapper'} @close=${() => this._closeMapper()}>
        ${s.showMapper ? html`<div class="form">
          <div class="field"><label class="field-label">Name *</label><input class="field-input" .value=${s.mapperName} @input=${e => this.setState({ mapperName: e.target.value })}/></div>
          <div class="field"><label class="field-label">Mapper type</label><select class="field-input" .value=${s.mapperType} @change=${e => this.setState({ mapperType: e.target.value })}>${Object.entries(mapperLabels).map(([value, label]) => html`<option value=${value}>${label}</option>`)}</select></div>
          ${s.mapperType !== 'audience' ? html`<div class="field"><label class="field-label">Token claim name *</label><input class="field-input" placeholder="department or employee.department" .value=${s.claimName} @input=${e => this.setState({ claimName: e.target.value })}/></div>` : ''}
          ${needsSource ? html`<div class="field"><label class="field-label">Source *</label><input class="field-input" placeholder=${s.mapperType === 'user_attribute' ? 'User attribute, for example department' : s.mapperType === 'client_roles' ? 'OAuth client ID' : 'User property, for example email'} .value=${s.source} @input=${e => this.setState({ source: e.target.value })}/></div>` : ''}
          ${needsValue ? html`<div class="field"><label class="field-label">${s.mapperType === 'audience' ? 'Audience' : 'Claim value'} *</label><input class="field-input" .value=${s.claimValue} @input=${e => this.setState({ claimValue: e.target.value })}/></div>` : ''}
          <div class="field"><label class="field-checkbox"><input type="checkbox" ?checked=${s.multivalued} @change=${e => this.setState({ multivalued: e.target.checked })}/>Always return an array</label></div>
          <div class="field"><label class="field-label">Include in</label><label class="field-checkbox"><input type="checkbox" ?checked=${s.accessToken} @change=${e => this.setState({ accessToken: e.target.checked })}/>Access token</label><label class="field-checkbox"><input type="checkbox" ?checked=${s.idToken} @change=${e => this.setState({ idToken: e.target.checked })}/>ID token</label><label class="field-checkbox"><input type="checkbox" ?checked=${s.userinfo} @change=${e => this.setState({ userinfo: e.target.checked })}/>UserInfo</label></div>
        </div>` : ''}
        <div slot="footer"><c-button variant="secondary" @click=${() => this._closeMapper()}>Cancel</c-button><c-button variant="primary" ?disabled=${s.mapperLoading || !s.mapperName.trim()} @click=${() => this._createMapper()}>${s.mapperLoading ? 'Saving...' : s.mapperId ? 'Save mapper' : 'Create mapper'}</c-button></div>
      </c-modal>`;
  }
}
customElements.define('scope-detail-page', ScopeDetailPage);
