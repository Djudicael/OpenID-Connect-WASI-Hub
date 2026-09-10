import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { listAllRealms } from '../services/realm-service.js';
import * as federation from '../services/user-federation-service.js';
import { resolveSelectedRealmId, setSelectedRealmId } from '../core/realm-context.js';
import { showToast } from '../components/ui/toast.js';

const typeLabels = { ldap: 'LDAP', active_directory: 'Active Directory', kerberos: 'Kerberos / SPNEGO' };
const defaultConfig = {
  ldap: { base_dn: 'ou=people,dc=example,dc=com', bind_dn: 'cn=service,dc=example,dc=com', user_filter: '(uid={identifier})', sync_filter: '(objectClass=person)', id_attribute: 'entryUUID', username_attribute: 'uid', email_attribute: 'mail', given_name_attribute: 'givenName', family_name_attribute: 'sn', display_name_attribute: 'displayName', group_attribute: 'memberOf', timeout_seconds: 10, page_size: 500, result_limit: 1000, link_existing_users: false },
  active_directory: { base_dn: 'dc=example,dc=com', bind_dn: 'CN=Service Account,OU=Users,DC=example,DC=com', user_filter: '(|(userPrincipalName={identifier})(sAMAccountName={identifier}))', sync_filter: '(&(objectClass=user)(objectCategory=person))', id_attribute: 'objectGUID', username_attribute: 'sAMAccountName', email_attribute: 'mail', given_name_attribute: 'givenName', family_name_attribute: 'sn', display_name_attribute: 'displayName', group_attribute: 'memberOf', enabled_attribute: 'userAccountControl', timeout_seconds: 10, page_size: 500, result_limit: 1000, link_existing_users: false },
  kerberos: { service_principal: 'HTTP/login.example.com@EXAMPLE.COM', user_principal_attribute: 'userPrincipalName', link_existing_users: false },
};

class UserFederationPage extends BaseComponent {
  constructor() {
    super();
    this._state = { realms: [], realmId: '', providers: [], loading: true, showModal: false, editing: null, name: '', type: 'ldap', connectionMode: 'direct', gatewayUrl: '', gatewaySecret: '', priority: 0, enabled: true, importUsers: true, syncGroups: true, config: JSON.stringify(defaultConfig.ldap, null, 2), workingId: '' };
  }
  connectedCallback() { super.connectedCallback(); this._loadRealms(); }
  async _loadRealms() {
    try { const realms = await listAllRealms(this.signal); const realmId = resolveSelectedRealmId(realms, this._state.realmId); setSelectedRealmId(realmId); await this.setState({ realms, realmId }); await this._load(); }
    catch { showToast('Failed to load user federation', 'error'); this.setState({ loading: false }); }
  }
  async _load() {
    if (!this._state.realmId) return this.setState({ providers: [], loading: false });
    this.setState({ loading: true });
    try { const data = await federation.listFederationProviders(this._state.realmId, this.signal); this.setState({ providers: data.items || [], loading: false }); }
    catch { showToast('Failed to load federation providers', 'error'); this.setState({ loading: false }); }
  }
  async _changeRealm(event) { const realmId = event.target.value; setSelectedRealmId(realmId); await this.setState({ realmId }); this._load(); }
  _open(provider = null) {
    const type = provider?.provider_type || 'ldap';
    const connectionMode = provider?.connection_mode || (provider ? 'gateway' : type === 'kerberos' ? 'gateway' : 'direct');
    this.setState({ showModal: true, editing: provider, name: provider?.name || '', type, connectionMode, gatewayUrl: provider?.connection_url || provider?.gateway_url || '', gatewaySecret: '', priority: provider?.priority || 0, enabled: provider?.enabled ?? true, importUsers: provider?.import_users ?? true, syncGroups: provider?.sync_groups ?? true, config: JSON.stringify(provider?.config || defaultConfig[type], null, 2) });
    requestAnimationFrame(() => this.shadowRoot.querySelector('c-modal')?.open());
  }
  _close() { this.shadowRoot.querySelector('c-modal')?.close(); this.setState({ showModal: false, editing: null }); }
  async _save() {
    let config; try { config = JSON.parse(this._state.config); } catch { return showToast('Configuration must be valid JSON', 'error'); }
    const body = { realm_id: this._state.realmId, name: this._state.name.trim(), provider_type: this._state.type, gateway_url: this._state.gatewayUrl.trim(), gateway_secret: this._state.gatewaySecret || undefined, priority: Number(this._state.priority), enabled: this._state.enabled, import_users: this._state.importUsers, sync_groups: this._state.syncGroups, config };
    const bindDn = typeof config.bind_dn === 'string' ? config.bind_dn.trim() : '';
    const originalMode = this._state.editing?.connection_mode;
    const changingMode = Boolean(originalMode && originalMode !== this._state.connectionMode);
    const secretRequired = this._state.connectionMode === 'gateway' || bindDn;
    if (!body.name || !body.gateway_url || (((!this._state.editing && secretRequired) || (changingMode && secretRequired)) && !body.gateway_secret)) return showToast(`Name, connection URL${secretRequired ? ', and credential' : ''} are required`, 'error');
    try { await (this._state.editing ? federation.updateFederationProvider(this._state.editing.id, body) : federation.createFederationProvider(body)); this._close(); showToast('Federation provider saved', 'success'); this._load(); }
    catch (error) { showToast(error.body?.error || 'Could not save federation provider', 'error'); }
  }
  async _action(id, action) {
    this.setState({ workingId: id });
    try { const result = await federation[action](id); showToast(action === 'testFederationProvider' ? (result.message || 'Connection successful') : `${result.synced} users synchronized`, 'success'); this._load(); }
    catch (error) { showToast(error.body?.error || 'Federation operation failed', 'error'); }
    finally { this.setState({ workingId: '' }); }
  }
  async _delete(id) { if (!confirm('Delete this federation provider? Existing imported users remain, but directory login stops.')) return; try { await federation.deleteFederationProvider(id); showToast('Federation provider deleted', 'success'); this._load(); } catch { showToast('Could not delete federation provider', 'error'); } }
  template() {
    const s = this._state;
    const columns = [
      { key: 'name', label: 'Provider' },
      { key: 'provider_type', label: 'Type', render: value => typeLabels[value] || value },
      { key: 'connection_mode', label: 'Connection', render: value => value === 'direct' ? 'Direct' : 'Gateway' },
      { key: 'linked_users', label: 'Users' },
      { key: 'last_sync_status', label: 'Last sync', render: (value, row) => value ? `${value} · ${new Date(row.last_sync_at).toLocaleString()}` : 'Never' },
      { key: 'enabled', label: 'Status', render: value => value ? 'Enabled' : 'Disabled' },
      { key: 'id', label: 'Actions', render: (_, row) => html`<div style="display:flex;gap:.4rem;flex-wrap:wrap"><c-button size="sm" @click=${()=>this._open(row)}>Edit</c-button><c-button size="sm" ?disabled=${s.workingId===row.id} @click=${()=>this._action(row.id,'testFederationProvider')}>Test</c-button>${row.provider_type!=='kerberos' ? html`<c-button size="sm" ?disabled=${s.workingId===row.id} @click=${()=>this._action(row.id,'syncFederationProvider')}>Sync</c-button>` : ''}<c-button size="sm" variant="danger" @click=${()=>this._delete(row.id)}>Delete</c-button></div>` },
    ];
    const direct = s.connectionMode === 'direct';
    const credentialLabel = direct ? 'Bind password' : 'Gateway secret';
    return html`<c-page-layout title="User Federation"><div slot="actions"><c-button variant="primary" @click=${()=>this._open()}>+ Add provider</c-button></div><section data-doc-section="user-federation"><p style="color:var(--color-text-muted)">Connect realm users directly to LDAP or Active Directory, or use a federation gateway.</p><div class="toolbar"><label>Realm: <select class="realm-select" .value=${s.realmId} @change=${event=>this._changeRealm(event)}>${s.realms.map(realm=>html`<option value=${realm.id}>${realm.display_name||realm.name}</option>`)}</select></label></div>${s.loading ? html`<div class="empty-state">Loading...</div>` : s.providers.length ? html`<c-table .columns=${columns} .rows=${s.providers}></c-table>` : html`<div class="empty-state"><div class="empty-state-text">No user federation providers configured</div></div>`}</section></c-page-layout>
    <c-modal title=${s.editing?'Edit federation provider':'Add federation provider'} @close=${()=>this._close()}>${s.showModal ? html`<div class="form"><div class="field"><label class="field-label">Name *</label><input class="field-input" .value=${s.name} @input=${event=>this.setState({name:event.target.value})}></div><div class="field"><label class="field-label">Directory type</label><select class="field-select" .value=${s.type} @change=${event=>{const type=event.target.value;this.setState({type,connectionMode:type==='kerberos'?'gateway':s.connectionMode,config:JSON.stringify(defaultConfig[type],null,2)});}}>${Object.entries(typeLabels).map(([value,label])=>html`<option value=${value}>${label}</option>`)}</select></div><div class="field"><label class="field-label">Connection mode</label><select class="field-select" .value=${s.connectionMode} ?disabled=${s.type==='kerberos'} @change=${event=>this.setState({connectionMode:event.target.value,gatewayUrl:''})}><option value="direct">Direct directory connection</option><option value="gateway">Federation gateway</option></select>${s.type==='kerberos'?html`<div class="hint">Kerberos/SPNEGO uses the configured gateway.</div>`:''}</div><div class="field"><label class="field-label">${direct?'Directory URL':'Federation gateway URL'} *</label><input class="field-input" type="url" placeholder=${direct?'ldaps://directory.example.com:636':'https://federation.example.com'} .value=${s.gatewayUrl} @input=${event=>this.setState({gatewayUrl:event.target.value})}><div class="hint">${direct?'Use LDAPS for remote directories. Plain LDAP requires allow_insecure_transport in the configuration.':'Enter the HTTPS endpoint of your federation gateway.'}</div></div><div class="field"><label class="field-label">${credentialLabel} ${s.editing?'':'*'}</label><input class="field-input" type="password" autocomplete="new-password" .value=${s.gatewaySecret} @input=${event=>this.setState({gatewaySecret:event.target.value})}><div class="hint">${direct?'Required when bind_dn is configured. Leave empty while editing to keep it.':'Leave empty while editing to keep the current secret.'}</div></div><div class="field"><label class="field-label">Priority</label><input class="field-input" type="number" .value=${s.priority} @input=${event=>this.setState({priority:event.target.value})}></div><div class="field"><label class="field-label">Directory configuration</label><textarea class="field-input" rows="14" .value=${s.config} @input=${event=>this.setState({config:event.target.value})}></textarea></div><label class="field-checkbox"><input type="checkbox" ?checked=${s.enabled} @change=${event=>this.setState({enabled:event.target.checked})}> Enabled</label><label class="field-checkbox"><input type="checkbox" ?checked=${s.importUsers} @change=${event=>this.setState({importUsers:event.target.checked})}> Import users</label><label class="field-checkbox"><input type="checkbox" ?checked=${s.syncGroups} @change=${event=>this.setState({syncGroups:event.target.checked})}> Synchronize groups</label></div>` : ''}<div slot="footer"><c-button variant="secondary" @click=${()=>this._close()}>Cancel</c-button><c-button variant="primary" @click=${()=>this._save()}>Save</c-button></div></c-modal>`;
  }
}
customElements.define('user-federation-page', UserFederationPage);
