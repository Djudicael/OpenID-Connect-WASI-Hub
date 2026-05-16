import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { listIdentityProviders, createIdentityProvider, deleteIdentityProvider } from '../services/idp-service.js';
import { listRealms } from '../services/realm-service.js';
import { showToast } from '../components/ui/toast.js';
import { handleApiError } from '../utils/error-handler.js';
import { isRequired } from '../utils/validators.js';

const ConfirmDialog = customElements.get('c-modal');

const PROVIDER_TYPES = [
  { value: 'oidc', label: 'Generic OIDC' },
  { value: 'google', label: 'Google' },
  { value: 'github', label: 'GitHub' },
];

class IdentityProvidersPage extends BaseComponent {
  constructor() {
    super();
    this._state = {
      providers: [],
      loading: false,
      realms: [],
      realmId: '',
      showCreateModal: false,
      createAlias: '',
      createType: 'oidc',
      createClientId: '',
      createClientSecret: '',
      createIssuer: '',
      createScopes: 'openid profile email',
      createAutoCreateUsers: true,
      createLinkByEmail: false,
      createLoading: false,
    };
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadRealms();
  }

  async _loadRealms() {
    try {
      const data = await listRealms({ limit: '100' }, this.signal);
      const realms = data.items || [];
      const defaultRealmId = realms.length > 0 ? realms[0].id : '';
      this.setState({ realms, realmId: defaultRealmId });
      if (defaultRealmId) this._loadProviders(defaultRealmId);
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to load realms');
    }
  }

  async _loadProviders(realmId) {
    this.setState({ loading: true });
    try {
      const data = await listIdentityProviders(realmId, this.signal);
      this.setState({ providers: data.items || data || [], loading: false });
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to load identity providers');
      this.setState({ providers: [], loading: false });
    }
  }

  async _onRealmChange(e) {
    const realmId = e.target.value;
    await this.setState({ realmId });
    this._loadProviders(realmId);
  }

  _openCreateModal() {
    this.setState({
      showCreateModal: true,
      createAlias: '',
      createType: 'oidc',
      createClientId: '',
      createClientSecret: '',
      createIssuer: '',
      createScopes: 'openid profile email',
      createAutoCreateUsers: true,
      createLinkByEmail: false,
      createLoading: false,
    });
    requestAnimationFrame(() => {
      const modal = this.shadowRoot.querySelector('c-modal');
      if (modal) modal.open();
    });
  }

  _closeCreateModal() {
    const modal = this.shadowRoot.querySelector('c-modal');
    if (modal) modal.close();
    this.setState({ showCreateModal: false });
  }

  async _createProvider() {
    const { realmId, createAlias, createType, createClientId, createClientSecret, createIssuer, createScopes, createAutoCreateUsers, createLinkByEmail } = this._state;
    if (!isRequired(realmId) || !isRequired(createAlias)) return;

    this.setState({ createLoading: true });
    try {
      await createIdentityProvider({
        realm_id: realmId,
        alias: createAlias.trim(),
        provider_type: createType,
        client_id: createClientId.trim() || undefined,
        client_secret: createClientSecret.trim() || undefined,
        issuer_url: createIssuer.trim() || undefined,
        scopes: createScopes.split(' ').filter(Boolean),
        auto_create_users: createAutoCreateUsers,
        link_users_by_email: createLinkByEmail,
      });
      this._closeCreateModal();
      showToast('Identity provider created', 'success');
      this._loadProviders(realmId);
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to create identity provider');
      this.setState({ createLoading: false });
    }
  }

  async _deleteProvider(id) {
    const confirmed = await ConfirmDialog.confirm('Delete this identity provider? Users linked via this provider will no longer be able to log in through it.', 'Delete Provider');
    if (!confirmed) return;
    try {
      await deleteIdentityProvider(id);
      showToast('Identity provider deleted', 'success');
      this._loadProviders(this._state.realmId);
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to delete identity provider');
    }
  }

  template() {
    const { providers, loading, realms, realmId, showCreateModal, createAlias, createType, createClientId, createClientSecret, createIssuer, createScopes, createAutoCreateUsers, createLinkByEmail, createLoading } = this._state;
    const columns = [
      { key: 'alias', label: 'Alias' },
      { key: 'provider_type', label: 'Type', render: (v) => { const t = PROVIDER_TYPES.find(t => t.value === v); return t ? t.label : v; } },
      { key: 'auto_create_users', label: 'Auto Create', render: (v) => v ? 'Yes' : 'No' },
      { key: 'link_users_by_email', label: 'Link by Email', render: (v) => v ? 'Yes' : 'No' },
      {
        key: 'id',
        label: 'Actions',
        render: (_, row) => html`
          <div style="display:flex;gap:0.5rem">
            <c-button size="sm" variant="danger" @click=${() => this._deleteProvider(row.id)}>Delete</c-button>
          </div>
        `,
      },
    ];

    return html`
      <c-page-layout title="Identity Providers">
        <div slot="actions">
          <c-button variant="primary" @click=${() => this._openCreateModal()}>+ Add Provider</c-button>
        </div>
        <div class="toolbar">
          <label style="font-size:0.875rem;color:var(--color-text-muted)">
            Realm:
            <select class="realm-select" aria-label="Select realm" .value=${realmId} @change=${(e) => this._onRealmChange(e)}>
              ${realms.map(r => html`<option value=${r.id} ?selected=${realmId === r.id}>${r.display_name || r.name}</option>`)}
            </select>
          </label>
        </div>
        ${loading
        ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>`
        : providers.length === 0
          ? html`<div class="empty-state"><div class="empty-state-icon">&#127760;</div><div class="empty-state-text">No identity providers configured</div><c-button variant="primary" @click=${() => this._openCreateModal()}>+ Add Provider</c-button></div>`
          : html`<c-table .columns=${columns} .rows=${providers}></c-table>`}
      </c-page-layout>

      <c-modal title="Add Identity Provider" @close=${() => this._closeCreateModal()}>
        ${showCreateModal ? html`
          <div class="form">
            <div class="field">
              <label class="field-label" for="idp-alias">Alias *</label>
              <input class="field-input" id="idp-alias" type="text" placeholder="e.g. google" .value=${createAlias} @input=${(e) => this.setState({ createAlias: e.target.value })} />
              <div class="hint">Unique identifier for this provider</div>
            </div>
            <div class="field">
              <label class="field-label" for="idp-type">Provider Type</label>
              <select class="field-select" id="idp-type" .value=${createType} @change=${(e) => this.setState({ createType: e.target.value })}>
                ${PROVIDER_TYPES.map(t => html`<option value=${t.value}>${t.label}</option>`)}
              </select>
            </div>
            <div class="field">
              <label class="field-label" for="idp-issuer">Issuer URL</label>
              <input class="field-input" id="idp-issuer" type="url" placeholder="https://accounts.google.com" .value=${createIssuer} @input=${(e) => this.setState({ createIssuer: e.target.value })} />
              <div class="hint">OIDC discovery URL (not needed for Google/GitHub)</div>
            </div>
            <div class="field">
              <label class="field-label" for="idp-client-id">Client ID</label>
              <input class="field-input" id="idp-client-id" type="text" .value=${createClientId} @input=${(e) => this.setState({ createClientId: e.target.value })} />
            </div>
            <div class="field">
              <label class="field-label" for="idp-client-secret">Client Secret</label>
              <input class="field-input" id="idp-client-secret" type="password" .value=${createClientSecret} @input=${(e) => this.setState({ createClientSecret: e.target.value })} />
            </div>
            <div class="field">
              <label class="field-label" for="idp-scopes">Scopes</label>
              <input class="field-input" id="idp-scopes" type="text" .value=${createScopes} @input=${(e) => this.setState({ createScopes: e.target.value })} />
              <div class="hint">Space-separated</div>
            </div>
            <div class="field">
              <label class="field-checkbox">
                <input type="checkbox" id="idp-auto-create" ?checked=${createAutoCreateUsers} @change=${(e) => this.setState({ createAutoCreateUsers: e.target.checked })} />
                Auto-create users
              </label>
            </div>
            <div class="field">
              <label class="field-checkbox">
                <input type="checkbox" id="idp-link-email" ?checked=${createLinkByEmail} @change=${(e) => this.setState({ createLinkByEmail: e.target.checked })} />
                Link users by email
              </label>
            </div>
          </div>
        ` : ''}
        <div slot="footer">
          <c-button variant="secondary" @click=${() => this._closeCreateModal()}>Cancel</c-button>
          <c-button variant="primary" ?disabled=${createLoading || !createAlias.trim()} @click=${() => this._createProvider()}>
            ${createLoading ? 'Creating...' : 'Create'}
          </c-button>
        </div>
      </c-modal>
    `;
  }
}

customElements.define('identity-providers-page', IdentityProvidersPage);
