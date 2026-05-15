import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { getClient, updateClient } from '../services/client-service.js';
import { navigate } from '../core/router.js';
import { showToast } from '../components/ui/toast.js';

const GRANT_TYPES = [
  { value: 'authorization_code', label: 'Authorization Code', desc: 'Standard web app flow' },
  { value: 'refresh_token', label: 'Refresh Token', desc: 'Long-lived sessions' },
  { value: 'client_credentials', label: 'Client Credentials', desc: 'Server-to-server' },
  { value: 'device_code', label: 'Device Code', desc: 'TVs, IoT, CLI apps' },
  { value: 'authorization_code_oidc', label: 'Auth Code + OIDC', desc: 'With OpenID Connect' },
];

class ClientDetailPage extends BaseComponent {
  constructor() {
    super();
    this._state = { client: null, savedClient: null, loading: true, saving: false, dirty: false };
    this._onBeforeUnload = this._onBeforeUnload.bind(this);
  }

  connectedCallback() {
    super.connectedCallback();
    if (this.params && this.params.id) {
      this._loadClient(this.params.id);
    }
    window.addEventListener('beforeunload', this._onBeforeUnload);
  }

  disconnectedCallback() {
    window.removeEventListener('beforeunload', this._onBeforeUnload);
  }

  _onBeforeUnload(e) {
    if (this._state.dirty) {
      e.preventDefault();
      e.returnValue = '';
    }
  }

  get _isDirty() {
    const { client, savedClient } = this._state;
    if (!client || !savedClient) return false;
    return (
      client.name !== savedClient.name ||
      this._arraysDiffer(client.redirect_uris, savedClient.redirect_uris) ||
      this._arraysDiffer(client.allowed_scopes, savedClient.allowed_scopes) ||
      this._arraysDiffer(client.allowed_grant_types, savedClient.allowed_grant_types) ||
      client.pkce_required !== savedClient.pkce_required ||
      client.enabled !== savedClient.enabled ||
      client.subject_type !== savedClient.subject_type ||
      client.sector_identifier_uri !== savedClient.sector_identifier_uri ||
      client.token_endpoint_auth_method !== savedClient.token_endpoint_auth_method ||
      client.jwks_uri !== savedClient.jwks_uri ||
      this._arraysDiffer(client.request_uris, savedClient.request_uris) ||
      client.frontchannel_logout_uri !== savedClient.frontchannel_logout_uri ||
      client.frontchannel_logout_session_required !== savedClient.frontchannel_logout_session_required ||
      client.backchannel_logout_uri !== savedClient.backchannel_logout_uri ||
      client.backchannel_logout_session_required !== savedClient.backchannel_logout_session_required ||
      this._arraysDiffer(client.post_logout_redirect_uris, savedClient.post_logout_redirect_uris) ||
      this._arraysDiffer(client.response_modes, savedClient.response_modes) ||
      client.id_token_encrypted_response_alg !== savedClient.id_token_encrypted_response_alg ||
      client.id_token_encrypted_response_enc !== savedClient.id_token_encrypted_response_enc ||
      client.request_object_encryption_alg !== savedClient.request_object_encryption_alg ||
      client.request_object_encryption_enc !== savedClient.request_object_encryption_enc
    );
  }

  _arraysDiffer(a, b) {
    const arrA = (a || []).slice().sort();
    const arrB = (b || []).slice().sort();
    if (arrA.length !== arrB.length) return true;
    return arrA.some((v, i) => v !== arrB[i]);
  }

  async _loadClient(id) {
    this.setState({ loading: true });
    try {
      const client = await getClient(id);
      this.setState({ client, savedClient: { ...client }, loading: false, dirty: false });
    } catch (err) {
      showToast('Failed to load client', 'error');
      this.setState({ loading: false });
    }
  }

  async _save() {
    const client = this._state.client;
    if (!client) return;
    this.setState({ saving: true });
    try {
      await updateClient(client.id, {
        name: client.name,
        redirect_uris: client.redirect_uris,
        allowed_scopes: client.allowed_scopes,
        allowed_grant_types: client.allowed_grant_types,
        pkce_required: client.pkce_required,
        enabled: client.enabled,
        subject_type: client.subject_type,
        sector_identifier_uri: client.sector_identifier_uri,
        token_endpoint_auth_method: client.token_endpoint_auth_method,
        jwks_uri: client.jwks_uri,
        request_uris: client.request_uris,
        frontchannel_logout_uri: client.frontchannel_logout_uri,
        frontchannel_logout_session_required: client.frontchannel_logout_session_required,
        backchannel_logout_uri: client.backchannel_logout_uri,
        backchannel_logout_session_required: client.backchannel_logout_session_required,
        post_logout_redirect_uris: client.post_logout_redirect_uris,
        response_modes: client.response_modes,
        id_token_encrypted_response_alg: client.id_token_encrypted_response_alg,
        id_token_encrypted_response_enc: client.id_token_encrypted_response_enc,
        request_object_encryption_alg: client.request_object_encryption_alg,
        request_object_encryption_enc: client.request_object_encryption_enc,
      });
      showToast('Client updated', 'success');
      this.setState({ saving: false, savedClient: { ...client }, dirty: false });
    } catch (err) {
      showToast('Failed to update client', 'error');
      this.setState({ saving: false });
    }
  }

  _updateField(field, value) {
    const client = { ...this._state.client, [field]: value };
    const savedClient = this._state.savedClient;
    const dirty = (
      client.name !== savedClient.name ||
      this._arraysDiffer(client.redirect_uris, savedClient.redirect_uris) ||
      this._arraysDiffer(client.allowed_scopes, savedClient.allowed_scopes) ||
      this._arraysDiffer(client.allowed_grant_types, savedClient.allowed_grant_types) ||
      client.pkce_required !== savedClient.pkce_required ||
      client.enabled !== savedClient.enabled ||
      client.subject_type !== savedClient.subject_type ||
      client.sector_identifier_uri !== savedClient.sector_identifier_uri ||
      client.token_endpoint_auth_method !== savedClient.token_endpoint_auth_method ||
      client.jwks_uri !== savedClient.jwks_uri ||
      this._arraysDiffer(client.request_uris, savedClient.request_uris) ||
      client.frontchannel_logout_uri !== savedClient.frontchannel_logout_uri ||
      client.frontchannel_logout_session_required !== savedClient.frontchannel_logout_session_required ||
      client.backchannel_logout_uri !== savedClient.backchannel_logout_uri ||
      client.backchannel_logout_session_required !== savedClient.backchannel_logout_session_required ||
      this._arraysDiffer(client.post_logout_redirect_uris, savedClient.post_logout_redirect_uris) ||
      this._arraysDiffer(client.response_modes, savedClient.response_modes) ||
      client.id_token_encrypted_response_alg !== savedClient.id_token_encrypted_response_alg ||
      client.id_token_encrypted_response_enc !== savedClient.id_token_encrypted_response_enc ||
      client.request_object_encryption_alg !== savedClient.request_object_encryption_alg ||
      client.request_object_encryption_enc !== savedClient.request_object_encryption_enc
    );
    this.setState({ client, dirty });
  }

  _updateRedirectUris(value) {
    const uris = value.split('\n').map(s => s.trim()).filter(Boolean);
    this._updateField('redirect_uris', uris);
  }

  _updateCommaField(field, value) {
    const arr = value.split(',').map(s => s.trim()).filter(Boolean);
    this._updateField(field, arr);
  }

  _toggleGrantType(value, checked) {
    const client = this._state.client;
    const arr = [...(client.allowed_grant_types || [])];
    if (checked) { if (!arr.includes(value)) arr.push(value); }
    else { const i = arr.indexOf(value); if (i >= 0) arr.splice(i, 1); }
    this._updateField('allowed_grant_types', arr);
  }

  _navigateAway(path) {
    if (this._state.dirty) {
      if (!confirm('You have unsaved changes. Are you sure you want to leave?')) {
        return;
      }
    }
    this.setState({ dirty: false });
    navigate(path);
  }

  template() {
    const { client, loading, saving, dirty } = this._state;
    return html`
      <style>
        :host { display: block; }
        .back-link {
          display: inline-flex;
          align-items: center;
          gap: 0.25rem;
          color: var(--color-primary);
          text-decoration: none;
          font-size: 0.875rem;
          margin-bottom: 1rem;
          cursor: pointer;
        }
        .dirty-indicator {
          display: inline-block;
          width: 0.5rem;
          height: 0.5rem;
          border-radius: 50%;
          background: var(--color-warning, #f59e0b);
          margin-left: 0.5rem;
          vertical-align: middle;
        }
        .form { max-width: 32rem; }
        .field { margin-bottom: 1rem; }
        .field-label {
          display: block;
          font-size: 0.875rem;
          font-weight: 500;
          margin-bottom: 0.25rem;
        }
        .field-input, .field-textarea {
          width: 100%;
          padding: 0.5rem 0.75rem;
          font-size: 0.875rem;
          border: 1px solid #e2e8f0;
          border-radius: var(--radius-sm);
          font-family: inherit;
          box-sizing: border-box;
        }
        .field-input:focus, .field-textarea:focus {
          outline: none;
          border-color: var(--color-primary);
        }
        .field-textarea {
          resize: vertical;
          min-height: 4rem;
        }
        .field-input[readonly] {
          background: #f8fafc;
          color: var(--color-text-muted);
          cursor: default;
        }
        .hint {
          font-size: 0.75rem;
          color: var(--color-text-muted);
          margin-top: 0.25rem;
        }
        .checkbox-row {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          margin-bottom: 1rem;
        }
        .actions { display: flex; gap: 0.5rem; margin-top: 1.5rem; }
        .info-row {
          font-size: 0.75rem;
          color: var(--color-text-muted);
          margin-bottom: 0.5rem;
        }
        .section {
          margin-top: 2rem;
          padding-top: 1.5rem;
          border-top: 1px solid #e2e8f0;
        }
        .section-title {
          font-size: 1rem;
          font-weight: 600;
          margin-bottom: 1rem;
        }
        .field-select {
          width: 100%;
          padding: 0.5rem 0.75rem;
          font-size: 0.875rem;
          border: 1px solid #e2e8f0;
          border-radius: var(--radius-sm);
          font-family: inherit;
          box-sizing: border-box;
        }
        .field-select:focus {
          outline: none;
          border-color: var(--color-primary);
        }
        .grant-type-list {
          max-height: 12rem;
          overflow-y: auto;
          border: 1px solid #e2e8f0;
          border-radius: var(--radius-sm);
          padding: 0.5rem;
        }
      </style>
      <c-page-layout title="Client Details">
        <span class="back-link" @click=${() => this._navigateAway('/clients')}>
          &larr; Back to Clients
        </span>
        ${loading
        ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>`
        : client
          ? html`
                <div class="form">
                  <div class="info-row">Internal ID: ${client.id}</div>

                  <div class="field">
                    <label class="field-label">Name</label>
                    <input class="field-input" type="text" .value=${client.name || ''} @input=${(e) => this._updateField('name', e.target.value)} />
                  </div>

                  <div class="field">
                    <label class="field-label">Client ID</label>
                    <input class="field-input" type="text" .value=${client.client_id || ''} readonly />
                    <div class="hint">The OAuth2 client_id — cannot be changed after creation</div>
                  </div>

                  <div class="field">
                    <label class="field-label">Client Type</label>
                    <input class="field-input" type="text" .value=${client.client_type || ''} readonly />
                    <div class="hint">Cannot be changed after creation</div>
                  </div>

                  <div class="field">
                    <label class="field-label">Redirect URIs</label>
                    <textarea
                      class="field-textarea"
                      .value=${(client.redirect_uris || []).join('\n')}
                      @input=${(e) => this._updateRedirectUris(e.target.value)}
                    ></textarea>
                    <div class="hint">One URI per line</div>
                  </div>

                  <div class="field">
                    <label class="field-label">Allowed Scopes</label>
                    <input
                      class="field-input"
                      type="text"
                      .value=${(client.allowed_scopes || []).join(', ')}
                      @input=${(e) => this._updateCommaField('allowed_scopes', e.target.value)}
                    />
                    <div class="hint">Comma-separated list of scopes</div>
                  </div>

                  <div class="field">
                    <label class="field-label">Allowed Grant Types</label>
                    <div class="grant-type-list">
                      ${GRANT_TYPES.map(gt => html`
                        <label class="checkbox-row" style="margin-bottom:.25rem">
                          <input type="checkbox" ?checked=${(client.allowed_grant_types || []).includes(gt.value)} @change=${(e) => this._toggleGrantType(gt.value, e.target.checked)} />
                          <span>${gt.label}</span>
                          <span style="font-size:.75rem;color:var(--color-text-muted);margin-left:.25rem">- ${gt.desc}</span>
                        </label>
                      `)}
                    </div>
                    <div class="hint">Select one or more grant types</div>
                  </div>

                  <label class="checkbox-row">
                    <input type="checkbox" ?checked=${client.pkce_required} @change=${(e) => this._updateField('pkce_required', e.target.checked)} />
                    PKCE Required
                  </label>

                  <div class="section">
                    <div class="section-title">OIDC Settings</div>
                    <div class="field">
                      <label class="field-label">Subject Type</label>
                      <select class="field-select" .value=${client.subject_type || 'public'} @change=${(e) => this._updateField('subject_type', e.target.value)}>
                        <option value="public">Public</option>
                        <option value="pairwise">Pairwise</option>
                      </select>
                    </div>
                    <div class="field">
                      <label class="field-label">Sector Identifier URI</label>
                      <input class="field-input" type="url" .value=${client.sector_identifier_uri || ''} @input=${(e) => this._updateField('sector_identifier_uri', e.target.value)} />
                      <div class="hint">Used for pairwise subject identifiers</div>
                    </div>
                    <div class="field">
                      <label class="field-label">Token Endpoint Auth Method</label>
                      <input class="field-input" type="text" .value=${client.token_endpoint_auth_method || ''} @input=${(e) => this._updateField('token_endpoint_auth_method', e.target.value)} placeholder="e.g. client_secret_basic" />
                    </div>
                    <div class="field">
                      <label class="field-label">JWKS URI</label>
                      <input class="field-input" type="url" .value=${client.jwks_uri || ''} @input=${(e) => this._updateField('jwks_uri', e.target.value)} />
                    </div>
                    <div class="field">
                      <label class="field-label">Response Modes</label>
                      <input
                        class="field-input"
                        type="text"
                        .value=${(client.response_modes || []).join(', ')}
                        @input=${(e) => this._updateCommaField('response_modes', e.target.value)}
                      />
                      <div class="hint">e.g. query, fragment, form_post</div>
                    </div>
                  </div>

                  <div class="section">
                    <div class="section-title">Request Objects</div>
                    <div class="field">
                      <label class="field-label">Request URIs</label>
                      <textarea
                        class="field-textarea"
                        .value=${(client.request_uris || []).join('\n')}
                        @input=${(e) => this._updateField('request_uris', e.target.value.split('\n').map(s => s.trim()).filter(Boolean))}
                      ></textarea>
                      <div class="hint">One URI per line</div>
                    </div>
                    <div class="field">
                      <label class="field-label">Request Object Encryption Alg</label>
                      <select class="field-select" .value=${client.request_object_encryption_alg || ''} @change=${(e) => this._updateField('request_object_encryption_alg', e.target.value || null)}>
                        <option value="">None</option>
                        <option value="dir">dir (symmetric)</option>
                        <option value="RSA-OAEP-256">RSA-OAEP-256</option>
                      </select>
                    </div>
                    <div class="field">
                      <label class="field-label">Request Object Encryption Enc</label>
                      <input class="field-input" type="text" .value=${client.request_object_encryption_enc || ''} @input=${(e) => this._updateField('request_object_encryption_enc', e.target.value || null)} placeholder="e.g. A256GCM" />
                    </div>
                  </div>

                  <div class="section">
                    <div class="section-title">ID Token Encryption</div>
                    <div class="field">
                      <label class="field-label">ID Token Encryption Alg</label>
                      <select class="field-select" .value=${client.id_token_encrypted_response_alg || ''} @change=${(e) => this._updateField('id_token_encrypted_response_alg', e.target.value || null)}>
                        <option value="">None</option>
                        <option value="dir">dir (symmetric)</option>
                        <option value="RSA-OAEP-256">RSA-OAEP-256</option>
                      </select>
                    </div>
                    <div class="field">
                      <label class="field-label">ID Token Encryption Enc</label>
                      <input class="field-input" type="text" .value=${client.id_token_encrypted_response_enc || ''} @input=${(e) => this._updateField('id_token_encrypted_response_enc', e.target.value || null)} placeholder="e.g. A256GCM" />
                    </div>
                  </div>

                  <div class="section">
                    <div class="section-title">Logout</div>
                    <div class="field">
                      <label class="field-label">Front-Channel Logout URI</label>
                      <input class="field-input" type="url" .value=${client.frontchannel_logout_uri || ''} @input=${(e) => this._updateField('frontchannel_logout_uri', e.target.value)} />
                    </div>
                    <label class="checkbox-row">
                      <input type="checkbox" ?checked=${client.frontchannel_logout_session_required} @change=${(e) => this._updateField('frontchannel_logout_session_required', e.target.checked)} />
                      Front-Channel Logout Session Required
                    </label>
                    <div class="field">
                      <label class="field-label">Back-Channel Logout URI</label>
                      <input class="field-input" type="url" .value=${client.backchannel_logout_uri || ''} @input=${(e) => this._updateField('backchannel_logout_uri', e.target.value)} />
                    </div>
                    <label class="checkbox-row">
                      <input type="checkbox" ?checked=${client.backchannel_logout_session_required} @change=${(e) => this._updateField('backchannel_logout_session_required', e.target.checked)} />
                      Back-Channel Logout Session Required
                    </label>
                    <div class="field">
                      <label class="field-label">Post-Logout Redirect URIs</label>
                      <textarea
                        class="field-textarea"
                        .value=${(client.post_logout_redirect_uris || []).join('\n')}
                        @input=${(e) => this._updateField('post_logout_redirect_uris', e.target.value.split('\n').map(s => s.trim()).filter(Boolean))}
                      ></textarea>
                      <div class="hint">One URI per line</div>
                    </div>
                  </div>

                  <label class="checkbox-row">
                    <input type="checkbox" ?checked=${client.enabled} @change=${(e) => this._updateField('enabled', e.target.checked)} />
                    Enabled
                  </label>

                  <div class="actions">
                    <c-button variant="primary" ?disabled=${saving || !dirty} @click=${() => this._save()}>
                      ${saving ? 'Saving...' : 'Save Changes'}${dirty ? html`<span class="dirty-indicator"></span>` : ''}
                    </c-button>
                    <c-button variant="ghost" @click=${() => this._navigateAway('/clients')}>Cancel</c-button>
                    <c-button variant="secondary" disabled title="Endpoint not yet available">
                      Reset Secret
                    </c-button>
                  </div>
                </div>
              `
          : html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Client not found.</div>`}
      </c-page-layout>
    `;
  }
}

customElements.define('client-detail-page', ClientDetailPage);
