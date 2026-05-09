import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { get, put } from '../core/http.js';
import { navigate } from '../core/router.js';
import { showToast } from '../components/ui/toast.js';

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
      client.enabled !== savedClient.enabled
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
      const client = await get(`/api/clients/${id}`);
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
      await put(`/api/clients/${client.id}`, {
        name: client.name,
        redirect_uris: client.redirect_uris,
        allowed_scopes: client.allowed_scopes,
        allowed_grant_types: client.allowed_grant_types,
        pkce_required: client.pkce_required,
        enabled: client.enabled,
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
      client.enabled !== savedClient.enabled
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
                    <input
                      class="field-input"
                      type="text"
                      .value=${(client.allowed_grant_types || []).join(', ')}
                      @input=${(e) => this._updateCommaField('allowed_grant_types', e.target.value)}
                    />
                    <div class="hint">Comma-separated list of grant types</div>
                  </div>

                  <label class="checkbox-row">
                    <input type="checkbox" ?checked=${client.pkce_required} @change=${(e) => this._updateField('pkce_required', e.target.checked)} />
                    PKCE Required
                  </label>

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
