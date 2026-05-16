import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { getApiKey, deleteApiKey, rotateApiKey } from '../services/apikey-service.js';
import { navigate } from '../core/router.js';
import { formatDate, formatRelativeTime } from '../utils/format.js';
import { showToast } from '../components/ui/toast.js';

class ApiKeyDetailPage extends BaseComponent {
  constructor() {
    super();
    this._state = {
      key: null,
      loading: true,
      rotating: false,
      revoking: false,
      rotatedRawKey: null,
    };
  }

  connectedCallback() {
    super.connectedCallback();
    if (this.params && this.params.id) {
      this._loadKey(this.params.id);
    }
  }

  async _loadKey(id) {
    this.setState({ loading: true });
    try {
      const key = await getApiKey(id);
      this.setState({ key, loading: false });
    } catch (err) { if (err.name === "AbortError") return;
      if (err.status === 404) {
        showToast('API key not found', 'error');
      } else {
        showToast('Failed to load API key', 'error');
      }
      this.setState({ loading: false });
    }
  }

  _getStatus(key) {
    if (key.revoked) return 'Revoked';
    if (key.expires_at && new Date(key.expires_at) < new Date()) return 'Expired';
    return 'Active';
  }

  _getStatusColor(status) {
    switch (status) {
      case 'Active': return 'var(--color-success, #16a34a)';
      case 'Revoked': return 'var(--color-danger, #dc2626)';
      case 'Expired': return 'var(--color-warning, #f59e0b)';
      default: return 'var(--color-text-muted)';
    }
  }

  async _rotateKey() {
    if (!confirm('Rotate this API key? The old key will stop working immediately.')) return;

    const key = this._state.key;
    if (!key) return;

    this.setState({ rotating: true });
    try {
      const data = await rotateApiKey(key.id);
      showToast('API key rotated successfully', 'success');
      this.setState({ rotating: false, rotatedRawKey: data.raw_key });
      // Reload key details to reflect updated state
      this._loadKey(key.id);
    } catch (err) { if (err.name === "AbortError") return;
      showToast('Failed to rotate API key', 'error');
      this.setState({ rotating: false });
    }
  }

  async _revokeKey() {
    if (!confirm('Are you sure you want to revoke this API key? This action cannot be undone.')) return;

    const key = this._state.key;
    if (!key) return;

    this.setState({ revoking: true });
    try {
      await deleteApiKey(key.id);
      showToast('API key revoked', 'success');
      this.setState({ revoking: false });
      this._loadKey(key.id);
    } catch (err) { if (err.name === "AbortError") return;
      showToast('Failed to revoke API key', 'error');
      this.setState({ revoking: false });
    }
  }

  _copyRawKey() {
    const rawKey = this._state.rotatedRawKey;
    if (!rawKey) return;
    navigator.clipboard.writeText(rawKey).then(() => {
      showToast('Copied to clipboard', 'success');
    }).catch(() => {
      // Fallback copy method
      const input = document.createElement('input');
      input.value = rawKey;
      input.style.cssText = 'position:fixed;left:-9999px';
      document.body.appendChild(input);
      input.select();
      document.execCommand('copy');
      document.body.removeChild(input);
      showToast('Copied to clipboard', 'success');
    });
  }

  template() {
    const { key, loading, rotating, revoking, rotatedRawKey } = this._state;

    return html`
      <c-page-layout title="API Key Details">
        <span class="back-link" @click=${() => navigate('/api-keys')}>
          &larr; Back to API Keys
        </span>
        ${loading
        ? html`<div class="loading-state">Loading...</div>`
        : key
          ? html`
              ${rotatedRawKey
              ? html`
                  <div class="key-display">
                    <div class="key-warning">
                      &#9888; Copy this key now. It will never be shown again.
                    </div>
                    <div class="key-value">${rotatedRawKey}</div>
                    <c-button variant="primary" size="sm" @click=${() => this._copyRawKey()}>Copy to Clipboard</c-button>
                  </div>
                `
              : ''}
              <div class="detail-grid">
                <div class="detail-row">
                  <span class="detail-label">Name</span>
                  <span class="detail-value">${key.name}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Prefix</span>
                  <span class="detail-value" style="font-family:monospace">${key.prefix}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Scopes</span>
                  <span class="detail-value">${Array.isArray(key.scopes) ? key.scopes.join(', ') : key.scopes}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Realm ID</span>
                  <span class="detail-value" style="font-family:monospace;font-size:0.8125rem">${key.realm_id}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Status</span>
                  <span class="detail-value">
                    <span class="status-badge">
                      <span class="status-dot" style="background:${this._getStatusColor(this._getStatus(key))}"></span>
                      ${this._getStatus(key)}
                    </span>
                  </span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Request Count</span>
                  <span class="detail-value">${key.request_count.toLocaleString()}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Created At</span>
                  <span class="detail-value">${formatDate(key.created_at)} (${formatRelativeTime(key.created_at)})</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Created By</span>
                  <span class="detail-value">${key.created_by || 'self'}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Last Used At</span>
                  <span class="detail-value">${key.last_used_at ? `${formatDate(key.last_used_at)} (${formatRelativeTime(key.last_used_at)})` : 'Never'}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Expires At</span>
                  <span class="detail-value">${key.expires_at ? `${formatDate(key.expires_at)} (${formatRelativeTime(key.expires_at)})` : 'Never'}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Rotated At</span>
                  <span class="detail-value">${key.rotated_at ? `${formatDate(key.rotated_at)} (${formatRelativeTime(key.rotated_at)})` : 'Never'}</span>
                </div>
              </div>
              <div class="actions">
                ${!key.revoked
              ? html`
                    <c-button
                      variant="secondary"
                      ?disabled=${rotating}
                      @click=${() => this._rotateKey()}
                    >
                      ${rotating ? 'Rotating...' : 'Rotate Key'}
                    </c-button>
                    <c-button
                      variant="danger"
                      ?disabled=${revoking}
                      @click=${() => this._revokeKey()}
                    >
                      ${revoking ? 'Revoking...' : 'Revoke Key'}
                    </c-button>
                  `
              : ''}
              </div>
            `
          : html`<div class="not-found">API key not found.</div>`
      }
      </c-page-layout>
    `;
  }
}

customElements.define('apikey-detail-page', ApiKeyDetailPage);
