import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { get, del, post } from '../core/http.js';
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
      const key = await get(`/api/keys/${id}`);
      this.setState({ key, loading: false });
    } catch (err) {
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
      const data = await post(`/api/keys/${key.id}/rotate`);
      showToast('API key rotated successfully', 'success');
      this.setState({ rotating: false, rotatedRawKey: data.raw_key });
      // Reload key details to reflect updated state
      this._loadKey(key.id);
    } catch (err) {
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
      await del(`/api/keys/${key.id}`);
      showToast('API key revoked', 'success');
      this.setState({ revoking: false });
      this._loadKey(key.id);
    } catch (err) {
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
        .back-link:hover {
          text-decoration: underline;
        }
        .detail-grid {
          display: grid;
          grid-template-columns: 1fr;
          gap: 1rem;
          max-width: 40rem;
        }
        .detail-row {
          display: flex;
          flex-direction: column;
          gap: 0.25rem;
          padding-bottom: 0.75rem;
          border-bottom: 1px solid var(--color-border, #e2e8f0);
        }
        .detail-row:last-child {
          border-bottom: none;
        }
        .detail-label {
          font-size: 0.75rem;
          font-weight: 600;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          color: var(--color-text-muted, #64748b);
        }
        .detail-value {
          font-size: 0.9375rem;
          color: var(--color-text, #1e293b);
          word-break: break-all;
        }
        .status-badge {
          display: inline-flex;
          align-items: center;
          gap: 0.375rem;
          font-size: 0.8125rem;
          font-weight: 500;
        }
        .status-dot {
          width: 0.5rem;
          height: 0.5rem;
          border-radius: 50%;
          display: inline-block;
        }
        .key-display {
          background: #fffbeb;
          border: 1px solid #fde68a;
          border-radius: var(--radius-md, 0.5rem);
          padding: 1.25rem;
          margin-bottom: 1.5rem;
        }
        .key-warning {
          color: var(--color-danger, #dc2626);
          font-size: 0.875rem;
          font-weight: 600;
          margin-bottom: 0.75rem;
          display: flex;
          align-items: center;
          gap: 0.375rem;
        }
        .key-value {
          font-family: monospace;
          font-size: 0.875rem;
          background: var(--color-surface, #fff);
          padding: 0.75rem;
          border-radius: var(--radius-sm, 0.25rem);
          border: 1px solid #e2e8f0;
          word-break: break-all;
          margin-bottom: 0.75rem;
          user-select: all;
        }
        .actions {
          display: flex;
          gap: 0.5rem;
          margin-top: 1.5rem;
        }
        .loading-state {
          padding: 2rem;
          text-align: center;
          color: var(--color-text-muted);
        }
        .not-found {
          padding: 2rem;
          text-align: center;
          color: var(--color-text-muted);
        }
      </style>
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
