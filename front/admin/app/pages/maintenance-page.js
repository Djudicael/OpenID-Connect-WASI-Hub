import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { post } from '../core/http.js';
import { showToast } from '../components/ui/toast.js';
import { handleApiError } from '../utils/error-handler.js';

const ConfirmDialog = customElements.get('c-modal');

class MaintenancePage extends BaseComponent {
  constructor() {
    super();
    this._state = {
      running: false,
      lastRun: null,
      results: null,
    };
  }

  async _runCleanup() {
    const confirmed = await ConfirmDialog.confirm('This will permanently delete all expired tokens, sessions, and codes. Continue?', 'Run Cleanup');
    if (!confirmed) return;

    this.setState({ running: true, results: null });
    try {
      const data = await post('/api/maintenance/cleanup', {});
      this.setState({
        running: false,
        lastRun: new Date().toISOString(),
        results: data,
      });
      showToast('Cleanup completed', 'success');
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to run cleanup');
      this.setState({ running: false });
    }
  }

  template() {
    const { running, lastRun, results } = this._state;

    return html`
      <style>
        :host { display: block; }
        .card {
          background: var(--color-surface);
          border-radius: var(--radius-md);
          padding: 1.5rem;
          box-shadow: var(--shadow-sm);
          margin-bottom: 1.5rem;
        }
        .card-title {
          font-size: 1rem;
          font-weight: 600;
          margin-bottom: 0.75rem;
        }
        .card-desc {
          font-size: 0.875rem;
          color: var(--color-text-muted);
          margin-bottom: 1rem;
        }
        .results-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
          gap: 0.75rem;
          margin-top: 1rem;
        }
        .result-item {
          padding: 0.75rem;
          background: var(--color-bg);
          border-radius: var(--radius-sm);
          border: 1px solid var(--color-border);
        }
        .result-table {
          font-size: 0.75rem;
          color: var(--color-text-muted);
          text-transform: uppercase;
          letter-spacing: 0.025em;
        }
        .result-count {
          font-size: 1.25rem;
          font-weight: 700;
          color: var(--color-primary);
        }
        .last-run {
          font-size: 0.875rem;
          color: var(--color-text-muted);
          margin-top: 0.5rem;
        }
      </style>
      <c-page-layout title="Maintenance">
        <div class="card">
          <div class="card-title">Token Cleanup</div>
          <div class="card-desc">
            Remove expired records from all token and session tables. This includes:
            expired sessions, password reset tokens, email verification tokens,
            account recovery tokens, device codes, authorization codes, and PAR requests.
          </div>
          <c-button variant="primary" ?disabled=${running} @click=${() => this._runCleanup()}>
            ${running ? 'Running...' : 'Run Cleanup Now'}
          </c-button>
          ${lastRun ? html`<div class="last-run">Last run: ${new Date(lastRun).toLocaleString()}</div>` : ''}
        </div>

        ${results ? html`
          <div class="card">
            <div class="card-title">Cleanup Results</div>
            <div class="results-grid">
              ${Object.entries(results).map(([table, count]) => html`
                <div class="result-item">
                  <div class="result-table">${table}</div>
                  <div class="result-count">${count}</div>
                </div>
              `)}
            </div>
          </div>
        ` : ''}
      </c-page-layout>
    `;
  }
}

customElements.define('maintenance-page', MaintenancePage);
