import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { get } from '../core/http.js';
import { formatDate } from '../utils/format.js';
import { showToast } from '../components/ui/toast.js';

class DashboardPage extends BaseComponent {
  constructor() {
    super();
    this._state = {
      stats: { users: '-', clients: '-', realms: '-', active_sessions: '-' },
      recentEvents: [],
      loading: true,
    };
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadData();
  }

  async _loadData() {
    try {
      const [stats, events] = await Promise.allSettled([
        get('/api/stats'),
        get('/api/audit/events?limit=10'),
      ]);

      const statsData = stats.status === 'fulfilled' ? stats.value : null;
      const eventsData = events.status === 'fulfilled' ? events.value : null;

      this.setState({
        stats: statsData || { users: '-', clients: '-', realms: '-', active_sessions: '-' },
        recentEvents: eventsData?.items || [],
        loading: false,
      });
    } catch (err) {
      showToast('Failed to load dashboard data', 'error');
      this.setState({ loading: false });
    }
  }

  template() {
    const { stats, recentEvents, loading } = this._state;
    return html`
      <style>
        :host { display: block; }
        .stats-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 1rem;
          margin-bottom: 1.5rem;
        }
        .stat-card {
          background: var(--color-surface);
          padding: 1.25rem;
          border-radius: var(--radius-md);
          box-shadow: var(--shadow-sm);
        }
        .stat-label {
          font-size: 0.875rem;
          color: var(--color-text-muted);
          margin-bottom: 0.5rem;
        }
        .stat-value {
          font-size: 1.75rem;
          font-weight: 700;
          color: var(--color-text);
        }
        .section-title {
          font-size: 1.125rem;
          font-weight: 600;
          margin-bottom: 1rem;
        }
        .events-table {
          width: 100%;
          border-collapse: collapse;
          font-size: 0.875rem;
        }
        .events-table th, .events-table td {
          padding: 0.75rem 1rem;
          text-align: left;
          border-bottom: 1px solid #e2e8f0;
        }
        .events-table th {
          font-weight: 600;
          color: var(--color-text-muted);
          background: #f8fafc;
          font-size: 0.75rem;
          text-transform: uppercase;
        }
        .empty-state {
          text-align: center;
          padding: 2rem;
          color: var(--color-text-muted);
        }
      </style>
      <c-page-layout title="Dashboard">
        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-label">Users</div>
            <div class="stat-value">${stats.users}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Clients</div>
            <div class="stat-value">${stats.clients}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Realms</div>
            <div class="stat-value">${stats.realms}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Active Sessions</div>
            <div class="stat-value">${stats.active_sessions}</div>
          </div>
        </div>

        <h2 class="section-title">Recent Audit Events</h2>
        ${recentEvents.length === 0
        ? html`<div class="empty-state">No recent events.</div>`
        : html`
              <table class="events-table">
                <thead>
                  <tr><th>Event</th><th>Actor</th><th>Target</th><th>Time</th></tr>
                </thead>
                <tbody>
                  ${recentEvents.map(e => html`
                    <tr>
                      <td>${e.event_type}</td>
                      <td>${e.actor_id || 'system'}</td>
                      <td>${e.target_type || '-'}</td>
                      <td>${formatDate(e.created_at)}</td>
                    </tr>
                  `)}
                </tbody>
              </table>
            `}
      </c-page-layout>
    `;
  }
}

customElements.define('dashboard-page', DashboardPage);
