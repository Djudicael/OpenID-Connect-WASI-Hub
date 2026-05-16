import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { fetchStats } from '../services/stats-service.js';
import { listAuditEvents } from '../services/audit-service.js';
import { formatDate } from '../utils/format.js';
import { showToast } from '../components/ui/toast.js';
import { handleApiError } from '../utils/error-handler.js';

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
        fetchStats(undefined, this.signal),
        listAuditEvents({ limit: '10' }, this.signal),
      ]);

      const statsData = stats.status === 'fulfilled' ? stats.value : null;
      const eventsData = events.status === 'fulfilled' ? events.value : null;

      this.setState({
        stats: statsData || { users: '-', clients: '-', realms: '-', active_sessions: '-' },
        recentEvents: eventsData?.items || [],
        loading: false,
      });
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to load dashboard data');
      this.setState({ loading: false });
    }
  }

  template() {
    const { stats, recentEvents, loading } = this._state;
    return html`
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
