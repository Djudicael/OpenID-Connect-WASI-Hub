import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { get } from '../core/http.js';
import { formatDate } from '../utils/format.js';
import { showToast } from '../components/ui/toast.js';

class AuditPage extends BaseComponent {
  constructor() {
    super();
    this._state = {
      events: [],
      loading: false,
      page: 1,
      pageSize: 20,
      total: 0,
      eventTypeFilter: '',
      actorSearch: '',
      eventTypes: [],
    };
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadEvents();
  }

  async _loadEvents() {
    this.setState({ loading: true });
    try {
      const { page, pageSize, eventTypeFilter, actorSearch } = this._state;
      const offset = (page - 1) * pageSize;
      const params = new URLSearchParams();
      params.set('limit', String(pageSize));
      params.set('offset', String(offset));
      if (eventTypeFilter) {
        params.set('event_type', eventTypeFilter);
      }
      if (actorSearch) {
        params.set('actor_id', actorSearch);
      }

      const data = await get(`/api/audit/events?${params.toString()}`);
      const events = data.items || [];
      const total = data.total || 0;

      // Extract unique event types from data for the filter dropdown
      const existingTypes = new Set(this._state.eventTypes);
      events.forEach(e => {
        if (e.event_type) existingTypes.add(e.event_type);
      });

      this.setState({
        events,
        total,
        eventTypes: Array.from(existingTypes).sort(),
        loading: false,
      });
    } catch (err) {
      showToast('Failed to load audit events', 'error');
      this.setState({ events: [], loading: false });
    }
  }

  _onPageChange(e) {
    this.setState({ page: e.detail.page });
    this._loadEvents();
  }

  _onEventTypeChange(e) {
    this.setState({ eventTypeFilter: e.target.value, page: 1 });
    this._loadEvents();
  }

  _onActorSearch(e) {
    this.setState({ actorSearch: e.target.value, page: 1 });
  }

  _onActorSearchSubmit() {
    this._loadEvents();
  }

  _clearFilters() {
    this.setState({ eventTypeFilter: '', actorSearch: '', page: 1 });
    this._loadEvents();
  }

  template() {
    const { events, loading, page, pageSize, total, eventTypeFilter, actorSearch, eventTypes } = this._state;
    const columns = [
      { key: 'event_type', label: 'Event' },
      { key: 'actor_type', label: 'Actor Type' },
      { key: 'actor_id', label: 'Actor', render: (v) => v ? v.slice(0, 8) + '...' : 'system' },
      { key: 'target_type', label: 'Target Type' },
      { key: 'target_id', label: 'Target', render: (v) => v ? v.slice(0, 8) + '...' : '-' },
      { key: 'created_at', label: 'Time', render: (v) => formatDate(v) },
    ];

    const hasFilters = eventTypeFilter || actorSearch;

    return html`
      <style>
        :host { display: block; }
        .filters {
          display: flex;
          gap: 1rem;
          margin-bottom: 1rem;
          align-items: flex-end;
          flex-wrap: wrap;
        }
        .filter-group {
          display: flex;
          flex-direction: column;
          gap: 0.25rem;
        }
        .filter-label {
          font-size: 0.75rem;
          font-weight: 500;
          color: var(--color-text-muted, #94a3b8);
          text-transform: uppercase;
          letter-spacing: 0.025em;
        }
        .filter-select,
        .filter-input {
          padding: 0.375rem 0.75rem;
          font-size: 0.875rem;
          border: 1px solid #e2e8f0;
          border-radius: var(--radius-sm, 0.25rem);
          font-family: inherit;
          background: var(--color-surface, #fff);
          color: var(--color-text, #1e293b);
          box-sizing: border-box;
        }
        .filter-select {
          min-width: 10rem;
          appearance: none;
          background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%2364748b' d='M6 8L1 3h10z'/%3E%3C/svg%3E");
          background-repeat: no-repeat;
          background-position: right 0.75rem center;
          padding-right: 2rem;
        }
        .filter-input {
          min-width: 14rem;
        }
        .filter-select:focus,
        .filter-input:focus {
          outline: none;
          border-color: var(--color-primary, #3b82f6);
        }
        .clear-btn {
          padding: 0.375rem 0.75rem;
          font-size: 0.875rem;
          border: 1px solid #e2e8f0;
          border-radius: var(--radius-sm, 0.25rem);
          background: var(--color-surface, #fff);
          color: var(--color-text-muted, #94a3b8);
          cursor: pointer;
          font-family: inherit;
        }
        .clear-btn:hover {
          background: #f8fafc;
          color: var(--color-text, #1e293b);
        }
      </style>
      <c-page-layout title="Audit Log">
        <div class="filters">
          <div class="filter-group">
            <span class="filter-label">Event Type</span>
            <select
              class="filter-select"
              .value=${eventTypeFilter}
              @change=${(e) => this._onEventTypeChange(e)}
            >
              <option value="">All Events</option>
              ${eventTypes.map(t => html`<option value=${t} ?selected=${eventTypeFilter === t}>${t}</option>`)}
            </select>
          </div>
          <div class="filter-group">
            <span class="filter-label">Actor ID</span>
            <input
              class="filter-input"
              type="text"
              placeholder="Search by actor ID..."
              .value=${actorSearch}
              @input=${(e) => this._onActorSearch(e)}
              @keydown=${(e) => { if (e.key === 'Enter') this._onActorSearchSubmit(); }}
            />
          </div>
          ${hasFilters ? html`
            <button class="clear-btn" @click=${() => this._clearFilters()}>Clear Filters</button>
          ` : ''}
        </div>
        ${loading
        ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>`
        : html`<c-table .columns=${columns} .rows=${events}></c-table>`}
        <c-pagination
          .page=${page}
          .pageSize=${pageSize}
          .total=${total}
          @page-change=${(e) => this._onPageChange(e)}
        ></c-pagination>
      </c-page-layout>
    `;
  }
}

customElements.define('audit-page', AuditPage);
