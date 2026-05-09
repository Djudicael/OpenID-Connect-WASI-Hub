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
    };
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadEvents();
  }

  async _loadEvents() {
    this.setState({ loading: true });
    try {
      const { page, pageSize } = this._state;
      const offset = (page - 1) * pageSize;
      const params = new URLSearchParams();
      params.set('limit', String(pageSize));
      params.set('offset', String(offset));

      const data = await get(`/api/audit/events?${params.toString()}`);
      this.setState({
        events: data.items || [],
        total: data.total || 0,
        loading: false,
      });
    } catch (err) {
      showToast('Failed to load audit events', 'error');
      this.setState({ events: [], loading: false });
    }
  }

  _onPageChange(e) {
    this.setState({ page: e.detail.page }, this._loadEvents());
  }

  template() {
    const { events, loading, page, pageSize, total } = this._state;
    const columns = [
      { key: 'event_type', label: 'Event' },
      { key: 'actor_type', label: 'Actor Type' },
      { key: 'actor_id', label: 'Actor', render: (v) => v ? v.slice(0, 8) + '...' : 'system' },
      { key: 'target_type', label: 'Target Type' },
      { key: 'target_id', label: 'Target', render: (v) => v ? v.slice(0, 8) + '...' : '-' },
      { key: 'created_at', label: 'Time', render: (v) => formatDate(v) },
    ];

    return html`
      <style>
        :host { display: block; }
      </style>
      <c-page-layout title="Audit Log">
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
