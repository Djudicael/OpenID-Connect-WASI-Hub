import { html } from 'lit-html';
import { BaseComponent } from '../../core/component.js';

class Pagination extends BaseComponent {
  static get observedAttributes() {
    return ['page', 'page-size', 'total'];
  }

  constructor() {
    super();
    this._state = { page: 1, pageSize: 20, total: 0 };
  }

  get page() {
    return this._state.page;
  }

  set page(value) {
    this.setState({ page: Number(value) || 1 });
  }

  get pageSize() {
    return this._state.pageSize;
  }

  set pageSize(value) {
    this.setState({ pageSize: Number(value) || 20 });
  }

  get total() {
    return this._state.total;
  }

  set total(value) {
    this.setState({ total: Number(value) || 0 });
  }

  attributeChangedCallback(name, oldVal, newVal) {
    if (oldVal === newVal) return;
    const num = Number(newVal);
    if (name === 'page') this.setState({ page: num || 1 });
    if (name === 'page-size') this.setState({ pageSize: num || 20 });
    if (name === 'total') this.setState({ total: num || 0 });
  }

  _totalPages() {
    return Math.max(1, Math.ceil(this._state.total / this._state.pageSize));
  }

  _goTo(page) {
    const totalPages = this._totalPages();
    if (page < 1 || page > totalPages) return;
    this.setState({ page });
    this.dispatchEvent(new CustomEvent('page-change', {
      detail: { page, pageSize: this._state.pageSize },
      bubbles: true,
      composed: true,
    }));
  }

  template() {
    const { page, total } = this._state;
    const totalPages = this._totalPages();
    if (totalPages <= 1) return html``;

    const pages = [];
    const start = Math.max(1, page - 2);
    const end = Math.min(totalPages, page + 2);
    for (let i = start; i <= end; i++) pages.push(i);

    return html`
      <style>
        :host { display: flex; justify-content: center; margin-top: 1rem; }
        .pagination {
          display: flex;
          gap: 0.25rem;
          align-items: center;
        }
        .page-btn {
          padding: 0.375rem 0.625rem;
          font-size: 0.875rem;
          border: 1px solid #e2e8f0;
          background: var(--color-surface);
          color: var(--color-text);
          border-radius: var(--radius-sm);
          cursor: pointer;
        }
        .page-btn:hover:not(:disabled) { background: var(--color-bg); }
        .page-btn.active {
          background: var(--color-primary);
          color: #fff;
          border-color: var(--color-primary);
        }
        .page-btn:disabled { opacity: 0.4; cursor: not-allowed; }
        .page-info {
          font-size: 0.875rem;
          color: var(--color-text-muted);
          margin-left: 0.75rem;
        }
      </style>
      <div class="pagination">
        <button class="page-btn" ?disabled=${page <= 1} @click=${() => this._goTo(page - 1)}>Prev</button>
        ${pages.map(p => html`
          <button class="page-btn ${p === page ? 'active' : ''}" @click=${() => this._goTo(p)}>${p}</button>
        `)}
        <button class="page-btn" ?disabled=${page >= totalPages} @click=${() => this._goTo(page + 1)}>Next</button>
        <span class="page-info">${page} / ${totalPages} (${total} total)</span>
      </div>
    `;
  }
}

customElements.define('c-pagination', Pagination);
