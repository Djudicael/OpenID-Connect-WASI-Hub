import { html } from 'lit-html';
import { BaseComponent } from '../../core/component.js';

class PageLayout extends BaseComponent {
  constructor() {
    super();
    this._state = { title: '', loading: false };
  }

  get title() {
    return this._state.title;
  }

  set title(value) {
    this.setState({ title: value || '' });
  }

  static get observedAttributes() {
    return ['title'];
  }

  attributeChangedCallback(name, oldVal, newVal) {
    if (name === 'title' && oldVal !== newVal) {
      this.setState({ title: newVal || '' });
    }
  }

  template() {
    return html`
      <style>
        :host {
          display: block;
          flex: 1;
          min-width: 0;
        }
        .page {
          padding: 1.5rem;
          max-width: 1200px;
        }
        .page-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 1.5rem;
        }
        .page-title {
          font-size: 1.5rem;
          font-weight: 600;
          margin: 0;
        }
        .page-content {
          background: var(--color-surface);
          border-radius: var(--radius-md);
          padding: 1.5rem;
          box-shadow: var(--shadow-sm);
        }
        .skeleton {
          display: flex;
          flex-direction: column;
          gap: 1rem;
        }
        .skeleton-row {
          height: 1rem;
          border-radius: 0.25rem;
          background: linear-gradient(90deg, #e2e8f0 25%, #f1f5f9 50%, #e2e8f0 75%);
          background-size: 200% 100%;
          animation: skeleton-pulse 1.5s ease-in-out infinite;
        }
        .skeleton-row.wide { width: 100%; }
        .skeleton-row.medium { width: 75%; }
        .skeleton-row.narrow { width: 50%; }
        .skeleton-row.tall { height: 2.5rem; }
        @keyframes skeleton-pulse {
          0% { background-position: 200% 0; }
          100% { background-position: -200% 0; }
        }
      </style>
      <div class="page">
        <div class="page-header">
          <h1 class="page-title">${this._state.title}</h1>
          <slot name="actions"></slot>
        </div>
        <div class="page-content">
          ${this._state.loading
        ? html`
              <div class="skeleton">
                <div class="skeleton-row wide"></div>
                <div class="skeleton-row medium"></div>
                <div class="skeleton-row wide"></div>
                <div class="skeleton-row narrow"></div>
                <div class="skeleton-row wide"></div>
                <div class="skeleton-row medium"></div>
              </div>
            `
        : html`<slot></slot>`}
        </div>
      </div>
    `;
  }
}

customElements.define('c-page-layout', PageLayout);
