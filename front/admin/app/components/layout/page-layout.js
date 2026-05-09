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
        .loading {
          color: var(--color-text-muted);
          font-style: italic;
        }
      </style>
      <div class="page">
        <div class="page-header">
          <h1 class="page-title">${this._state.title}</h1>
          <slot name="actions"></slot>
        </div>
        <div class="page-content">
          ${this._state.loading
        ? html`<div class="loading">Loading...</div>`
        : html`<slot></slot>`}
        </div>
      </div>
    `;
  }
}

customElements.define('c-page-layout', PageLayout);
