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
