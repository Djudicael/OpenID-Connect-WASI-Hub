import { html } from 'lit-html';
import { BaseComponent } from '../../core/component.js';

let pageLayoutTitleId = 0;

class PageLayout extends BaseComponent {
  constructor() {
    super();
    this._state = { title: '', loading: false };
    this._titleElementId = `page-layout-title-${++pageLayoutTitleId}`;
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

  getPageFocusTarget() {
    return this.shadowRoot?.querySelector('[data-page-focus]') || null;
  }

  focusPageContent(options = { preventScroll: true }) {
    const target = this.getPageFocusTarget();
    target?.focus(options);
    return target;
  }

  template() {
    return html`
      <div class="page">
        <div class="page-header">
          <h1 id=${this._titleElementId} class="page-title">${this._state.title}</h1>
          <slot name="actions"></slot>
        </div>
        <div class="page-content" tabindex="-1" data-page-focus aria-labelledby=${this._titleElementId}>
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
