import { html, render } from 'lit-html';

export class BaseComponent extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this._state = {};
    this._abortController = new AbortController();
  }

  async setState(patch) {
    this._state = { ...this._state, ...patch };
    this._render();
    return this._state;
  }

  get signal() {
    return this._abortController.signal;
  }

  _resetAbort() {
    this._abortController.abort();
    this._abortController = new AbortController();
  }

  connectedCallback() {
    this._render();
  }

  disconnectedCallback() {
    this._abortController.abort();
  }

  _render() {
    try {
      render(this.template(), this.shadowRoot);
    } catch (err) {
      console.error(`Component render error in <${this.tagName.toLowerCase()}>:`, err);
      render(
        html`
          <style>
            :host { display: block; }
            .error-boundary {
              padding: 1rem;
              background: #fef2f2;
              border: 1px solid #fecaca;
              border-radius: 0.375rem;
              color: #991b1b;
              font-size: 0.875rem;
            }
            .error-boundary summary {
              font-weight: 600;
              cursor: pointer;
              margin-bottom: 0.25rem;
            }
            .error-boundary pre {
              margin: 0.5rem 0 0;
              white-space: pre-wrap;
              font-size: 0.75rem;
              opacity: 0.8;
            }
          </style>
          <div class="error-boundary">
            <details>
              <summary>Component Error</summary>
              <pre>${err.message}\n${err.stack || ''}</pre>
            </details>
          </div>
        `,
        this.shadowRoot
      );
    }
  }

  template() {
    throw new Error('template() must be implemented');
  }
}
