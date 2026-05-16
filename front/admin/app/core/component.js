import { html, render } from 'lit-html';

export class BaseComponent extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = '/style/bundle.css';
    this.shadowRoot.appendChild(link);
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
        html`<div class="error-boundary"><details><summary>Component Error</summary><pre>${err.message}\n${err.stack || ''}</pre></details></div>`,
        this.shadowRoot
      );
    }
  }

  template() {
    throw new Error('template() must be implemented');
  }
}
