import { render } from 'lit-html';

export class BaseComponent extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this._state = {};
  }

  setState(patch) {
    this._state = { ...this._state, ...patch };
    this._render();
  }

  connectedCallback() {
    this._render();
  }

  _render() {
    render(this.template(), this.shadowRoot);
  }

  template() {
    throw new Error('template() must be implemented');
  }
}
