import { html } from 'lit-html';
import { BaseComponent } from '../../core/component.js';

class Toast extends BaseComponent {
  static get observedAttributes() {
    return ['message', 'type', 'duration'];
  }

  constructor() {
    super();
    this._state = { message: '', type: 'info', duration: 4000 };
    this._timer = null;
  }

  attributeChangedCallback(name, oldVal, newVal) {
    if (oldVal === newVal) return;
    this.setState({ [name]: name === 'duration' ? Number(newVal) || 4000 : (newVal || '') });
  }

  connectedCallback() {
    super.connectedCallback();
    this._startTimer();
    queueMicrotask(() => this._applyColor());
  }

  disconnectedCallback() {
    if (this._timer) clearTimeout(this._timer);
  }

  _startTimer() {
    if (this._timer) clearTimeout(this._timer);
    this._timer = setTimeout(() => {
      this.remove();
    }, this._state.duration);
  }

  _applyColor() {
    const colors = { info: '#2563eb', success: '#16a34a', error: '#dc2626', warning: '#d97706' };
    const toast = this.shadowRoot.querySelector('.toast');
    if (toast) toast.style.setProperty('--toast-color', colors[this._state.type] || colors.info);
  }

  template() {
    const { message } = this._state;
    return html`
      <div class="toast" role="alert">
        <span>${message}</span>
        <button class="toast-close" @click=${() => this.remove()}>&times;</button>
      </div>
    `;
  }
}

customElements.define('c-toast', Toast);

export function showToast(message, opts = {}, duration) {
  let type, dur;
  if (typeof opts === 'object') {
    type = opts.type || 'info';
    dur = opts.duration !== undefined ? opts.duration : (duration || 4000);
  } else {
    type = opts || 'info';
    dur = duration || 4000;
  }
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.style.cssText = 'position:fixed;top:1rem;right:1rem;z-index:200;display:flex;flex-direction:column;gap:0.5rem;max-width:24rem;';
    container.setAttribute('aria-live', 'polite');
    container.setAttribute('role', 'status');
    document.body.appendChild(container);
  }
  const toast = document.createElement('c-toast');
  toast.setAttribute('message', message);
  toast.setAttribute('type', type);
  toast.setAttribute('duration', String(dur));
  container.appendChild(toast);
}
