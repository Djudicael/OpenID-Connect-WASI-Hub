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

  template() {
    const { message, type } = this._state;
    const colors = {
      info: '#2563eb',
      success: '#16a34a',
      error: '#dc2626',
      warning: '#d97706',
    };
    const color = colors[type] || colors.info;

    return html`
      <style>
        :host { display: block; }
        .toast {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          padding: 0.875rem 1rem;
          background: var(--color-surface);
          border-left: 4px solid ${color};
          border-radius: var(--radius-sm);
          box-shadow: var(--shadow-md);
          font-size: 0.875rem;
          animation: slideIn 0.2s ease;
        }
        @keyframes slideIn {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        .toast-close {
          margin-left: auto;
          background: none;
          border: none;
          cursor: pointer;
          color: var(--color-text-muted);
          font-size: 1rem;
        }
      </style>
      <div class="toast">
        <span>${message}</span>
        <button class="toast-close" @click=${() => this.remove()}>&times;</button>
      </div>
    `;
  }
}

customElements.define('c-toast', Toast);

/**
 * Global toast helper.
 */
export function showToast(message, type = 'info', duration = 4000) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.style.cssText = 'position:fixed;top:1rem;right:1rem;z-index:200;display:flex;flex-direction:column;gap:0.5rem;max-width:24rem;';
    document.body.appendChild(container);
  }
  const toast = document.createElement('c-toast');
  toast.setAttribute('message', message);
  toast.setAttribute('type', type);
  toast.setAttribute('duration', String(duration));
  container.appendChild(toast);
}
