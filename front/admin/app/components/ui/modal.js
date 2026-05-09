import { html } from 'lit-html';
import { BaseComponent } from '../../core/component.js';

class Modal extends BaseComponent {
  static get observedAttributes() {
    return ['open', 'title'];
  }

  constructor() {
    super();
    this._state = { open: false, title: '' };
  }

  attributeChangedCallback(name, oldVal, newVal) {
    if (oldVal === newVal) return;
    if (name === 'open') {
      this.setState({ open: newVal !== null });
    } else {
      this.setState({ [name]: newVal || '' });
    }
  }

  open() {
    this.setState({ open: true });
    this.setAttribute('open', '');
  }

  close() {
    this.setState({ open: false });
    this.removeAttribute('open');
    this.dispatchEvent(new CustomEvent('close', { bubbles: true, composed: true }));
  }

  template() {
    const { open, title } = this._state;
    if (!open) return html``;

    return html`
      <style>
        :host { display: block; }
        .overlay {
          position: fixed;
          inset: 0;
          background: rgba(0, 0, 0, 0.4);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 100;
          padding: 1rem;
        }
        .modal {
          background: var(--color-surface);
          border-radius: var(--radius-md);
          box-shadow: var(--shadow-md);
          max-width: 32rem;
          width: 100%;
          max-height: 90vh;
          overflow-y: auto;
        }
        .modal-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 1rem 1.5rem;
          border-bottom: 1px solid #e2e8f0;
        }
        .modal-title {
          font-size: 1.125rem;
          font-weight: 600;
          margin: 0;
        }
        .modal-close {
          background: none;
          border: none;
          font-size: 1.25rem;
          cursor: pointer;
          color: var(--color-text-muted);
        }
        .modal-body { padding: 1.5rem; }
        .modal-footer {
          display: flex;
          justify-content: flex-end;
          gap: 0.5rem;
          padding: 1rem 1.5rem;
          border-top: 1px solid #e2e8f0;
        }
      </style>
      <div class="overlay" @click=${(e) => { if (e.target === e.currentTarget) this.close(); }}>
        <div class="modal">
          <div class="modal-header">
            <h3 class="modal-title">${title}</h3>
            <button class="modal-close" @click=${() => this.close()}>&times;</button>
          </div>
          <div class="modal-body">
            <slot></slot>
          </div>
          <div class="modal-footer">
            <slot name="footer"></slot>
          </div>
        </div>
      </div>
    `;
  }
}

customElements.define('c-modal', Modal);
