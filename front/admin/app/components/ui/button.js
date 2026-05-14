import { html } from 'lit-html';
import { BaseComponent } from '../../core/component.js';

class Button extends BaseComponent {
  static get observedAttributes() {
    return ['variant', 'size', 'disabled'];
  }

  constructor() {
    super();
    this._state = { variant: 'primary', size: 'md', disabled: false };
    this._onClick = this._onClick.bind(this);
  }

  attributeChangedCallback(name, oldVal, newVal) {
    if (oldVal === newVal) return;
    if (name === 'disabled') {
      this.setState({ disabled: newVal !== null });
    } else {
      this.setState({ [name]: newVal || this._state[name] });
    }
  }

  template() {
    const { variant, size, disabled } = this._state;
    const variantClass = `btn--${variant}`;
    const sizeClass = `btn--${size}`;

    return html`
      <style>
        :host { display: inline-block; }
        .btn {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 0.5rem;
          border: none;
          border-radius: var(--radius-sm);
          font-family: inherit;
          font-weight: 500;
          cursor: pointer;
          transition: background 0.15s, opacity 0.15s;
        }
        .btn:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }
        .btn--sm { padding: 0.25rem 0.5rem; font-size: 0.75rem; }
        .btn--md { padding: 0.5rem 1rem; font-size: 0.875rem; }
        .btn--lg { padding: 0.75rem 1.5rem; font-size: 1rem; }
        .btn--primary { background: var(--color-primary); color: #fff; }
        .btn--primary:hover:not(:disabled) { background: var(--color-primary-dark); }
        .btn--danger { background: var(--color-danger); color: #fff; }
        .btn--danger:hover:not(:disabled) { background: #b91c1c; }
        .btn--secondary { background: #e2e8f0; color: var(--color-text); }
        .btn--secondary:hover:not(:disabled) { background: #cbd5e1; }
        .btn--ghost { background: transparent; color: var(--color-text); border: 1px solid #e2e8f0; }
        .btn--ghost:hover:not(:disabled) { background: var(--color-bg); }
      </style>
      <button class="btn ${variantClass} ${sizeClass}" ?disabled=${disabled} @click=${this._onClick}>
        <slot></slot>
      </button>
    `;
  }

  _onClick(e) {
    if (this._state.disabled) {
      e.preventDefault();
      e.stopPropagation();
      return;
    }
    // Stop the native click from bubbling so parent lit-html @click
    // handlers don't fire twice (once from native, once from custom).
    e.stopPropagation();
    this.dispatchEvent(new CustomEvent('click', { bubbles: true, composed: true }));
  }
}

customElements.define('c-button', Button);
