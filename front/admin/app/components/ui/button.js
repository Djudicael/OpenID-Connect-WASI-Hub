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
