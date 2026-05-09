import { html } from 'lit-html';
import { BaseComponent } from '../../core/component.js';

class Input extends BaseComponent {
  static get observedAttributes() {
    return ['type', 'placeholder', 'value', 'label', 'name', 'required'];
  }

  constructor() {
    super();
    this._state = { type: 'text', placeholder: '', value: '', label: '', name: '', required: false };
  }

  attributeChangedCallback(name, oldVal, newVal) {
    if (oldVal === newVal) return;
    if (name === 'required') {
      this.setState({ required: newVal !== null });
    } else {
      this.setState({ [name]: newVal || '' });
    }
  }

  get value() {
    const input = this.shadowRoot?.querySelector('input');
    return input ? input.value : this._state.value;
  }

  set value(v) {
    this.setState({ value: v });
    const input = this.shadowRoot?.querySelector('input');
    if (input) input.value = v;
  }

  template() {
    const { type, placeholder, value, label, name, required } = this._state;
    return html`
      <style>
        :host { display: block; margin-bottom: 1rem; }
        .field-label {
          display: block;
          font-size: 0.875rem;
          font-weight: 500;
          margin-bottom: 0.25rem;
          color: var(--color-text);
        }
        .field-input {
          width: 100%;
          padding: 0.5rem 0.75rem;
          font-size: 0.875rem;
          border: 1px solid #e2e8f0;
          border-radius: var(--radius-sm);
          background: var(--color-surface);
          color: var(--color-text);
          font-family: inherit;
          box-sizing: border-box;
        }
        .field-input:focus {
          outline: none;
          border-color: var(--color-primary);
          box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.1);
        }
      </style>
      ${label ? html`<label class="field-label">${label}${required ? html` <span style="color:var(--color-danger)">*</span>` : ''}</label>` : ''}
      <input
        class="field-input"
        type=${type}
        name=${name}
        placeholder=${placeholder}
        .value=${value}
        ?required=${required}
        @input=${(e) => this.setState({ value: e.target.value })}
      />
    `;
  }
}

customElements.define('c-input', Input);
