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
    const input = this.shadowRoot.querySelector('input');
    return input ? input.value : this._state.value;
  }

  set value(v) {
    this.setState({ value: v });
    const input = this.shadowRoot.querySelector('input');
    if (input) input.value = v;
  }

  template() {
    const { type, placeholder, value, label, name, required } = this._state;
    return html`
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
