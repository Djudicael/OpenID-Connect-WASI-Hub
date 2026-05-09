import { html } from 'lit-html';
import { BaseComponent } from '../../core/component.js';

class FormSelect extends BaseComponent {
  constructor() {
    super();
    this._state = {
      value: '',
      label: '',
      name: '',
      required: false,
      placeholder: '',
      error: '',
      hint: '',
      disabled: false,
      options: [], // Array of { value, label } objects
    };
  }

  static get observedAttributes() {
    return ['value', 'label', 'name', 'required', 'placeholder', 'error', 'hint', 'disabled'];
  }

  attributeChangedCallback(attrName, oldVal, newVal) {
    if (oldVal === newVal) return;
    if (attrName === 'required' || attrName === 'disabled') {
      this.setState({ [attrName]: newVal !== null });
    } else {
      this.setState({ [attrName]: newVal || '' });
    }
  }

  _onChange(e) {
    const value = e.target.value;
    this.setState({ value });
    this.dispatchEvent(new CustomEvent('change', {
      detail: { value, name: this._state.name },
      bubbles: true,
      composed: true,
    }));
    this.dispatchEvent(new CustomEvent('input', {
      detail: { value, name: this._state.name },
      bubbles: true,
      composed: true,
    }));
  }

  template() {
    const { value, label, name, required, placeholder, error, hint, disabled, options } = this._state;

    return html`
      <style>
        :host { display: block; }
        .field { margin-bottom: 1rem; }
        .field-label {
          display: block;
          font-size: 0.875rem;
          font-weight: 500;
          margin-bottom: 0.25rem;
          color: var(--color-text, #1e293b);
        }
        .field-label .required {
          color: var(--color-danger, #dc2626);
          margin-left: 0.125rem;
        }
        .field-select {
          width: 100%;
          padding: 0.5rem 0.75rem;
          font-size: 0.875rem;
          border: 1px solid ${error ? 'var(--color-danger, #dc2626)' : '#e2e8f0'};
          border-radius: var(--radius-sm, 0.25rem);
          font-family: inherit;
          box-sizing: border-box;
          background: var(--color-surface, #fff);
          color: var(--color-text, #1e293b);
          appearance: none;
          background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%2364748b' d='M6 8L1 3h10z'/%3E%3C/svg%3E");
          background-repeat: no-repeat;
          background-position: right 0.75rem center;
          padding-right: 2rem;
        }
        .field-select:focus {
          outline: none;
          border-color: ${error ? 'var(--color-danger, #dc2626)' : 'var(--color-primary, #3b82f6)'};
          box-shadow: 0 0 0 3px ${error ? 'rgba(220,38,38,0.1)' : 'rgba(59,130,246,0.1)'};
        }
        .field-select:disabled {
          background: #f1f5f9;
          cursor: not-allowed;
          opacity: 0.7;
        }
        .field-error {
          font-size: 0.75rem;
          color: var(--color-danger, #dc2626);
          margin-top: 0.25rem;
        }
        .field-hint {
          font-size: 0.75rem;
          color: var(--color-text-muted, #94a3b8);
          margin-top: 0.25rem;
        }
      </style>
      <div class="field">
        ${label ? html`
          <label class="field-label" for=${name}>
            ${label}${required ? html`<span class="required">*</span>` : ''}
          </label>
        ` : ''}
        <select
          class="field-select"
          id=${name}
          name=${name}
          .value=${value}
          ?required=${required}
          ?disabled=${disabled}
          @change=${(e) => this._onChange(e)}
        >
          ${placeholder ? html`<option value="" disabled ?selected=${!value}>${placeholder}</option>` : ''}
          ${(options || []).map(opt => html`
            <option value=${opt.value} ?selected=${value === opt.value}>${opt.label}</option>
          `)}
        </select>
        ${error ? html`<div class="field-error">${error}</div>` : ''}
        ${hint && !error ? html`<div class="field-hint">${hint}</div>` : ''}
      </div>
    `;
  }
}

customElements.define('form-select', FormSelect);
