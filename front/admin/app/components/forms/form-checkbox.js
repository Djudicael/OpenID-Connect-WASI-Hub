import { html } from 'lit-html';
import { BaseComponent } from '../../core/component.js';

class FormCheckbox extends BaseComponent {
  constructor() {
    super();
    this._state = {
      checked: false,
      label: '',
      name: '',
      required: false,
      error: '',
      hint: '',
      disabled: false,
    };
  }

  static get observedAttributes() {
    return ['checked', 'label', 'name', 'required', 'error', 'hint', 'disabled'];
  }

  attributeChangedCallback(attrName, oldVal, newVal) {
    if (oldVal === newVal) return;
    if (attrName === 'checked' || attrName === 'required' || attrName === 'disabled') {
      this.setState({ [attrName]: newVal !== null });
    } else {
      this.setState({ [attrName]: newVal || '' });
    }
  }

  _onChange(e) {
    const checked = e.target.checked;
    this.setState({ checked });
    this.dispatchEvent(new CustomEvent('change', {
      detail: { checked, name: this._state.name },
      bubbles: true,
      composed: true,
    }));
    this.dispatchEvent(new CustomEvent('input', {
      detail: { checked, name: this._state.name },
      bubbles: true,
      composed: true,
    }));
  }

  template() {
    const { checked, label, name, required, error, hint, disabled } = this._state;

    return html`
      <style>
        :host { display: block; }
        .checkbox-field { margin-bottom: 1rem; }
        .checkbox-row {
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }
        .checkbox-input {
          width: 1rem;
          height: 1rem;
          accent-color: var(--color-primary, #3b82f6);
          cursor: pointer;
        }
        .checkbox-input:disabled {
          cursor: not-allowed;
          opacity: 0.7;
        }
        .checkbox-label {
          font-size: 0.875rem;
          color: var(--color-text, #1e293b);
          cursor: pointer;
          user-select: none;
        }
        .checkbox-label .required {
          color: var(--color-danger, #dc2626);
          margin-left: 0.125rem;
        }
        .field-error {
          font-size: 0.75rem;
          color: var(--color-danger, #dc2626);
          margin-top: 0.25rem;
          margin-left: 1.5rem;
        }
        .field-hint {
          font-size: 0.75rem;
          color: var(--color-text-muted, #94a3b8);
          margin-top: 0.25rem;
          margin-left: 1.5rem;
        }
      </style>
      <div class="checkbox-field">
        <label class="checkbox-row">
          <input
            class="checkbox-input"
            type="checkbox"
            id=${name}
            name=${name}
            .checked=${checked}
            ?required=${required}
            ?disabled=${disabled}
            @change=${(e) => this._onChange(e)}
          />
          <span class="checkbox-label">
            ${label}${required ? html`<span class="required">*</span>` : ''}
          </span>
        </label>
        ${error ? html`<div class="field-error">${error}</div>` : ''}
        ${hint && !error ? html`<div class="field-hint">${hint}</div>` : ''}
      </div>
    `;
  }
}

customElements.define('form-checkbox', FormCheckbox);
