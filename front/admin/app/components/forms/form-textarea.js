import { html } from 'lit-html';
import { BaseComponent } from '../../core/component.js';

class FormTextarea extends BaseComponent {
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
      rows: 4,
    };
  }

  static get observedAttributes() {
    return ['value', 'label', 'name', 'required', 'placeholder', 'error', 'hint', 'disabled', 'rows'];
  }

  attributeChangedCallback(attrName, oldVal, newVal) {
    if (oldVal === newVal) return;
    if (attrName === 'required' || attrName === 'disabled') {
      this.setState({ [attrName]: newVal !== null });
    } else if (attrName === 'rows') {
      this.setState({ [attrName]: parseInt(newVal, 10) || 4 });
    } else {
      this.setState({ [attrName]: newVal || '' });
    }
  }

  _onInput(e) {
    const value = e.target.value;
    this.setState({ value });
    this.dispatchEvent(new CustomEvent('input', {
      detail: { value, name: this._state.name },
      bubbles: true,
      composed: true,
    }));
  }

  _onChange(e) {
    const value = e.target.value;
    this.dispatchEvent(new CustomEvent('change', {
      detail: { value, name: this._state.name },
      bubbles: true,
      composed: true,
    }));
  }

  template() {
    const { value, label, name, required, placeholder, error, hint, disabled, rows } = this._state;

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
        .field-textarea {
          width: 100%;
          padding: 0.5rem 0.75rem;
          font-size: 0.875rem;
          border: 1px solid ${error ? 'var(--color-danger, #dc2626)' : '#e2e8f0'};
          border-radius: var(--radius-sm, 0.25rem);
          font-family: inherit;
          box-sizing: border-box;
          background: var(--color-surface, #fff);
          color: var(--color-text, #1e293b);
          resize: vertical;
        }
        .field-textarea:focus {
          outline: none;
          border-color: ${error ? 'var(--color-danger, #dc2626)' : 'var(--color-primary, #3b82f6)'};
          box-shadow: 0 0 0 3px ${error ? 'rgba(220,38,38,0.1)' : 'rgba(59,130,246,0.1)'};
        }
        .field-textarea:disabled {
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
        <textarea
          class="field-textarea"
          id=${name}
          name=${name}
          .value=${value}
          placeholder=${placeholder}
          rows=${rows}
          ?required=${required}
          ?disabled=${disabled}
          @input=${(e) => this._onInput(e)}
          @change=${(e) => this._onChange(e)}
        ></textarea>
        ${error ? html`<div class="field-error">${error}</div>` : ''}
        ${hint && !error ? html`<div class="field-hint">${hint}</div>` : ''}
      </div>
    `;
  }
}

customElements.define('form-textarea', FormTextarea);
