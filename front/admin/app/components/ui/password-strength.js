import { html } from 'lit-html';
import { BaseComponent } from '../../core/component.js';

class PasswordStrength extends BaseComponent {
  static get observedAttributes() {
    return ['value'];
  }

  constructor() {
    super();
    this._state = { value: '', strength: 0, label: '' };
  }

  attributeChangedCallback(name, oldVal, newVal) {
    if (name === 'value' && oldVal !== newVal) {
      this._evaluate(newVal || '');
    }
  }

  _evaluate(password) {
    let score = 0;
    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
    if (/\d/.test(password)) score++;
    if (/[^a-zA-Z0-9]/.test(password)) score++;

    let label = '';
    if (password.length === 0) {
      score = 0;
      label = '';
    } else if (score <= 1) {
      label = 'Weak';
    } else if (score <= 2) {
      label = 'Fair';
    } else if (score <= 3) {
      label = 'Good';
    } else {
      label = 'Strong';
    }

    this.setState({ value: password, strength: score, label });
  }

  template() {
    const { strength, label } = this._state;
    if (!label) return html``;

    const colors = {
      0: '#dc2626',
      1: '#dc2626',
      2: '#f59e0b',
      3: '#22c55e',
      4: '#16a34a',
      5: '#15803d',
    };
    const color = colors[strength] || colors[0];
    const width = `${(strength / 5) * 100}%`;

    return html`
      <style>
        :host { display: block; margin-top: 0.5rem; }
        .strength-bar {
          height: 4px;
          background: #e2e8f0;
          border-radius: 2px;
          overflow: hidden;
          margin-bottom: 0.25rem;
        }
        .strength-fill {
          height: 100%;
          width: ${width};
          background: ${color};
          border-radius: 2px;
          transition: width 0.2s, background 0.2s;
        }
        .strength-label {
          font-size: 0.75rem;
          color: ${color};
          font-weight: 500;
        }
      </style>
      <div class="strength-bar"><div class="strength-fill"></div></div>
      <span class="strength-label">${label}</span>
    `;
  }
}

customElements.define('c-password-strength', PasswordStrength);
