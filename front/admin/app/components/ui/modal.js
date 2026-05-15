import { html } from 'lit-html';
import { BaseComponent } from '../../core/component.js';

class Modal extends BaseComponent {
  static get observedAttributes() {
    return ['open', 'title'];
  }

  constructor() {
    super();
    this._state = { open: false, title: '' };
    this._previouslyFocusedElement = null;
    this._onKeyDown = this._onKeyDown.bind(this);
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
    // Restore focus to previously focused element
    if (this._previouslyFocusedElement) {
      this._previouslyFocusedElement.focus();
      this._previouslyFocusedElement = null;
    }
  }

  updated() {
    const { open } = this._state;
    if (open) {
      // Save the currently focused element before trapping focus
      this._previouslyFocusedElement = document.activeElement;
      // Add keydown listener for Escape and Tab trapping
      document.addEventListener('keydown', this._onKeyDown);
      // Focus the first focusable element in the modal
      requestAnimationFrame(() => this._focusFirstElement());
    } else {
      document.removeEventListener('keydown', this._onKeyDown);
    }
  }

  disconnectedCallback() {
    document.removeEventListener('keydown', this._onKeyDown);
    if (this._previouslyFocusedElement) {
      this._previouslyFocusedElement.focus();
      this._previouslyFocusedElement = null;
    }
  }

  _onKeyDown(e) {
    if (!this._state.open) return;

    if (e.key === 'Escape') {
      e.preventDefault();
      this.close();
      return;
    }

    if (e.key === 'Tab') {
      this._handleTabTrap(e);
    }
  }

  _getFocusableElements() {
    const modal = this.shadowRoot.querySelector('.modal');
    if (!modal) return [];
    const selector = 'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';
    // Focusable elements inside the shadow DOM modal
    const shadowFocusable = Array.from(modal.querySelectorAll(selector));
    // Also check slotted content (light DOM children)
    const slot = this.shadowRoot.querySelector('slot');
    const slottedFocusable = slot
      ? Array.from(slot.assignedElements({ flatten: true }))
        .reduce((acc, el) => {
          if (el.matches && el.matches(selector)) acc.push(el);
          return acc.concat(Array.from(el.querySelectorAll ? el.querySelectorAll(selector) : []));
        }, [])
      : [];
    const footerSlot = this.shadowRoot.querySelector('slot[name="footer"]');
    const footerFocusable = footerSlot
      ? Array.from(footerSlot.assignedElements({ flatten: true }))
        .reduce((acc, el) => {
          if (el.matches && el.matches(selector)) acc.push(el);
          return acc.concat(Array.from(el.querySelectorAll ? el.querySelectorAll(selector) : []));
        }, [])
      : [];

    return [...shadowFocusable, ...slottedFocusable, ...footerFocusable].filter(
      (el) => el.offsetParent !== null // visible
    );
  }

  _handleTabTrap(e) {
    const focusable = this._getFocusableElements();
    if (focusable.length === 0) {
      e.preventDefault();
      return;
    }

    const first = focusable[0];
    const last = focusable[focusable.length - 1];

    if (e.shiftKey) {
      // Shift+Tab: if on first element, wrap to last
      if (document.activeElement === first || !focusable.includes(document.activeElement)) {
        e.preventDefault();
        last.focus();
      }
    } else {
      // Tab: if on last element, wrap to first
      if (document.activeElement === last || !focusable.includes(document.activeElement)) {
        e.preventDefault();
        first.focus();
      }
    }
  }

  _focusFirstElement() {
    const focusable = this._getFocusableElements();
    if (focusable.length > 0) {
      focusable[0].focus();
    }
  }

  template() {
    const { open, title } = this._state;
    if (!open) return html``;

    // Trigger focus management after render
    requestAnimationFrame(() => this.updated());

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
      <div class="overlay" role="dialog" aria-modal="true" aria-label=${title} @click=${(e) => { if (e.target === e.currentTarget) this.close(); }}>
        <div class="modal">
          <div class="modal-header">
            <h3 class="modal-title">${title}</h3>
            <button class="modal-close" aria-label="Close dialog" @click=${() => this.close()}>&times;</button>
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

Modal.confirm = function(message, title = 'Confirm') {
  return new Promise((resolve) => {
    const modal = document.createElement('c-modal');
    modal.setAttribute('title', title);
    const content = document.createElement('div');
    content.textContent = message;
    content.style.cssText = 'font-size:0.875rem;line-height:1.5;';
    modal.appendChild(content);

    const footer = document.createElement('div');
    footer.setAttribute('slot', 'footer');
    footer.style.cssText = 'display:flex;justify-content:flex-end;gap:0.5rem;';

    const cancelBtn = document.createElement('c-button');
    cancelBtn.setAttribute('variant', 'secondary');
    cancelBtn.textContent = 'Cancel';
    cancelBtn.addEventListener('click', () => { modal.close(); });

    const okBtn = document.createElement('c-button');
    okBtn.setAttribute('variant', 'danger');
    okBtn.textContent = 'Confirm';
    okBtn.addEventListener('click', () => { resolve(true); modal.remove(); });

    footer.appendChild(cancelBtn);
    footer.appendChild(okBtn);
    modal.appendChild(footer);

    modal.addEventListener('close', () => { resolve(false); }, { once: true });

    document.body.appendChild(modal);
    modal.open();
  });
};
