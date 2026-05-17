import { html } from 'lit-html';
import { BaseComponent } from '../../core/component.js';

const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'textarea:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
  '[contenteditable="true"]',
].join(', ');

class Modal extends BaseComponent {
  static get observedAttributes() {
    return ['open', 'title'];
  }

  constructor() {
    super();
    this._state = { open: false, title: '' };
    this._previouslyFocusedElement = null;
    this._focusTrapActive = false;
    this._focusRaf = null;
    this._onKeyDown = this._onKeyDown.bind(this);
  }

  attributeChangedCallback(name, oldVal, newVal) {
    if (oldVal === newVal) return;

    if (name === 'open') {
      const isOpen = newVal !== null;
      const wasOpen = this._state.open;
      this.setState({ open: isOpen });

      if (isOpen && !wasOpen) {
        this._activateFocusTrap();
      } else if (!isOpen && wasOpen) {
        this._deactivateFocusTrap();
      }
      return;
    }

    this.setState({ [name]: newVal || '' });
  }

  open() {
    if (this.hasAttribute('open')) return;

    this._previouslyFocusedElement = this._getDeepActiveElement(document);
    this.setAttribute('open', '');
  }

  close() {
    if (!this.hasAttribute('open') && !this._state.open) return;

    this._deactivateFocusTrap();
    this.removeAttribute('open');
    this.dispatchEvent(new CustomEvent('close', { bubbles: true, composed: true }));
    this._restoreFocus();
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    this._deactivateFocusTrap();
    this._restoreFocus();
  }

  _activateFocusTrap() {
    if (this._focusTrapActive) return;

    this._focusTrapActive = true;
    document.addEventListener('keydown', this._onKeyDown);
    this._queueFocusFirstElement();
  }

  _deactivateFocusTrap() {
    document.removeEventListener('keydown', this._onKeyDown);
    this._focusTrapActive = false;
    if (this._focusRaf !== null) {
      cancelAnimationFrame(this._focusRaf);
      this._focusRaf = null;
    }
  }

  _queueFocusFirstElement() {
    if (this._focusRaf !== null) {
      cancelAnimationFrame(this._focusRaf);
    }

    this._focusRaf = requestAnimationFrame(() => {
      this._focusRaf = null;
      this._focusFirstElement();
    });
  }

  _restoreFocus() {
    if (!this._previouslyFocusedElement || !this._previouslyFocusedElement.isConnected) {
      this._previouslyFocusedElement = null;
      return;
    }

    if (typeof this._previouslyFocusedElement.focus === 'function') {
      this._previouslyFocusedElement.focus({ preventScroll: true });
    }
    this._previouslyFocusedElement = null;
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

  _getDeepActiveElement(root = document) {
    let active = root?.activeElement || null;

    while (active?.shadowRoot?.activeElement) {
      active = active.shadowRoot.activeElement;
    }

    return active;
  }

  _isVisible(el) {
    return !!el && !el.hidden && el.getClientRects().length > 0;
  }

  _isFocusable(el) {
    if (!(el instanceof HTMLElement)) return false;
    if (!el.matches(FOCUSABLE_SELECTOR)) return false;
    if (!this._isVisible(el)) return false;
    if (el.hasAttribute('disabled') || el.getAttribute('aria-hidden') === 'true') return false;
    if (el.tabIndex < 0 && !el.matches('input, select, textarea, button, a[href]')) return false;
    return true;
  }

  _collectFocusableElements(root, focusable, seen) {
    if (!root) return;

    const children = root instanceof HTMLSlotElement
      ? root.assignedElements({ flatten: true })
      : Array.from(root.children || []);

    for (const child of children) {
      if (child instanceof HTMLElement && this._isFocusable(child) && !seen.has(child)) {
        seen.add(child);
        focusable.push(child);
      }

      if (child.shadowRoot) {
        this._collectFocusableElements(child.shadowRoot, focusable, seen);
      }

      this._collectFocusableElements(child, focusable, seen);
    }
  }

  _getFocusableElements() {
    const modal = this.shadowRoot?.querySelector('.modal');
    if (!modal) return [];

    const focusable = [];
    this._collectFocusableElements(modal, focusable, new Set());
    return focusable;
  }

  _isNodeInsideModal(node) {
    let current = node;
    while (current) {
      if (current === this) return true;
      current = current.assignedSlot || current.parentNode || current.host || null;
    }
    return false;
  }

  _handleTabTrap(e) {
    const focusable = this._getFocusableElements();
    const modal = this.shadowRoot?.querySelector('.modal');
    const active = this._getDeepActiveElement(document);

    if (focusable.length === 0) {
      e.preventDefault();
      modal?.focus({ preventScroll: true });
      return;
    }

    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    const activeInsideModal = active && this._isNodeInsideModal(active);

    if (e.shiftKey) {
      if (!activeInsideModal || active === first) {
        e.preventDefault();
        last.focus({ preventScroll: true });
      }
      return;
    }

    if (!activeInsideModal || active === last) {
      e.preventDefault();
      first.focus({ preventScroll: true });
    }
  }

  _focusFirstElement() {
    const focusable = this._getFocusableElements();
    if (focusable.length > 0) {
      focusable[0].focus({ preventScroll: true });
      return;
    }

    const modal = this.shadowRoot?.querySelector('.modal');
    modal?.focus({ preventScroll: true });
  }

  template() {
    const { open, title } = this._state;
    if (!open) return html``;

    return html`
      <div class="overlay" role="dialog" aria-modal="true" aria-label=${title} @click=${(e) => { if (e.target === e.currentTarget) this.close(); }}>
        <div class="modal" tabindex="-1">
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

Modal.confirm = function (message, title = 'Confirm') {
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
