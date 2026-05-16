import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { navigate } from '../core/router.js';

class NotFoundPage extends BaseComponent {
  template() {
    return html`
      <div class="not-found">
        <div class="error-code">404</div>
        <div class="error-title">Page Not Found</div>
        <div class="error-message">
          The page you're looking for doesn't exist or has been moved.
        </div>
        <a class="home-link" href="/" @click=${(e) => { e.preventDefault(); navigate('/'); }}>
          &larr; Back to Dashboard
        </a>
      </div>
    `;
  }
}

customElements.define('not-found-page', NotFoundPage);
