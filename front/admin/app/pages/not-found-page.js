import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { navigate } from '../core/router.js';

class NotFoundPage extends BaseComponent {
  template() {
    return html`
      <style>
        :host { display: block; }
        .not-found {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          min-height: 60vh;
          text-align: center;
          padding: 2rem;
        }
        .error-code {
          font-size: 6rem;
          font-weight: 700;
          color: var(--color-primary, #3b82f6);
          line-height: 1;
          margin-bottom: 0.5rem;
        }
        .error-title {
          font-size: 1.5rem;
          font-weight: 600;
          color: var(--color-text, #1e293b);
          margin-bottom: 0.5rem;
        }
        .error-message {
          font-size: 0.875rem;
          color: var(--color-text-muted, #94a3b8);
          margin-bottom: 2rem;
          max-width: 24rem;
        }
        .home-link {
          display: inline-flex;
          align-items: center;
          gap: 0.5rem;
          padding: 0.625rem 1.25rem;
          background: var(--color-primary, #3b82f6);
          color: #fff;
          border: none;
          border-radius: var(--radius-sm, 0.25rem);
          font-size: 0.875rem;
          font-weight: 500;
          cursor: pointer;
          text-decoration: none;
          transition: background 0.15s;
        }
        .home-link:hover {
          background: var(--color-primary-dark, #2563eb);
        }
      </style>
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
