import { BaseComponent } from '../core/component.js';

class Sidebar extends BaseComponent {
  template() {
    return html`
      <nav class="sidebar">
        <ul>
          <li><a href="/">Dashboard</a></li>
          <li><a href="/users">Users</a></li>
          <li><a href="/clients">Clients</a></li>
          <li><a href="/realms">Realms</a></li>
          <li><a href="/api-keys">API Keys</a></li>
          <li><a href="/audit">Audit</a></li>
        </ul>
      </nav>
    `;
  }
}

customElements.define('c-sidebar', Sidebar);
