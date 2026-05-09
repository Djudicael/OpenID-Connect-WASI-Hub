# Frontend Plan — Management UI

Inspired by `djmxcreation_backend/front/admin`. Pure native Web Components, zero React/Vue/Angular. Built with `esbuild` and `lit-html`.

---

## 1. Architecture

```
front/admin/
├── app/
│   ├── index.js              # Entry point: define custom elements, boot router
│   ├── config/
│   │   └── api.js            # API base URL resolution
│   ├── core/
│   │   ├── router.js         # <router-outlet> implementation
│   │   ├── store.js          # Lightweight observable state
│   │   ├── http.js           # Fetch wrapper with auth + error handling
│   │   └── component.js      # Base class extending HTMLElement
│   ├── auth/
│   │   ├── auth-service.js   # OIDC login/logout/token refresh
│   │   └── auth-guard.js     # Route guard mixin
│   ├── components/
│   │   ├── layout/
│   │   │   ├── sidebar.js    # <c-sidebar>
│   │   │   ├── header.js     # <c-header>
│   │   │   └── page-layout.js # <c-page-layout>
│   │   ├── ui/
│   │   │   ├── button.js
│   │   │   ├── input.js
│   │   │   ├── table.js
│   │   │   ├── modal.js
│   │   │   ├── toast.js
│   │   │   └── pagination.js
│   │   └── forms/
│   │       ├── user-form.js
│   │       ├── client-form.js
│   │       ├── apikey-form.js
│   │       └── realm-form.js
│   ├── pages/
│   │   ├── login-page.js
│   │   ├── dashboard-page.js
│   │   ├── users-page.js
│   │   ├── user-detail-page.js
│   │   ├── clients-page.js
│   │   ├── realms-page.js
│   │   ├── sessions-page.js
│   │   ├── apikeys-page.js
│   │   ├── apikey-create-page.js
│   │   └── audit-page.js
│   └── utils/
│       ├── dom.js
│       ├── format.js         # date, bytes, etc.
│       └── validators.js
├── style/
│   ├── index.css             # CSS variables, reset, base
│   ├── layout.css
│   ├── components.css
│   └── pages.css
├── index.html
├── app.js                    # Express dev server (same as reference)
├── dev.js
├── buildJs.js                # esbuild script
└── package.json
```

---

## 2. Technology Choices

| Concern | Choice | Reason |
|---------|--------|--------|
| Components | Native `HTMLElement` | Zero runtime, smallest bundle |
| Templating | `lit-html` | Efficient DOM updates, small footprint |
| Routing | Custom `<router-outlet>` | No SPA framework needed |
| State | Custom observable store | 50 lines, no Redux complexity |
| Styling | CSS Custom Properties | Themable at runtime |
| Build | `esbuild` | Fast, no config bloat |
| Dev Server | Express (from reference) | SPA fallback, static assets |

---

## 3. Base Component Class

```javascript
// app/core/component.js
import { render } from 'lit-html';

export class BaseComponent extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this._state = {};
  }

  setState(patch) {
    this._state = { ...this._state, ...patch };
    this._render();
  }

  connectedCallback() {
    this._render();
  }

  _render() {
    render(this.template(), this.shadowRoot);
  }

  template() {
    throw new Error('template() must be implemented');
  }
}
```

---

## 4. Router Implementation

```javascript
// app/core/router.js
const routes = [
  { path: '/login', component: 'login-page', public: true },
  { path: '/', component: 'dashboard-page' },
  { path: '/users', component: 'users-page' },
  { path: '/users/:id', component: 'user-detail-page' },
  { path: '/clients', component: 'clients-page' },
  { path: '/realms', component: 'realms-page' },
  { path: '/sessions', component: 'sessions-page' },
  { path: '/api-keys', component: 'apikeys-page' },
  { path: '/api-keys/create', component: 'apikey-create-page' },
  { path: '/audit', component: 'audit-page' },
];

class RouterOutlet extends HTMLElement {
  connectedCallback() {
    window.addEventListener('popstate', () => this._match());
    this._match();
  }

  _match() {
    const path = window.location.pathname;
    const route = routes.find(r => this._matchPath(r.path, path));
    
    if (!route) {
      this.innerHTML = '<h1>404</h1>';
      return;
    }
    
    if (!route.public && !authService.isAuthenticated()) {
      window.history.pushState({}, '', '/login');
      this._match();
      return;
    }
    
    this.innerHTML = '';
    const el = document.createElement(route.component);
    el.params = this._extractParams(route.path, path);
    this.appendChild(el);
  }
  
  _matchPath(pattern, path) { /* ... */ }
  _extractParams(pattern, path) { /* ... */ }
}

customElements.define('router-outlet', RouterOutlet);
```

---

## 5. Auth Service (OIDC Client-Side)

```javascript
// app/auth/auth-service.js
class AuthService {
  constructor() {
    this.config = {
      authority: window.__OIDC_AUTHORITY__ || '/oidc',
      client_id: 'admin-ui',
      redirect_uri: `${window.location.origin}/admin/callback`,
      response_type: 'code',
      scope: 'openid profile email',
    };
    this.tokens = JSON.parse(localStorage.getItem('oidc_tokens') || 'null');
  }

  isAuthenticated() {
    return this.tokens && this.tokens.expires_at > Date.now();
  }

  async login() {
    const state = this._randomString(32);
    const codeChallenge = await this._generatePKCE();
    sessionStorage.setItem('oidc_state', state);
    sessionStorage.setItem('oidc_code_verifier', codeChallenge.verifier);
    
    const url = new URL(`${this.config.authority}/authorize`);
    url.searchParams.set('client_id', this.config.client_id);
    url.searchParams.set('redirect_uri', this.config.redirect_uri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', this.config.scope);
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', codeChallenge.challenge);
    url.searchParams.set('code_challenge_method', 'S256');
    
    window.location.href = url.toString();
  }

  async handleCallback() {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');
    
    if (state !== sessionStorage.getItem('oidc_state')) {
      throw new Error('Invalid state');
    }
    
    const response = await fetch(`${this.config.authority}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: this.config.redirect_uri,
        client_id: this.config.client_id,
        code_verifier: sessionStorage.getItem('oidc_code_verifier'),
      }),
    });
    
    this.tokens = await response.json();
    this.tokens.expires_at = Date.now() + this.tokens.expires_in * 1000;
    localStorage.setItem('oidc_tokens', JSON.stringify(this.tokens));
    window.history.replaceState({}, '', '/');
  }

  async fetchWithAuth(url, options = {}) {
    if (this.tokens.expires_at - Date.now() < 60000) {
      await this._refresh();
    }
    options.headers = {
      ...options.headers,
      'Authorization': `Bearer ${this.tokens.access_token}`,
    };
    return fetch(url, options);
  }

  logout() {
    localStorage.removeItem('oidc_tokens');
    window.location.href = `${this.config.authority}/logout?post_logout_redirect_uri=${encodeURIComponent(window.location.origin)}`;
  }
}

export const authService = new AuthService();
```

**Validation Criteria**:
- [ ] PKCE code challenge generated correctly (SHA-256, base64url)
- [ ] State parameter validated on callback
- [ ] Token refresh automatic before expiry
- [ ] Logout clears storage and redirects to OIDC logout endpoint

---

## 6. Key Pages

### Dashboard
- Stats cards: Users, Active Sessions, API Keys
- Recent audit events table (last 10)
- System health indicator

### Users Page
- Paginated table with search/filter
- Actions: View, Enable/Disable, Reset Password
- Bulk actions (phase 2)

### API Keys Page
- List with prefix, scopes, expiry, usage
- "Create Key" button → modal with raw key display (copy button)
- Revoke action with confirmation

---

## 7. Styling System

```css
/* style/index.css */
:root {
  --color-primary: #2563eb;
  --color-primary-dark: #1d4ed8;
  --color-danger: #dc2626;
  --color-success: #16a34a;
  --color-bg: #f8fafc;
  --color-surface: #ffffff;
  --color-text: #0f172a;
  --color-text-muted: #64748b;
  --font-sans: system-ui, -apple-system, sans-serif;
  --radius-sm: 4px;
  --radius-md: 8px;
  --shadow-sm: 0 1px 2px rgba(0,0,0,0.05);
  --shadow-md: 0 4px 6px rgba(0,0,0,0.1);
}

* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: var(--font-sans);
  background: var(--color-bg);
  color: var(--color-text);
}
```

---

## 8. Build System

```javascript
// buildJs.js
import esbuild from 'esbuild';

await esbuild.build({
  entryPoints: ['app/index.js'],
  bundle: true,
  outfile: 'dist/js/index.js',
  format: 'esm',
  target: 'es2022',
  minify: true,
  sourcemap: true,
  loader: {
    '.css': 'text',
  },
});
```

```json
// package.json
{
  "name": "oidc-admin-ui",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "node dev.js",
    "build": "node buildJs.js",
    "build:watch": "nodemon --watch app --watch style buildJs.js"
  },
  "dependencies": {
    "esbuild": "^0.25",
    "lit-html": "^3"
  },
  "devDependencies": {
    "express": "^4",
    "nodemon": "^3"
  }
}
```

---

## 9. API Base URL Resolution

Same pattern as reference:
1. Runtime global: `globalThis.__OIDC_API_BASE_URL__`
2. HTML meta tag: `<meta name="oidc-api-base-url" content="...">`
3. Build-time env: `import.meta.env.BACKEND_API_URL`
4. Default: relative paths (`/api/...`)

---

## 10. Checklist

- [ ] `index.html` loads with `<c-sidebar>` and `<router-outlet>`
- [ ] `esbuild` bundles to `dist/js/index.js` without errors
- [ ] No React, Vue, or Angular dependencies in `package.json`
- [ ] All components extend `HTMLElement` or `BaseComponent`
- [ ] Router handles `/login`, `/`, `/users`, `/api-keys`, `/audit`
- [ ] Auth service implements Authorization Code + PKCE
- [ ] Token refresh automatic before 60s expiry
- [ ] HTTP client adds `Authorization: Bearer` to all API calls
- [ ] Dashboard displays real stats from `/api/stats`
- [ ] Users page supports pagination and search
- [ ] API Keys page shows raw key exactly once with copy button
- [ ] Audit page shows recent events
- [ ] CSS theming works via CSS Custom Properties
- [ ] Dev server (`npm run dev`) serves at `localhost:3008`
- [ ] Production build minified and source-mapped
- [ ] All API calls use relative paths by default
