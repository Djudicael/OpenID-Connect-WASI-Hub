---
name: wasi-frontend
description: Build the OpenID Connect WASI Hub admin UI (front/admin) with native Web Components (Custom Elements) and lit-html templates, bundled by esbuild. Use when adding pages, components, routes, API services, state, forms, auth (OIDC PKCE), styles, or Playwright tests. No React, Vue, Angular, Svelte, or the Lit framework (LitElement); only HTMLElement + lit-html.
---

# Admin UI: native Web Components + lit-html

- **Custom Elements** (`class X extends HTMLElement`) for every page and
  component, usually through `BaseComponent`.
- **`lit-html`** (`html`, `render`, directives) for templating only. No
  `LitElement`, no `lit` decorators.
- **`esbuild`** bundles `app/index.js` → `dist/js/index.js`; CSS files in
  `style/` are concatenated into `dist/style/bundle.<hash>.css` (linked from
  `dist/index.html`) and `dist/style/bundle.css` (stable URL for shadow DOM).
- **No framework, router library, or state library.** Routing, HTTP, and state
  are small modules in `app/core/`.
- The build is served in production by `oidc-admin-wasi` (see
  `wasi-frontend-packaging`), on the same origin as the Hub API.

## Layout (`front/admin`)

```text
front/admin/
├── package.json        # scripts: dev, build, build:dev, build:watch, e2e*
├── buildJs.js          # esbuild bundle + CSS concat/hash + index.html rewrite
├── dev.js              # express dev server: security headers/CSP, SPA fallback
├── index.html          # shell: c-header, c-sidebar, c-session-timer, <router-outlet>
├── playwright.config.js
├── app/
│   ├── index.js        # imports every component/page file (registration)
│   ├── config/api.js   # base URL from <meta name="oidc-api-base-url">, apiUrl()
│   ├── core/           # component.js, router.js, http.js, store.js, realm-context.js
│   ├── auth/           # auth-service.js (Authorization Code + PKCE)
│   ├── services/       # <resource>-service.js — the only place that calls http
│   ├── components/
│   │   ├── layout/     # c-header, c-sidebar, c-page-layout
│   │   └── ui/         # c-button, c-input, c-modal, c-table, c-toast, c-pagination, …
│   ├── pages/          # <name>-page.js, one per route
│   └── utils/          # validators, format, error-handler, http-utils, dom
├── style/              # plain CSS split by concern (index, layout, components, pages, shared/)
└── e2e/                # Playwright specs + helpers.js
```

## Core modules (`app/core/`)

- **`BaseComponent`** (`component.js`): attaches an open shadow root with
  `<link rel="stylesheet" href="/style/bundle.css">`, keeps `_state`,
  `setState(patch)` (merge + re-render), `this.signal` from an
  `AbortController` aborted on disconnect, and `template()` rendered by
  `_render()` with an error boundary.
- **Router** (`router.js`): a `routes` table
  `{ path, component, public?, account? }` with `:param` segments, History API
  navigation, link interception, and `navigate(path)`. `<router-outlet>`
  creates the page element; non-public routes require `authService`.
- **HTTP** (`http.js`): `http(url, options)` resolves `apiUrl`, sends JSON,
  `credentials: 'same-origin'`, the `Authorization: Bearer` token, and the
  `x-csrf-token` header from the `oidc_csrf_token` cookie. Throws
  `HttpError`; helpers `get`, `post`, `put`, `del`.
- **Services**: `services/<resource>-service.js` use
  `createCrudService('<resource>')` (`utils/http-utils.js`) plus explicit
  functions for extra endpoints. **Components never call `fetch` directly.**
- **Store** (`store.js`): `appStore` for cross-page state (user, toasts,
  sidebar). Page-local state stays in `_state`.
- **Realm context** (`realm-context.js`): the selected realm shared by
  realm-scoped pages.

## Writing a page

```js
import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { listClients } from '../services/client-service.js';
import { handleApiError } from '../utils/error-handler.js';

class ClientsPage extends BaseComponent {
  constructor() {
    super();
    this._state = { items: [], loading: false };
  }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    this.setState({ loading: true });
    try {
      const data = await listClients({ limit: '20' }, this.signal);
      this.setState({ items: data.items ?? [], loading: false });
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to load clients');
      this.setState({ loading: false });
    }
  }

  template() {
    const { items, loading } = this._state;
    if (loading && !items.length) return html`<div role="status">Loading…</div>`;
    return html`<c-page-layout>…</c-page-layout>`;
  }
}

customElements.define('clients-page', ClientsPage);
```

Then import the file in `app/index.js` and add the route in `core/router.js`.
Check the service signature before calling it.

Rules:

- **Naming:** pages are `pages/<name>-page.js` with tag `<name>-page`;
  reusable components are `components/ui/<name>.js` with tag `c-<name>`.
  Class names are PascalCase.
- **Events:** bind with `@click=${…}` and `.value=${…}`. Remove listeners on
  `window`/`document` in `disconnectedCallback`.
- **Data flow:** parent → child through properties or attributes; child →
  parent through `CustomEvent(name, { detail, bubbles: true, composed: true })`.
- **Async:** pass `this.signal` to every service call and ignore `AbortError`.
- **States:** every data page renders loading, error, and empty states with
  `role="status"` / `role="alert"`. Warn before leaving unsaved changes where
  forms are long (see the realm pages).
- **Security:** keep lit-html escaping; never use `unsafeHTML` on server or
  user content. No inline `<script>` or `on*` attributes, so the CSP stays
  `script-src 'self'`. Tokens stay in memory/`sessionStorage` (never
  `localStorage`).
- **Accessibility:** real `<button>`/`<a>` elements, labels on inputs, focus
  return after a modal closes, Escape closes overlays, the skip link stays in
  `index.html`, and `prefers-reduced-motion` is respected.
- **Text:** UI text is English.

## Configuration and auth

- API calls use **relative paths** (`/api/...`, `/oidc/...`) so one build works
  behind the proxy. `<meta name="oidc-api-base-url">` can override the base.
- `auth-service.js` runs Authorization Code + **PKCE S256** against the Hub
  (`authority: '/oidc'`, `client_id: 'admin-ui'`, redirect `/callback`). Never
  put a client secret in the frontend.
- The CSP lives in `index.html` (`<meta http-equiv>`), `dev.js`, and the
  security headers of `oidc-admin-wasi`; change them together.

## Build, dev, and dependencies

- `npm run build` (production, minified) / `npm run build:dev` (sourcemaps) /
  `npm run build:watch`.
- `npm run dev` serves `dist/` on port 3008 with the same headers and SPA
  fallback; the full stack (API + proxy) comes from `oidc-dev start`.
- Plain CSS with custom properties for theme tokens. No preprocessors or CSS
  frameworks. New CSS files in `style/` are picked up automatically
  (sorted); `main.css` is the dev entry only.
- Runtime dependencies are only `lit-html` and `esbuild`. Upgrades go through
  `update-dependencies`; run `npm audit`.

## Tests

- Playwright specs in `e2e/*.spec.js` with shared helpers in `e2e/helpers.js`.
  They run against a running stack (`PLAYWRIGHT_BASE_URL`, default
  `http://localhost:3008`): `cargo run -p oidc-dev -- start`, then
  `npm run e2e` (or `oidc-dev e2e` / `oidc-wasm-dev e2e`).
- Cover real persistence, deep links, reloads, and permission-restricted
  views. `*-docs.spec.js` specs also produce the documentation screenshots
  (`update-project-docs`).

## Done when

- `npm run build` succeeds with no warnings.
- The new page works on a deep link and after a reload (SPA fallback).
- A Playwright spec covers the new flow.
- No new runtime dependency besides `lit-html`.
