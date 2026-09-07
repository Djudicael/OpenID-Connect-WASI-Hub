import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test('capture the offline access guide', async ({ page }) => {
  test.skip(!process.env.UPDATE_DOC_SCREENSHOTS, 'Set UPDATE_DOC_SCREENSHOTS=1 to refresh documentation images');
  await page.setViewportSize({ width: 1440, height: 1100 });
  await login(page);

  await page.goto('/realms');
  await page.getByRole('button', { name: 'Edit' }).first().click();
  await expect(page.getByRole('heading', { name: 'Offline access' })).toBeVisible();
  await page.locator('[data-doc-section="offline-sessions"]').screenshot({
    path: '../../docs/assets/offline-access/realm-policy.png',
  });

  const originalScopes = await page.evaluate(async () => {
    const token = JSON.parse(sessionStorage.getItem('oidc_tokens')).access_token;
    const clients = await fetch('/api/clients?limit=100', {
      headers: { Authorization: `Bearer ${token}` },
    }).then(response => response.json());
    const client = clients.items.find(item => item.client_id === 'admin-ui');
    const csrf = document.cookie.match(/(?:^|; )oidc_csrf_token=([^;]+)/)?.[1];
    const scopes = [...new Set([...(client.allowed_scopes || []), 'offline_access'])];
    const response = await fetch(`/api/clients/${client.id}`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrf,
      },
      body: JSON.stringify({ allowed_scopes: scopes }),
    });
    if (!response.ok) throw new Error(`Could not enable offline_access: ${response.status}`);
    return { id: client.id, scopes: client.allowed_scopes || [] };
  });

  await page.evaluate(async () => {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    const verifier = btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
    const challenge = btoa(String.fromCharCode(...digest)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
    const state = 'offline-doc-state';
    sessionStorage.setItem('oidc_state', state);
    sessionStorage.setItem('oidc_code_verifier', verifier);
    const url = new URL('/oidc/authorize', location.origin);
    url.searchParams.set('client_id', 'admin-ui');
    url.searchParams.set('redirect_uri', `${location.origin}/callback`);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'openid profile email admin offline_access');
    url.searchParams.set('prompt', 'consent');
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', challenge);
    url.searchParams.set('code_challenge_method', 'S256');
    location.href = url.toString();
  });
  await expect(page.getByRole('heading', { name: /access/i })).toBeVisible();
  await page.getByRole('button', { name: 'Allow' }).click();
  await page.waitForURL(url => url.pathname === '/', { timeout: 15000 });

  await page.goto('/account');
  await page.getByRole('button', { name: 'Offline access', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Offline access' })).toBeVisible();
  await expect(page.getByText('Admin UI', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Revoke access' })).toBeEnabled();
  await page.locator('[data-doc-section="offline-access"]').screenshot({
    path: '../../docs/assets/offline-access/account-grants.png',
  });

  await page.evaluate(async ({ id, scopes }) => {
    const token = JSON.parse(sessionStorage.getItem('oidc_tokens')).access_token;
    const csrf = document.cookie.match(/(?:^|; )oidc_csrf_token=([^;]+)/)?.[1];
    await fetch(`/api/clients/${id}`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrf,
      },
      body: JSON.stringify({ allowed_scopes: scopes }),
    });
  }, originalScopes);
});
