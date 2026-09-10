import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test('capture the CIBA guide', async ({ page }) => {
  test.skip(!process.env.UPDATE_DOC_SCREENSHOTS, 'Set UPDATE_DOC_SCREENSHOTS=1 to refresh documentation images');
  await page.setViewportSize({ width: 1440, height: 1000 });
  await login(page);
  const client = await page.evaluate(async () => {
    const token = JSON.parse(sessionStorage.getItem('oidc_tokens')).access_token;
    const response = await fetch('/api/clients?search=test-service&limit=20', { headers: { Authorization: `Bearer ${token}` } });
    return (await response.json()).items.find(item => item.client_id === 'test-service');
  });
  expect(client).toBeTruthy();
  await page.evaluate(async id => {
    const token = JSON.parse(sessionStorage.getItem('oidc_tokens')).access_token;
    const csrf = document.cookie.match(/(?:^|; )oidc_csrf_token=([^;]+)/)?.[1];
    const response = await fetch(`/api/clients/${id}/ciba`, { method: 'PUT', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: JSON.stringify({ enabled: true, delivery_mode: 'poll', request_lifetime_seconds: 300, polling_interval_seconds: 5 }) });
    if (!response.ok) throw new Error(`Could not enable CIBA: ${response.status}`);
  }, client.id);
  await page.goto(`/clients/${client.id}`);
  await expect(page.getByText('Backchannel authentication (CIBA)')).toBeVisible();
  await page.locator('[data-doc-section="ciba-settings"]').screenshot({ path: '../../docs/assets/ciba/client-settings.png' });

  await page.evaluate(async () => {
    const body = new URLSearchParams({ login_hint: 'admin@example.com', scope: 'openid profile', binding_message: '4821', request_context: 'Approve the desktop sign-in' });
    const response = await fetch('/realms/master/protocol/openid-connect/ext/ciba/auth', { method: 'POST', headers: { Authorization: `Basic ${btoa('test-service:test-service-secret')}`, 'Content-Type': 'application/x-www-form-urlencoded' }, body });
    if (!response.ok) throw new Error(`Could not create CIBA request: ${response.status}`);
  });
  await page.goto('/account');
  await page.getByRole('button', { name: /Sign-in requests/ }).click();
  await expect(page.getByText('Verification message:')).toBeVisible();
  await page.locator('[data-doc-section="ciba-requests"]').screenshot({ path: '../../docs/assets/ciba/account-approval.png' });
});
