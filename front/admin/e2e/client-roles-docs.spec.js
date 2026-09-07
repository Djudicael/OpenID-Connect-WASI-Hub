import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test('capture the client and composite roles guide', async ({ page }) => {
  test.skip(!process.env.UPDATE_DOC_SCREENSHOTS, 'Set UPDATE_DOC_SCREENSHOTS=1 to refresh documentation images');
  await page.setViewportSize({ width: 1440, height: 1000 });
  await login(page);
  await page.goto('/roles');
  await expect(page.getByRole('heading', { name: 'Roles' })).toBeVisible();

  await page.getByRole('button', { name: /Add Role/ }).first().click();
  await page.locator('#create-role-type').selectOption('client');
  await page.locator('#create-role-client').selectOption({ index: 1 });
  await page.locator('#create-role-name').fill('ticket-editor');
  await page.locator('#create-role-desc').fill('Can review and update support tickets');
  await page.screenshot({ path: '../../docs/assets/client-roles/create-client-role.png' });
  await page.getByRole('button', { name: 'Cancel' }).last().click();

  const parentId = await page.evaluate(async () => {
    const token = JSON.parse(sessionStorage.getItem('oidc_tokens')).access_token;
    const csrf = document.cookie.match(/(?:^|; )oidc_csrf_token=([^;]+)/)?.[1];
    const call = async (path, options = {}) => {
      const response = await fetch(path, { ...options, credentials: 'same-origin', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, ...(options.method && options.method !== 'GET' ? { 'X-CSRF-Token': csrf } : {}) } });
      if (!response.ok) throw new Error(`${options.method || 'GET'} ${path}: ${response.status}`);
      return response.json();
    };
    const realmId = (await call('/api/realms?limit=1')).items[0].id;
    const clientId = (await call(`/api/clients?realm_id=${realmId}&limit=1`)).items[0].id;
    const current = await call(`/api/roles?realm_id=${realmId}&limit=1000`);
    for (const item of current.items.filter(role => ['support-staff', 'ticket-editor'].includes(role.name))) await call(`/api/roles/${item.id}`, { method: 'DELETE' });
    const child = await call('/api/roles', { method: 'POST', body: JSON.stringify({ realm_id: realmId, client_id: clientId, name: 'ticket-editor', description: 'Can review and update support tickets', permissions: ['tickets:write'] }) });
    const parent = await call('/api/roles', { method: 'POST', body: JSON.stringify({ realm_id: realmId, name: 'support-staff', description: 'Support team access', permissions: [] }) });
    await call(`/api/roles/${parent.id}/composites`, { method: 'POST', body: JSON.stringify({ role_id: child.id }) });
    return parent.id;
  });

  await page.goto(`/roles/${parentId}`);
  await expect(page.getByRole('heading', { name: 'Composite roles' })).toBeVisible();
  await expect(page.getByText('ticket-editor', { exact: true })).toBeVisible();
  await page.screenshot({ path: '../../docs/assets/client-roles/composite-role.png' });
});
