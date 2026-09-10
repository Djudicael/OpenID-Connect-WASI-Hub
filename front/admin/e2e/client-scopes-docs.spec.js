import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test('capture the client scopes and protocol mappers guide', async ({ page }) => {
  test.skip(!process.env.UPDATE_DOC_SCREENSHOTS, 'Set UPDATE_DOC_SCREENSHOTS=1 to refresh documentation images');
  await page.setViewportSize({ width: 1440, height: 1100 });
  await login(page);

  const scopeId = await page.evaluate(async () => {
    const token = JSON.parse(sessionStorage.getItem('oidc_tokens')).access_token;
    let csrf;
    const call = async (path, options = {}) => {
      const response = await fetch(path, { ...options, credentials: 'same-origin', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, ...(options.method && options.method !== 'GET' ? { 'X-CSRF-Token': csrf } : {}) } });
      if (!response.ok) throw new Error(`${options.method || 'GET'} ${path}: ${response.status}`);
      return response.json();
    };
    const realm = (await call('/api/realms?limit=1')).items[0];
    csrf = document.cookie.match(/(?:^|; )oidc_csrf_token=([^;]+)/)?.[1];
    const client = (await call(`/api/clients?realm_id=${realm.id}&limit=1`)).items[0];
    const current = await call(`/api/scopes?realm_id=${realm.id}`);
    for (const item of current.items.filter(scope => scope.name === 'workforce-profile')) await call(`/api/scopes/${item.id}`, { method: 'DELETE' });
    const scope = await call('/api/scopes', { method: 'POST', body: JSON.stringify({ realm_id: realm.id, name: 'workforce-profile', description: 'Claims shared by workforce applications', enabled: true }) });
    await call(`/api/clients/${client.id}/scopes`, { method: 'POST', body: JSON.stringify({ scope_id: scope.id, assignment_type: 'default' }) });
    for (const mapper of [
      { name: 'Department', mapper_type: 'user_attribute', claim_name: 'employee.department', source: 'department', add_to_access_token: true, add_to_id_token: true, add_to_userinfo: true },
      { name: 'Tenant tier', mapper_type: 'hardcoded_claim', claim_name: 'tenant.tier', claim_value: 'gold', add_to_access_token: true, add_to_id_token: true, add_to_userinfo: true },
      { name: 'Workforce API audience', mapper_type: 'audience', claim_value: 'workforce-api', add_to_access_token: true, add_to_id_token: false, add_to_userinfo: false },
    ]) await call(`/api/scopes/${scope.id}/mappers`, { method: 'POST', body: JSON.stringify(mapper) });
    return scope.id;
  });

  await page.goto(`/scopes/${scopeId}`);
  await expect(page.getByRole('heading', { name: 'Protocol mappers' })).toBeVisible();
  await expect(page.getByText('Department', { exact: true })).toBeVisible();
  await page.screenshot({ path: '../../docs/assets/client-scopes/scope-overview.png', fullPage: true });

  await page.getByRole('button', { name: /Add mapper/ }).click();
  const modal = page.locator('c-modal');
  const inputs = modal.locator('input.field-input');
  await inputs.nth(0).fill('Cost center');
  await modal.locator('select').selectOption('user_attribute');
  await inputs.nth(1).fill('employee.cost_center');
  await inputs.nth(2).fill('employment.cost_center');
  await page.screenshot({ path: '../../docs/assets/client-scopes/create-mapper.png' });
});
