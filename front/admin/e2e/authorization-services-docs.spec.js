import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test('capture the authorization services guide', async ({ page }) => {
  test.skip(!process.env.UPDATE_DOC_SCREENSHOTS, 'Set UPDATE_DOC_SCREENSHOTS=1 to refresh documentation images');
  await page.setViewportSize({ width: 1440, height: 1000 });
  await login(page);
  const csrfToken = '0000000000000000000000000000000000000000000000000000000000000000';
  await page.context().clearCookies({ name: 'oidc_csrf_token' });
  await page.context().addCookies([{
    name: 'oidc_csrf_token',
    value: csrfToken,
    domain: 'localhost',
    path: '/',
    secure: false,
    sameSite: 'Strict',
  }]);
  await expect.poll(() => page.evaluate(() => document.cookie)).toContain('oidc_csrf_token=');

  const token = await page.evaluate(() => JSON.parse(sessionStorage.getItem('oidc_tokens')).access_token);
  const call = async (path, options = {}) => {
    const response = await page.request.fetch(path, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
        Cookie: `oidc_csrf_token=${csrfToken}`,
        ...(options.method && options.method !== 'GET' ? { 'X-CSRF-Token': csrfToken } : {}),
      },
    });
    if (!response.ok()) throw new Error(`${options.method || 'GET'} ${path}: ${response.status()} ${await response.text()}`);
    return response.status() === 204 ? null : response.json();
  };
  const realmId = (await call('/api/realms?limit=1')).items[0].id;
  const clients = (await call(`/api/clients?realm_id=${realmId}&limit=100`)).items;
  const server = clients.find(client => client.client_id === 'admin-ui') || clients[0];
  const query = `?resource_server_id=${server.id}`;
  for (const item of (await call(`/api/authorization/permissions${query}`)).items.filter(item => item.name === 'View financial reports')) {
    await call(`/api/authorization/permissions/${item.id}`, { method: 'DELETE' });
  }
  for (const item of (await call(`/api/authorization/policies${query}`)).items.filter(item => item.name === 'Finance team')) {
    await call(`/api/authorization/policies/${item.id}`, { method: 'DELETE' });
  }
  for (const item of (await call(`/api/authorization/resources${query}`)).items.filter(item => item.name === 'quarterly-report')) {
    await call(`/api/authorization/resources/${item.id}`, { method: 'DELETE' });
  }
  const resource = await call('/api/authorization/resources', {
    method: 'POST',
    data: { resource_server_id: server.id, name: 'quarterly-report', display_name: 'Quarterly financial report', resource_type: 'document', owner_id: null, uris: ['/reports/quarterly'], scopes: ['view', 'edit'], attributes: { classification: 'internal', department: 'finance' }, icon_uri: null },
  });
  const policy = await call('/api/authorization/policies', {
    method: 'POST',
    data: { resource_server_id: server.id, name: 'Finance team', description: 'Allows members of the finance group', policy_type: 'group', logic: 'positive', config: { groups: ['finance'] } },
  });
  const permission = await call('/api/authorization/permissions', {
    method: 'POST',
    data: { resource_server_id: server.id, name: 'View financial reports', description: 'Grants read access to quarterly reports', resources: [resource.id], scopes: ['view'], policies: [policy.id], decision_strategy: 'unanimous' },
  });
  const sample = { serverId: server.id, resourceId: resource.id, policyId: policy.id, permissionId: permission.id };

  await page.goto('/authorization-services');
  await expect(page.getByRole('heading', { name: 'Authorization Services' })).toBeVisible();
  await page.getByLabel('Resource server:').selectOption(sample.serverId);
  await expect(page.getByText('quarterly-report', { exact: true })).toBeVisible();
  const section = page.locator('[data-doc-section="authorization-services"]');
  await section.screenshot({ path: '../../docs/assets/authorization-services/resources.png' });

  await page.getByRole('button', { name: 'Policies', exact: true }).click();
  await expect(page.getByText('Finance team', { exact: true })).toBeVisible();
  await section.screenshot({ path: '../../docs/assets/authorization-services/policies.png' });

  await page.getByRole('button', { name: 'Permissions', exact: true }).click();
  await expect(page.getByText('View financial reports', { exact: true })).toBeVisible();
  await section.screenshot({ path: '../../docs/assets/authorization-services/permissions.png' });
});
