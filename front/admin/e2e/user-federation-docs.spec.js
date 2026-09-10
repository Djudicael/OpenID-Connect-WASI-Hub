import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test('capture the user federation guide', async ({ page }) => {
  test.skip(!process.env.UPDATE_DOC_SCREENSHOTS, 'Set UPDATE_DOC_SCREENSHOTS=1 to refresh documentation images');
  await page.setViewportSize({ width: 1440, height: 900 });
  await login(page);
  const csrfToken = '0000000000000000000000000000000000000000000000000000000000000000';
  await page.context().clearCookies({ name: 'oidc_csrf_token' });
  await page.context().addCookies([{ name: 'oidc_csrf_token', value: csrfToken, domain: 'localhost', path: '/', secure: false, sameSite: 'Strict' }]);
  const token = await page.evaluate(() => JSON.parse(sessionStorage.getItem('oidc_tokens')).access_token);
  const call = async (path, options = {}) => {
    const response = await page.request.fetch(path, { ...options, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, Cookie: `oidc_csrf_token=${csrfToken}`, ...(options.method && options.method !== 'GET' ? { 'X-CSRF-Token': csrfToken } : {}) } });
    if (!response.ok()) throw new Error(`${options.method || 'GET'} ${path}: ${response.status()} ${await response.text()}`);
    return response.json();
  };
  const realmId = (await call('/api/realms?limit=1')).items[0].id;
  const existing = (await call(`/api/user-federation?realm_id=${realmId}`)).items;
  for (const provider of existing.filter(item => ['Corporate LDAP', 'Company Active Directory', 'Desktop SSO'].includes(item.name))) {
    await call(`/api/user-federation/${provider.id}`, { method: 'DELETE' });
  }
  const samples = [
    ['Corporate LDAP', 'ldap', 10, 'ldaps://ldap.example.com:636', { bind_dn: 'cn=oidc-service,ou=service,dc=example,dc=com', base_dn: 'ou=people,dc=example,dc=com', user_filter: '(uid={identifier})' }],
    ['Company Active Directory', 'active_directory', 20, 'ldaps://ad.example.com:636', { bind_dn: 'CN=OIDC Service,OU=Service Accounts,DC=example,DC=com', base_dn: 'dc=example,dc=com', user_filter: '(|(userPrincipalName={identifier})(sAMAccountName={identifier}))' }],
    ['Desktop SSO', 'kerberos', 30, 'https://federation.example.com', { connection: 'company-ad', service_principal: 'HTTP/login.example.com@EXAMPLE.COM' }],
  ];
  for (const [name, provider_type, priority, gateway_url, config] of samples) {
    await call('/api/user-federation', { method: 'POST', data: { realm_id: realmId, name, provider_type, priority, gateway_url, gateway_secret: 'documentation-placeholder-secret', config, enabled: true, import_users: true, sync_groups: true } });
  }
  await page.goto('/user-federation');
  await expect(page.getByRole('heading', { name: 'User Federation' })).toBeVisible();
  await expect(page.getByText('Corporate LDAP', { exact: true })).toBeVisible();
  await expect(page.getByText('Company Active Directory', { exact: true })).toBeVisible();
  await expect(page.getByText('Desktop SSO', { exact: true })).toBeVisible();
  await page.locator('[data-doc-section="user-federation"]').screenshot({ path: '../../docs/assets/user-federation/providers.png' });
});
