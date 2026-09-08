import { test, expect } from '@playwright/test';

test('capture SAML administration guide', async ({ page }) => {
  test.skip(!process.env.UPDATE_DOC_SCREENSHOTS, 'Set UPDATE_DOC_SCREENSHOTS=1 to refresh documentation images');
  await page.setViewportSize({ width: 1440, height: 950 });
  await page.addInitScript(() => {
    const payload = btoa(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600 })).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
    sessionStorage.setItem('oidc_tokens', JSON.stringify({ access_token: `x.${payload}.x`, id_token: `x.${payload}.x`, expires_at: Date.now() + 3600000, administration_access: true }));
  });
  await page.route('**/api/realms*', route => route.fulfill({ json: { items: [{ id: '018f0000-0000-7000-8000-000000000001', name: 'acme', display_name: 'Acme' }] } }));
  await page.route('**/api/saml/clients*', route => route.fulfill({ json: { items: [{ id: '018f0000-0000-7000-8000-000000000002', realm_id: '018f0000-0000-7000-8000-000000000001', name: 'Acme expenses', entity_id: 'https://expenses.example.test/saml/metadata', enabled: true, sign_assertions: true }] } }));
  await page.goto('/saml-clients');
  await expect(page.getByText('Acme expenses')).toBeVisible();
  await page.waitForTimeout(500);
  await page.screenshot({ path: '../../docs/assets/saml/saml-clients.png' });
  await page.getByRole('button', { name: '+ Add SAML Client' }).click();
  await expect(page.getByText('Service provider metadata XML')).toBeVisible();
  await page.screenshot({ path: '../../docs/assets/saml/add-saml-client.png' });
});
