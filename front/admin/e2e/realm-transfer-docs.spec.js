import { test, expect } from '@playwright/test';

test('capture realm import and export guide', async ({ page }) => {
  test.skip(!process.env.UPDATE_DOC_SCREENSHOTS, 'Set UPDATE_DOC_SCREENSHOTS=1 to refresh documentation images');
  await page.setViewportSize({ width: 1440, height: 950 });
  await page.addInitScript(() => {
    const payload = btoa(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600 })).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
    sessionStorage.setItem('oidc_tokens', JSON.stringify({ access_token: `x.${payload}.x`, id_token: `x.${payload}.x`, expires_at: Date.now() + 3600000, administration_access: true }));
  });
  await page.route('**/api/realms*', route => route.fulfill({ json: {
    items: [{ id: '018f0000-0000-7000-8000-000000000001', name: 'acme', display_name: 'Acme Production', enabled: true }],
    total: 1,
  } }));
  await page.goto('/realms');
  await expect(page.getByText('Acme Production')).toBeVisible();
  await page.waitForTimeout(500);
  await page.screenshot({ path: '../../docs/assets/realm-transfer/realms.png' });

  await page.getByRole('button', { name: 'Export', exact: true }).click();
  await expect(page.getByText('The archive includes users')).toBeVisible();
  await page.screenshot({ path: '../../docs/assets/realm-transfer/export-realm.png' });
  await page.keyboard.press('Escape');

  await page.getByRole('button', { name: 'Import Realm', exact: true }).click();
  await expect(page.getByText('Replace a realm with the same name or ID')).toBeVisible();
  await page.screenshot({ path: '../../docs/assets/realm-transfer/import-realm.png' });
});
