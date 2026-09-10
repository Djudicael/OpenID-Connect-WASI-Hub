import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test('capture the organization administration guide', async ({ page }) => {
  test.skip(!process.env.UPDATE_DOC_SCREENSHOTS, 'Set UPDATE_DOC_SCREENSHOTS=1 to refresh documentation images');
  await page.setViewportSize({ width: 1440, height: 1000 });
  await login(page);
  await page.goto('/organizations');
  await expect(page.getByText('Loading...')).toBeHidden();
  if (!(await page.getByText('Acme Corporation').isVisible())) {
    await page.getByRole('button', { name: '+ Add Organization' }).click();
    await page.locator('#organization-name').fill('Acme Corporation');
    await page.locator('#organization-alias').fill('acme');
    await page.getByRole('button', { name: 'Create', exact: true }).click();
  }
  await expect(page.getByText('Acme Corporation')).toBeVisible();
  await page.keyboard.press('Escape');
  await page.getByRole('button', { name: 'Manage' }).click({ force: true });
  await expect(page.getByRole('heading', { name: 'Organization Details' })).toBeVisible();
  await page.reload();
  await page.getByPlaceholder('https://app.example.com/welcome').fill('https://app.example.test/welcome');
  await page.locator('textarea').first().fill('{"plan":"enterprise","region":"eu-west"}');
  await page.getByPlaceholder('plan, region').fill('plan, region');
  await page.getByRole('button', { name: 'Save Changes' }).click();
  await expect(page.getByRole('button', { name: 'Save Changes' })).toBeEnabled();
  await page.reload();
  await page.waitForTimeout(500);
  await expect(page.getByText(/server error|duplicate key/i)).toHaveCount(0);
  await page.screenshot({ path: '../../docs/assets/organizations/organization-settings-and-domains.png' });

  if (!(await page.getByText('(unverified)').isVisible())) {
    await page.getByPlaceholder('example.com', { exact: true }).fill('example.test');
    await page.getByRole('button', { name: 'Add Domain' }).click();
  }
  await expect(page.getByText('(unverified)')).toBeVisible();
  // The DNS proof is intentionally omitted from documentation images.
  const dnsProof = page.locator('.empty-state').filter({ hasText: 'Add this DNS TXT record' });
  if (await dnsProof.isVisible()) await dnsProof.evaluate((element) => { element.hidden = true; });
  await page.locator('.section').nth(3).scrollIntoViewIfNeeded();
  await expect(page.getByText(/server error|duplicate key/i)).toHaveCount(0);
  await page.screenshot({ path: '../../docs/assets/organizations/organization-members-and-access.png' });
});
