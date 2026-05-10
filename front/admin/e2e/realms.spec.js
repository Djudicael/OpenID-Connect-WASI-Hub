import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test.describe('Realms page', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('can navigate to realms page', async ({ page }) => {
    // Click the "Realms" link in the sidebar
    await page.locator('.sidebar-nav >> text=Realms').click();

    // URL should be /realms
    await expect(page).toHaveURL('/realms');

    // Page heading should contain "Realms"
    const heading = page.locator('text=Realms');
    await expect(heading).toBeVisible();
  });

  test('shows master realm', async ({ page }) => {
    // Navigate directly to the realms page
    await page.goto('/realms');

    // The "master" realm should be listed in the table
    const masterRealm = page.locator('text=master');
    await expect(masterRealm).toBeVisible({ timeout: 10000 });
  });
});
