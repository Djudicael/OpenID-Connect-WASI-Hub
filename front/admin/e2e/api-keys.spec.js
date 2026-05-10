import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test.describe('API Keys page', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('can navigate to API keys page', async ({ page }) => {
    // Click the "API Keys" link in the sidebar
    await page.locator('.sidebar-nav >> text=API Keys').click();

    // URL should be /api-keys
    await expect(page).toHaveURL('/api-keys');

    // Page heading should contain "API Keys"
    const heading = page.locator('text=API Keys');
    await expect(heading).toBeVisible();
  });

  test('shows create API key button', async ({ page }) => {
    // Navigate directly to the API keys page
    await page.goto('/api-keys');

    // The "+ Create Key" button should be visible
    const createBtn = page.locator('text=Create Key');
    await expect(createBtn).toBeVisible();
  });
});
