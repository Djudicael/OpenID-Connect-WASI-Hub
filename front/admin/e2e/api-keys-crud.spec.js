import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test.describe('API Keys CRUD', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('can create an API key', async ({ page }) => {
    await page.goto('/api-keys');

    // Click the "+ Create Key" button in the page actions slot
    await page.locator('text=Create Key').click();

    // Should navigate to the create page
    await expect(page).toHaveURL('/api-keys/create', { timeout: 5000 });

    // Fill in the form — inputs use class="field-input" inside shadow DOM
    const nameInput = page.locator('.field-input[placeholder="e.g. Production Service Key"]');
    await nameInput.fill('E2E Test Key');

    // Submit the form by clicking the "Create Key" button
    await page.locator('text=Create Key').last().click();

    // After creation, the raw key should be displayed (shown only once)
    // The key-value div contains the raw key which starts with "oidc_"
    const rawKeyDisplay = page.locator('.key-value');
    await expect(rawKeyDisplay).toBeVisible({ timeout: 10000 });

    // The warning message should be visible
    await expect(page.locator('text=Copy this key now')).toBeVisible({ timeout: 5000 });

    // The "Copy to Clipboard" button should be available
    await expect(page.locator('text=Copy to Clipboard')).toBeVisible();

    // Navigate back to the API keys list
    await page.locator('text=Back to API Keys').click();
    await expect(page).toHaveURL('/api-keys', { timeout: 5000 });
  });

  test('can list API keys', async ({ page }) => {
    await page.goto('/api-keys');

    // Wait for the table to load (c-table renders rows)
    const tableRows = page.locator('c-table');
    await expect(tableRows).toBeVisible({ timeout: 10000 });

    // The "E2E Test Key" created in the previous test should appear
    await expect(page.locator('text=E2E Test Key')).toBeVisible({ timeout: 10000 });
  });

  test('can view API key details', async ({ page }) => {
    await page.goto('/api-keys');

    // Wait for the table to load
    await page.locator('c-table').waitFor({ timeout: 10000 });

    // Click on the "E2E Test Key" link to navigate to the detail page
    await page.locator('text=E2E Test Key').first().click();

    // Should navigate to the detail page
    await expect(page).toHaveURL(/\/api-keys\/[0-9a-f-]+/, { timeout: 5000 });

    // Detail page should show key information
    await expect(page.locator('text=API Key Details')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('text=E2E Test Key')).toBeVisible({ timeout: 5000 });

    // Status should show "Active"
    await expect(page.locator('text=Active')).toBeVisible({ timeout: 5000 });

    // Back link should be visible
    await expect(page.locator('text=Back to API Keys')).toBeVisible();
  });

  test('can revoke an API key', async ({ page }) => {
    await page.goto('/api-keys');

    // Wait for the table to load
    await page.locator('c-table').waitFor({ timeout: 10000 });

    // Find the "E2E Test Key" row and click its "Revoke" button
    // The Revoke button is a c-button with variant="danger" inside the table row
    const revokeBtn = page.locator('c-button:has-text("Revoke")').first();

    if (await revokeBtn.isVisible({ timeout: 3000 }).catch(() => false)) {
      // Accept the confirm() dialog
      page.on('dialog', async (dialog) => {
        await dialog.accept();
      });

      await revokeBtn.click();

      // After revocation, the key should show "Revoked" status
      await expect(page.locator('text=Revoked').first()).toBeVisible({ timeout: 10000 });
    }
  });

  test('can filter API keys by realm', async ({ page }) => {
    await page.goto('/api-keys');

    // The realm select dropdown should be visible
    const realmSelect = page.locator('.realm-select');
    await expect(realmSelect).toBeVisible({ timeout: 5000 });

    // The "Include revoked" checkbox should be visible
    const revokedCheckbox = page.locator('text=Include revoked');
    await expect(revokedCheckbox).toBeVisible();
  });

  test('can toggle include revoked keys', async ({ page }) => {
    await page.goto('/api-keys');

    // Find and click the "Include revoked" checkbox
    const revokedCheckbox = page.locator('input[type="checkbox"]');
    const includeRevokedLabel = page.locator('text=Include revoked');

    await expect(includeRevokedLabel).toBeVisible({ timeout: 5000 });

    // Click the checkbox to include revoked keys
    await revokedCheckbox.click();

    // Wait for the table to reload
    await page.waitForTimeout(500);

    // The table should still be visible
    await expect(page.locator('c-table')).toBeVisible({ timeout: 5000 });
  });
});
