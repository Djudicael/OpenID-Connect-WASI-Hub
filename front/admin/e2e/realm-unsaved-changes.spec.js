import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test.describe('Realm unsaved changes', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('prompts before leaving dirty realm details and only navigates after confirmation', async ({ page }) => {
    await page.goto('/realms');
    await expect(page.locator('c-table')).toBeVisible({ timeout: 10000 });

    const masterRealmRow = page.locator('tr:has-text("master")').first();
    await expect(masterRealmRow).toBeVisible({ timeout: 10000 });
    await masterRealmRow.locator('c-button:has-text("Edit")').click();

    await expect(page).toHaveURL(/\/realms\/[0-9a-f-]+/, { timeout: 10000 });
    await expect(page.locator('text=Realm Details')).toBeVisible();

    const displayNameInput = page.locator('.field-input').nth(1);
    const dirtyDisplayName = `Master Realm ${Date.now()}`;
    await displayNameInput.fill(dirtyDisplayName);
    await expect(page.locator('.dirty-indicator')).toBeVisible({ timeout: 5000 });

    let dismissedMessage = '';
    page.once('dialog', async (dialog) => {
      dismissedMessage = dialog.message();
      await dialog.dismiss();
    });

    await page.locator('text=Back to Realms').click();

    await expect.poll(() => dismissedMessage).toContain('unsaved changes');
    await expect(page).toHaveURL(/\/realms\/[0-9a-f-]+/);
    await expect(page.locator('.dirty-indicator')).toBeVisible();
    await expect(displayNameInput).toHaveValue(dirtyDisplayName);

    let acceptedMessage = '';
    page.once('dialog', async (dialog) => {
      acceptedMessage = dialog.message();
      await dialog.accept();
    });

    await page.locator('text=Back to Realms').click();

    await expect.poll(() => acceptedMessage).toContain('unsaved changes');
    await expect(page).toHaveURL('/realms', { timeout: 10000 });
    await expect(page.locator('text=Create Realm')).not.toBeVisible();
    await expect(page.locator('text=master')).toBeVisible({ timeout: 10000 });
  });
});
