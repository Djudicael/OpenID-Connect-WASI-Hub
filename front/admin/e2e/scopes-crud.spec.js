import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

function uniqueScopeName() {
  const suffix = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  return `e2e-scope-${suffix}`;
}

test.describe('Scopes CRUD', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('can create and delete a scope', async ({ page }) => {
    const scopeName = uniqueScopeName();
    const scopeDescription = 'Created by Playwright browser regression coverage';

    await page.goto('/scopes');
    await expect(page).toHaveURL('/scopes');

    await page.locator('c-button:has-text("Add Scope")').first().click();
    await expect(page.locator('[role="dialog"][aria-label="Create Scope"]')).toBeVisible();

    const inputs = page.locator('.field-input');
    await inputs.nth(0).fill(scopeName);
    await inputs.nth(1).fill(scopeDescription);
    await page.locator('c-modal[title="Create Scope"] >> text=Create').last().click();

    await expect(page.locator('[role="dialog"][aria-label="Create Scope"]')).toBeHidden({ timeout: 10000 });
    await expect(page.locator(`tr:has-text("${scopeName}")`)).toBeVisible({ timeout: 10000 });

    page.once('dialog', async (dialog) => {
      await dialog.accept();
    });

    await page.locator(`tr:has-text("${scopeName}")`).locator('c-button:has-text("Delete")').click();

    await expect(page.locator('text=Scope deleted')).toBeVisible({ timeout: 10000 });
    await expect(page.locator(`tr:has-text("${scopeName}")`)).toHaveCount(0, { timeout: 10000 });
  });
});
