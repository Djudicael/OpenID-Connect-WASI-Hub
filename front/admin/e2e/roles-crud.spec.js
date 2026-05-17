import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

function uniqueRoleName() {
  const suffix = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  return `e2e-role-${suffix}`;
}

test.describe('Roles CRUD', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('can create, filter, bulk-select, and delete a role', async ({ page }) => {
    const roleName = uniqueRoleName();
    const roleDescription = 'Created by Playwright browser regression coverage';

    await page.goto('/roles');
    await expect(page).toHaveURL('/roles');

    await page.locator('c-button:has-text("Add Role")').first().click();
    await expect(page.locator('[role="dialog"][aria-label="Create Role"]')).toBeVisible();

    await page.locator('#create-role-name').fill(roleName);
    await page.locator('#create-role-desc').fill(roleDescription);
    await page.locator('#create-role-perms').fill('users:read, users:write');
    await page.locator('c-modal[title="Create Role"] >> text=Create').last().click();

    await expect(page.locator('[role="dialog"][aria-label="Create Role"]')).toBeHidden({ timeout: 10000 });
    await expect(page.locator(`tr:has-text("${roleName}")`)).toBeVisible({ timeout: 10000 });

    const searchInput = page.locator('.search-input[placeholder="Search roles..."]');
    await searchInput.fill(roleName);
    await expect(page.locator(`tr:has-text("${roleName}")`)).toBeVisible({ timeout: 10000 });

    await page.getByLabel(`Select role ${roleName}`).check();
    await expect(page.locator('.bulk-bar')).toContainText('1 selected');

    await page.locator('c-button:has-text("Delete Selected")').click();

    const confirmDialog = page.locator('[role="dialog"][aria-label="Bulk Delete"]');
    await expect(confirmDialog).toBeVisible();
    await page.locator('c-modal[title="Bulk Delete"] >> text=Confirm').last().click();

    await expect(page.locator('text=1 role(s) deleted')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=No roles match your search')).toBeVisible({ timeout: 10000 });
  });
});
