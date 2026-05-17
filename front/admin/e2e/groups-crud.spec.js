import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

function uniqueGroupName() {
  const suffix = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  return `e2e-group-${suffix}`;
}

test.describe('Groups CRUD', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('can create, filter, bulk-select, and delete a group', async ({ page }) => {
    const groupName = uniqueGroupName();
    const groupDescription = 'Created by Playwright browser regression coverage';

    await page.goto('/groups');
    await expect(page).toHaveURL('/groups');

    await page.locator('c-button:has-text("Add Group")').first().click();
    await expect(page.locator('[role="dialog"][aria-label="Create Group"]')).toBeVisible();

    await page.locator('#create-group-name').fill(groupName);
    await page.locator('#create-group-desc').fill(groupDescription);
    await page.locator('c-modal[title="Create Group"] >> text=Create').last().click();

    await expect(page.locator('[role="dialog"][aria-label="Create Group"]')).toBeHidden({ timeout: 10000 });
    await expect(page.locator(`tr:has-text("${groupName}")`)).toBeVisible({ timeout: 10000 });

    const searchInput = page.locator('.search-input[placeholder="Search groups..."]');
    await searchInput.fill(groupName);
    await expect(page.locator(`tr:has-text("${groupName}")`)).toBeVisible({ timeout: 10000 });

    await page.getByLabel(`Select group ${groupName}`).check();
    await expect(page.locator('.bulk-bar')).toContainText('1 selected');

    await page.locator('c-button:has-text("Delete Selected")').click();

    const confirmDialog = page.locator('[role="dialog"][aria-label="Bulk Delete"]');
    await expect(confirmDialog).toBeVisible();
    await page.locator('c-modal[title="Bulk Delete"] >> text=Confirm').last().click();

    await expect(page.locator('text=1 group(s) deleted')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=No groups match your search')).toBeVisible({ timeout: 10000 });
  });
});
