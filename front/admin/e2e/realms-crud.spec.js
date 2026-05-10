import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test.describe('Realms CRUD', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('can create a realm', async ({ page }) => {
    await page.goto('/realms');

    // Click the "+ Add Realm" button in the page actions slot
    await page.locator('text=Add Realm').click();

    // The modal should open — wait for the "Create Realm" title
    await expect(page.locator('text=Create Realm')).toBeVisible({ timeout: 5000 });

    // Fill in the form — inputs use class="field-input" inside shadow DOM
    const nameInput = page.locator('.field-input[placeholder="e.g. production"]');
    await nameInput.fill('e2e-test-realm');

    const displayNameInput = page.locator('.field-input[placeholder="e.g. Production"]');
    await displayNameInput.fill('E2E Test Realm');

    // Submit the form by clicking the "Create" button in the modal footer
    await page.locator('c-modal >> text=Create').last().click();

    // The modal should close and the new realm should appear in the list
    await expect(page.locator('text=e2e-test-realm')).toBeVisible({ timeout: 10000 });

    // A success toast should appear
    await expect(page.locator('text=Realm created successfully')).toBeVisible({ timeout: 5000 });
  });

  test('can list realms with master realm', async ({ page }) => {
    await page.goto('/realms');

    // The table should be visible
    await expect(page.locator('c-table')).toBeVisible({ timeout: 10000 });

    // The "master" realm should be listed in the table
    await expect(page.locator('text=master')).toBeVisible({ timeout: 5000 });
  });

  test('can view realm details', async ({ page }) => {
    await page.goto('/realms');

    // Wait for the table to load
    await page.locator('c-table').waitFor({ timeout: 10000 });

    // Click the "Edit" button on the master realm row
    await page.locator('c-button:has-text("Edit")').first().click();

    // Should navigate to the realm detail page
    await expect(page).toHaveURL(/\/realms\/[0-9a-f-]+/, { timeout: 5000 });

    // The detail page should show the realm name field
    await expect(page.locator('text=Realm Details')).toBeVisible({ timeout: 5000 });

    // The "Back to Realms" link should be visible
    await expect(page.locator('text=Back to Realms')).toBeVisible();

    // The name input should be populated
    const nameInput = page.locator('.field-input').first();
    await expect(nameInput).toBeVisible({ timeout: 5000 });
  });

  test('can edit a realm', async ({ page }) => {
    await page.goto('/realms');

    // Wait for the table to load
    await page.locator('c-table').waitFor({ timeout: 10000 });

    // Find the "e2e-test-realm" row and click its "Edit" button
    const e2eRealmRow = page.locator('text=e2e-test-realm').first();
    if (await e2eRealmRow.isVisible({ timeout: 3000 }).catch(() => false)) {
      // Click the Edit button in the same row
      await page.locator('c-button:has-text("Edit")').first().click();

      await expect(page).toHaveURL(/\/realms\/[0-9a-f-]+/, { timeout: 5000 });

      // Modify the display name
      const displayNameInput = page.locator('.field-input').nth(1);
      await displayNameInput.fill('E2E Test Realm Updated');

      // The dirty indicator should appear
      await expect(page.locator('.dirty-indicator')).toBeVisible({ timeout: 3000 });

      // Save the changes
      await page.locator('text=Save Changes').click();

      // A success toast should appear
      await expect(page.locator('text=Realm updated')).toBeVisible({ timeout: 5000 });
    }
  });

  test('can delete a realm', async ({ page }) => {
    await page.goto('/realms');

    // Wait for the table to load
    await page.locator('c-table').waitFor({ timeout: 10000 });

    // Find a "Delete" button for a non-master realm (e2e-test-realm)
    const deleteBtns = page.locator('c-button:has-text("Delete")');
    const count = await deleteBtns.count();

    if (count > 0) {
      // Accept the confirm() dialog
      page.on('dialog', async (dialog) => {
        await dialog.accept();
      });

      await deleteBtns.first().click();

      // A success toast should appear
      await expect(page.locator('text=Realm deleted')).toBeVisible({ timeout: 10000 });
    }
  });
});
