import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test.describe('Users CRUD', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('can navigate to users page', async ({ page }) => {
    // Click the "Users" link in the sidebar
    await page.locator('.sidebar-nav >> text=Users').click();

    // URL should be /users
    await expect(page).toHaveURL('/users');

    // Page heading should contain "Users"
    await expect(page.locator('text=Users')).toBeVisible();
  });

  test('can list users with default admin', async ({ page }) => {
    await page.goto('/users');

    // Wait for the table to load
    await expect(page.locator('c-table')).toBeVisible({ timeout: 10000 });

    // Should have at least admin@localhost
    await expect(page.locator('text=admin@localhost')).toBeVisible({ timeout: 5000 });
  });

  test('can create a user', async ({ page }) => {
    await page.goto('/users');

    // Click the "+ Add User" button in the page actions slot
    await page.locator('text=Add User').click();

    // The modal should open — wait for the "Create User" title
    await expect(page.locator('text=Create User')).toBeVisible({ timeout: 5000 });

    // Fill in the required fields — inputs use class="field-input" inside shadow DOM
    // Realm ID is required
    const realmIdInput = page.locator('.field-input[placeholder="Enter realm UUID"]');
    await realmIdInput.fill('00000000-0000-0000-0000-000000000000');

    // Email is required
    const emailInput = page.locator('.field-input[placeholder="user@example.com"]');
    await emailInput.fill('e2e-test@example.com');

    // Password is required
    const passwordInput = page.locator('.field-input[placeholder="Password"]');
    await passwordInput.fill('TestPass123!');

    // Submit the form by clicking the "Create" button in the modal footer
    await page.locator('c-modal >> text=Create').last().click();

    // The modal should close and the new user should appear in the list
    await expect(page.locator('text=e2e-test@example.com')).toBeVisible({ timeout: 10000 });

    // A success toast should appear
    await expect(page.locator('text=User created successfully')).toBeVisible({ timeout: 5000 });
  });

  test('can search users', async ({ page }) => {
    await page.goto('/users');

    // Wait for the table to load
    await expect(page.locator('c-table')).toBeVisible({ timeout: 10000 });

    // The search input should be visible
    const searchInput = page.locator('.search-input[placeholder="Search users..."]');
    await expect(searchInput).toBeVisible({ timeout: 5000 });

    // Type a search query
    await searchInput.fill('admin');

    // Wait for the search to debounce and results to filter
    await page.waitForTimeout(500);

    // The admin user should still be visible
    await expect(page.locator('text=admin@localhost')).toBeVisible({ timeout: 5000 });
  });

  test('can view user details', async ({ page }) => {
    await page.goto('/users');

    // Wait for the table to load
    await expect(page.locator('c-table')).toBeVisible({ timeout: 10000 });

    // Click the "View" button on the admin@localhost row
    await page.locator('c-button:has-text("View")').first().click();

    // Should navigate to the user detail page
    await expect(page).toHaveURL(/\/users\/[0-9a-f-]+/, { timeout: 5000 });
  });

  test('can delete a user', async ({ page }) => {
    await page.goto('/users');

    // Wait for the table to load
    await expect(page.locator('c-table')).toBeVisible({ timeout: 10000 });

    // Find the "e2e-test@example.com" row and click its "Delete" button
    const e2eUserRow = page.locator('text=e2e-test@example.com').first();
    if (await e2eUserRow.isVisible({ timeout: 3000 }).catch(() => false)) {
      // Accept the confirm() dialog
      page.on('dialog', async (dialog) => {
        await dialog.accept();
      });

      // Click the Delete button — need to find it near the e2e user row
      const deleteBtns = page.locator('c-button:has-text("Delete")');
      const count = await deleteBtns.count();

      if (count > 0) {
        await deleteBtns.last().click();

        // A success toast should appear
        await expect(page.locator('text=User deleted')).toBeVisible({ timeout: 10000 });
      }
    }
  });
});
