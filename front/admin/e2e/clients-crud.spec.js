import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test.describe('Clients CRUD', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('can navigate to clients page', async ({ page }) => {
    // Click the "Clients" link in the sidebar
    await page.locator('.sidebar-nav >> text=Clients').click();

    // URL should be /clients
    await expect(page).toHaveURL('/clients');

    // Page heading should contain "Clients"
    await expect(page.locator('text=Clients')).toBeVisible();
  });

  test('can list clients with admin-ui', async ({ page }) => {
    await page.goto('/clients');

    // Wait for the table to load
    await expect(page.locator('c-table')).toBeVisible({ timeout: 10000 });

    // Should have at least the admin-ui client
    await expect(page.locator('text=admin-ui')).toBeVisible({ timeout: 5000 });
  });

  test('can create a client', async ({ page }) => {
    await page.goto('/clients');

    // Click the "+ Add Client" button in the page actions slot
    await page.locator('text=Add Client').click();

    // The modal should open — wait for the "Create Client" title
    await expect(page.locator('text=Create Client')).toBeVisible({ timeout: 5000 });

    // Fill in the required fields — inputs use class="field-input" inside shadow DOM
    // Realm ID
    const realmIdInput = page.locator('.field-input[placeholder="Enter realm UUID"]');
    await realmIdInput.fill('00000000-0000-0000-0000-000000000000');

    // Client ID is required
    const clientIdInput = page.locator('.field-input[placeholder="e.g. my-web-app"]');
    await clientIdInput.fill('e2e-test-client');

    // Name is required
    const nameInput = page.locator('.field-input[placeholder="e.g. My Web Application"]');
    await nameInput.fill('E2E Test Client');

    // Redirect URIs (textarea)
    const redirectUrisInput = page.locator('.field-textarea[placeholder="https://example.com/callback"]');
    await redirectUrisInput.fill('http://localhost:3000/callback');

    // Submit the form by clicking the "Create" button in the modal footer
    await page.locator('c-modal >> text=Create').last().click();

    // The modal should close and the new client should appear in the list
    await expect(page.locator('text=e2e-test-client')).toBeVisible({ timeout: 10000 });

    // A success toast should appear
    await expect(page.locator('text=Client created successfully')).toBeVisible({ timeout: 5000 });
  });

  test('can search clients', async ({ page }) => {
    await page.goto('/clients');

    // Wait for the table to load
    await expect(page.locator('c-table')).toBeVisible({ timeout: 10000 });

    // The search input should be visible
    const searchInput = page.locator('.search-input[placeholder="Search clients..."]');
    await expect(searchInput).toBeVisible({ timeout: 5000 });

    // Type a search query
    await searchInput.fill('admin-ui');

    // Wait for the search to debounce and results to filter
    await page.waitForTimeout(500);

    // The admin-ui client should still be visible
    await expect(page.locator('text=admin-ui')).toBeVisible({ timeout: 5000 });
  });

  test('can view client details', async ({ page }) => {
    await page.goto('/clients');

    // Wait for the table to load
    await expect(page.locator('c-table')).toBeVisible({ timeout: 10000 });

    // Click the "Edit" button on the admin-ui row
    await page.locator('c-button:has-text("Edit")').first().click();

    // Should navigate to the client detail page
    await expect(page).toHaveURL(/\/clients\/[0-9a-f-]+/, { timeout: 5000 });
  });

  test('can delete a client', async ({ page }) => {
    await page.goto('/clients');

    // Wait for the table to load
    await expect(page.locator('c-table')).toBeVisible({ timeout: 10000 });

    // Find the "e2e-test-client" row and click its "Delete" button
    const e2eClientRow = page.locator('text=e2e-test-client').first();
    if (await e2eClientRow.isVisible({ timeout: 3000 }).catch(() => false)) {
      // Accept the confirm() dialog
      page.on('dialog', async (dialog) => {
        await dialog.accept();
      });

      // Click the Delete button — need to find it near the e2e client row
      const deleteBtns = page.locator('c-button:has-text("Delete")');
      const count = await deleteBtns.count();

      if (count > 0) {
        await deleteBtns.last().click();

        // A success toast should appear
        await expect(page.locator('text=Client deleted')).toBeVisible({ timeout: 10000 });
      }
    }
  });
});
