import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test.describe('Auth state', () => {
  test('redirects to login when not authenticated', async ({ page }) => {
    // Clear any existing session tokens
    await page.goto('/login');
    await page.evaluate(() => {
      sessionStorage.clear();
    });

    // Try to navigate to the dashboard
    await page.goto('/');

    // Should be redirected to /login
    await expect(page).toHaveURL(/\/login/, { timeout: 10000 });
  });

  test('persists session across page reload', async ({ page }) => {
    // Login first
    await login(page);

    // Verify we're on the dashboard
    await expect(page).toHaveURL('/');

    // Reload the page
    await page.reload();

    // Should still be on the dashboard (not redirected to login)
    await expect(page).toHaveURL('/', { timeout: 10000 });

    // Dashboard content should still be visible
    const dashboardHeading = page.locator('text=Dashboard');
    await expect(dashboardHeading).toBeVisible();
  });
});
