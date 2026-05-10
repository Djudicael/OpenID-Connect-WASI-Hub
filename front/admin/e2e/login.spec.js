import { test, expect } from '@playwright/test';

test.describe('Login page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login');
  });

  test('shows login form on /login', async ({ page }) => {
    // Verify email input exists
    const emailInput = page.locator('#email');
    await expect(emailInput).toBeVisible();

    // Verify password input exists
    const passwordInput = page.locator('#password');
    await expect(passwordInput).toBeVisible();

    // Verify submit button exists
    const submitBtn = page.locator('button[type="submit"]');
    await expect(submitBtn).toBeVisible();
  });

  test('displays error on wrong credentials', async ({ page }) => {
    await page.locator('#email').fill('admin@localhost');
    await page.locator('#password').fill('wrong');
    await page.locator('button[type="submit"]').click();

    // An error message should appear (rendered inside shadow DOM)
    const errorBox = page.locator('.error');
    await expect(errorBox).toBeVisible({ timeout: 5000 });
  });

  test('redirects to dashboard on successful login', async ({ page }) => {
    await page.locator('#email').fill('admin@localhost');
    await page.locator('#password').fill('admin123');
    await page.locator('button[type="submit"]').click();

    // Should redirect to /
    await expect(page).toHaveURL('/', { timeout: 10000 });

    // Dashboard heading should be visible (rendered by c-page-layout with title="Dashboard")
    const dashboardHeading = page.locator('text=Dashboard');
    await expect(dashboardHeading).toBeVisible();
  });

  test('login form prevents submission with empty fields', async ({ page }) => {
    // Click submit without filling any fields
    const submitBtn = page.locator('button[type="submit"]');

    // HTML5 validation should block submission — the browser will show a
    // validation popup and the page stays on /login.
    // We check that the URL has NOT changed and the form is still present.
    await submitBtn.click();

    // Page should still be on /login (no navigation occurred)
    await expect(page).toHaveURL('/login');

    // The email input should have the :invalid or :user-invalid pseudo-class
    // but Playwright can't easily check pseudo-classes. Instead, verify we're
    // still on the login page and the form is intact.
    await expect(page.locator('#email')).toBeVisible();
    await expect(page.locator('#password')).toBeVisible();
  });
});
