/**
 * Shared helpers for E2E tests.
 * The admin UI uses Shadow DOM, but Playwright's locator() pierces shadow DOM by default.
 */

export const DEFAULT_EMAIL = process.env.DEFAULT_EMAIL || 'admin@example.com';
export const DEFAULT_PASSWORD = process.env.DEFAULT_PASSWORD || 'Admin123';

/**
 * Perform login via the password form on /login.
 * Waits for navigation to the dashboard (/) after successful login.
 */
export async function login(page, email = DEFAULT_EMAIL, password = DEFAULT_PASSWORD) {
  await page.goto('/login');

  // Fill the email and password inputs (they live inside shadow DOM)
  await page.locator('#email').fill(email);
  await page.locator('#password').fill(password);

  // Submit the form and wait for redirect to dashboard
  await page.locator('button[type="submit"]').click();

  // Wait for the URL to change away from /login
  await page.waitForURL((url) => url.pathname !== '/login', { timeout: 10000 });
}
