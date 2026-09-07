import { test, expect } from '@playwright/test';
import { login, DEFAULT_EMAIL, DEFAULT_PASSWORD } from './helpers.js';

test('capture authentication flow and required action guide', async ({ page }) => {
  test.skip(!process.env.UPDATE_DOC_SCREENSHOTS, 'Set UPDATE_DOC_SCREENSHOTS=1 to refresh documentation images');
  await page.setViewportSize({ width: 1440, height: 1600 });
  await login(page);
  await page.goto('/realms');
  await page.getByRole('button', { name: 'Edit' }).first().click();
  await expect(page.getByRole('heading', { name: 'Authentication flow' })).toBeVisible();
  await page.getByText('Enable realm authentication flow').locator('input').check();
  await page.getByText('Require a verified email address').locator('input').check();
  await page.getByText('Require first and last name').locator('input').check();
  await page.locator('[data-doc-section="authentication-flow"]').screenshot({ path: '../../docs/assets/authentication-flows/realm-flow.png' });
  await page.goto('/users');
  await page.getByRole('row', { name: new RegExp(DEFAULT_EMAIL) })
    .getByRole('button', { name: 'View' }).click();
  const userId = new URL(page.url()).pathname.split('/').pop();
  const adminToken = await page.evaluate(() => JSON.parse(sessionStorage.getItem('oidc_tokens')).access_token);
  const csrfToken = await page.evaluate(() => document.cookie.match(/(?:^|; )oidc_csrf_token=([^;]+)/)?.[1]);
  await expect(page.getByText('Required actions', { exact: true })).toBeVisible();
  await page.getByText('Update password', { exact: true }).locator('input').check();
  await page.getByRole('button', { name: 'Save required actions' }).click();
  await expect(page.getByText('Required actions updated')).toBeVisible();
  await page.locator('[data-doc-section="required-actions"]').screenshot({ path: '../../docs/assets/authentication-flows/user-actions.png' });
  await page.evaluate(() => sessionStorage.clear());
  await page.goto('/login');
  await page.locator('#email').fill(DEFAULT_EMAIL);
  await page.locator('#password').fill(DEFAULT_PASSWORD);
  await page.locator('button[type="submit"]').click();
  await expect(page.getByRole('heading', { name: 'Choose a new password' })).toBeVisible();
  await page.screenshot({ path: '../../docs/assets/authentication-flows/user-password-action.png' });
  const cleanup = await page.request.put(`/api/users/${userId}/required-actions`, {
    headers: { Authorization: `Bearer ${adminToken}`, 'X-CSRF-Token': csrfToken },
    data: { required_actions: [] },
  });
  expect(cleanup.ok()).toBeTruthy();
});
