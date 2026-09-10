import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test('capture the user account console guide', async ({ page }) => {
  test.skip(!process.env.UPDATE_DOC_SCREENSHOTS, 'Set UPDATE_DOC_SCREENSHOTS=1 to refresh documentation images');
  await page.setViewportSize({ width: 1440, height: 1000 });
  await login(page);
  await page.goto('/account');
  await expect(page.getByRole('heading', { name: 'My account' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Personal information' })).toBeVisible();
  await page.screenshot({ path: '../../docs/assets/user-account-console/profile.png' });

  await page.getByRole('button', { name: 'Sessions', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Active sessions' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign out' }).first()).toBeEnabled();
  await page.screenshot({ path: '../../docs/assets/user-account-console/sessions.png' });

  await page.getByRole('button', { name: 'Applications', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Approved applications' })).toBeVisible();
  await expect(page.getByText('Admin UI', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Remove access' })).toBeEnabled();
  await page.screenshot({ path: '../../docs/assets/user-account-console/applications.png' });
});
