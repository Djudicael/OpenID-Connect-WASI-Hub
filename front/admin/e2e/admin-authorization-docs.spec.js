import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test('capture the delegated administration guide', async ({ page }) => {
  test.skip(
    !process.env.UPDATE_DOC_SCREENSHOTS,
    'Set UPDATE_DOC_SCREENSHOTS=1 to refresh documentation images',
  );
  await page.setViewportSize({ width: 1440, height: 1000 });
  await login(page);
  await page.goto('/roles');
  await expect(page.getByRole('heading', { name: 'Roles' })).toBeVisible();
  await page.getByRole('button', { name: /Add Role/ }).first().click();
  await page.locator('#create-role-name').fill('support-administrator');
  await page
    .locator('#create-role-desc')
    .fill('Can view users and clients without changing them');
  await page.locator('#create-role-perms').fill('users:read, clients:read');
  await expect(page.getByText('Create Role', { exact: true })).toBeVisible();
  await page.screenshot({
    path: '../../docs/assets/delegated-administration/create-role.png',
  });
});
