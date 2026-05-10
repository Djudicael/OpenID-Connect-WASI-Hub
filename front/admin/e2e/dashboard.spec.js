import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test.describe('Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('dashboard shows navigation after login', async ({ page }) => {
    // Sidebar nav links should be visible
    const navLabels = ['Dashboard', 'Users', 'Clients', 'Realms', 'Sessions', 'API Keys', 'Audit'];

    for (const label of navLabels) {
      const link = page.locator(`.sidebar-nav >> text=${label}`);
      await expect(link).toBeVisible();
    }
  });

  test('dashboard shows stats cards', async ({ page }) => {
    // The dashboard renders stat cards with .stat-card class
    const statCards = page.locator('.stat-card');
    await expect(statCards).toHaveCount(4, { timeout: 10000 });

    // Each stat card should have a label and a value
    const statLabels = ['Users', 'Clients', 'Realms', 'Active Sessions'];
    for (const label of statLabels) {
      const card = page.locator(`.stat-card >> text=${label}`);
      await expect(card).toBeVisible();
    }
  });
});
