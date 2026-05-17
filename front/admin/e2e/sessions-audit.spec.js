import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test.describe('Sessions and Audit', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('can exercise session bulk-selection controls without revoking the current session', async ({ page }) => {
    await page.goto('/sessions');
    await expect(page).toHaveURL('/sessions');
    await expect(page.getByRole('heading', { name: 'Sessions' })).toBeVisible();

    await expect(page.locator('c-table, .empty-state')).toBeVisible({ timeout: 10000 });

    const selectableSessions = page.getByLabel('Select session');
    const count = await selectableSessions.count();
    expect(count).toBeGreaterThan(0);

    await selectableSessions.first().check();
    await expect(page.locator('.bulk-bar')).toContainText('1 selected');

    await page.locator('c-button:has-text("Revoke Selected")').click();
    const confirmDialog = page.locator('[role="dialog"][aria-label="Bulk Revoke"]');
    await expect(confirmDialog).toBeVisible();
    await page.locator('c-modal[title="Bulk Revoke"] >> text=Cancel').last().click();
    await expect(confirmDialog).toBeHidden();

    await page.locator('c-button:has-text("Clear")').click();
    await expect(page.locator('.bulk-bar')).toHaveCount(0);

    await page.getByLabel('Include revoked sessions').check();
    await expect(page.getByLabel('Include revoked sessions')).toBeChecked();
  });

  test('can filter audit events by event type and clear filters', async ({ page }) => {
    await page.goto('/audit');
    await expect(page).toHaveURL('/audit');
    await expect(page.locator('text=Audit Log')).toBeVisible();
    await expect(page.locator('c-table')).toBeVisible({ timeout: 10000 });

    const eventTypeFilter = page.locator('.filter-select');
    await expect(eventTypeFilter).toBeVisible();

    await expect.poll(async () => {
      return await eventTypeFilter.locator('option').count();
    }).toBeGreaterThan(1);

    const chosenEventType = await eventTypeFilter.locator('option').nth(1).getAttribute('value');
    expect(chosenEventType).toBeTruthy();

    await eventTypeFilter.selectOption(chosenEventType);
    await expect(page.locator('.clear-btn')).toBeVisible({ timeout: 10000 });
    await expect(eventTypeFilter).toHaveValue(chosenEventType);
    await expect(page.locator('c-table')).toBeVisible();

    await page.locator('.clear-btn').click();
    await expect(eventTypeFilter).toHaveValue('');
    await expect(page.locator('.clear-btn')).toHaveCount(0);
  });
});
