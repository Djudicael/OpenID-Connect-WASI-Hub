import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test.describe('Password Policies', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('can save password policy changes and restore the previous values', async ({ page }) => {
    const uniqueBlockedPassword = `e2e-blocked-${Date.now()}`;

    await page.goto('/password-policies');
    await expect(page).toHaveURL('/password-policies');
    await expect(page.getByRole('heading', { name: 'Password Policies' })).toBeVisible();

    const minLengthInput = page.locator('#pp-min');
    const maxLengthInput = page.locator('#pp-max');
    const uniqueCharsInput = page.locator('#pp-unique');
    const disallowedTextarea = page.locator('#pp-disallowed');
    const requireUpperCheckbox = page.locator('#pp-upper');

    const originalMinLength = await minLengthInput.inputValue();
    const originalMaxLength = await maxLengthInput.inputValue();
    const originalUniqueChars = await uniqueCharsInput.inputValue();
    const originalDisallowed = await disallowedTextarea.inputValue();
    const originalRequireUpper = await requireUpperCheckbox.isChecked();

    const nextRequireUpper = !originalRequireUpper;
    const nextMinLength = String(Math.min(64, Math.max(8, Number(originalMinLength || '8') + 1)));
    const nextMaxLength = String(Math.max(Number(nextMinLength) + 4, Number(originalMaxLength || '128')));
    const nextUniqueChars = String(Math.max(1, Number(originalUniqueChars || '0') + 1));
    const nextDisallowed = originalDisallowed
      ? `${originalDisallowed}\n${uniqueBlockedPassword}`
      : uniqueBlockedPassword;

    await minLengthInput.fill(nextMinLength);
    await maxLengthInput.fill(nextMaxLength);
    await uniqueCharsInput.fill(nextUniqueChars);
    await disallowedTextarea.fill(nextDisallowed);
    await requireUpperCheckbox.setChecked(nextRequireUpper);

    await page.locator('c-button:has-text("Save Policy")').click();
    await expect(page.locator('text=Password policy saved')).toBeVisible({ timeout: 10000 });

    await page.reload();
    await expect(minLengthInput).toHaveValue(nextMinLength);
    await expect(maxLengthInput).toHaveValue(nextMaxLength);
    await expect(uniqueCharsInput).toHaveValue(nextUniqueChars);
    await expect(disallowedTextarea).toHaveValue(nextDisallowed);
    expect(await requireUpperCheckbox.isChecked()).toBe(nextRequireUpper);

    await minLengthInput.fill(originalMinLength);
    await maxLengthInput.fill(originalMaxLength);
    await uniqueCharsInput.fill(originalUniqueChars);
    await disallowedTextarea.fill(originalDisallowed);
    await requireUpperCheckbox.setChecked(originalRequireUpper);

    await page.locator('c-button:has-text("Save Policy")').click();
    await expect(page.locator('text=Password policy saved')).toBeVisible({ timeout: 10000 });
  });
});
