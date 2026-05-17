import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

function toBase64Url(value) {
  return Buffer.from(JSON.stringify(value))
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function makeJwt(claims) {
  return `${toBase64Url({ alg: 'none', typ: 'JWT' })}.${toBase64Url(claims)}.signature`;
}

async function getFocusState(page) {
  return page.evaluate(() => {
    const getDeepActiveElement = (root = document) => {
      let active = root?.activeElement || null;
      while (active?.shadowRoot?.activeElement) {
        active = active.shadowRoot.activeElement;
      }
      return active;
    };

    const active = getDeepActiveElement(document);
    const routeElement = document.querySelector('router-outlet')?.firstElementChild || null;
    const pageFocusTarget = routeElement?.shadowRoot
      ?.querySelector('c-page-layout')
      ?.shadowRoot
      ?.querySelector('[data-page-focus]') || null;

    return {
      tagName: active?.tagName || null,
      text: (active?.textContent || '').replace(/\s+/g, ' ').trim(),
      ariaLabel: active?.getAttribute?.('aria-label') || null,
      isPageFocusTarget: active === pageFocusTarget,
    };
  });
}

test.describe('Admin authz and accessibility', () => {
  test('redirects non-admin sessions away from protected routes and clears stored tokens', async ({ page }) => {
    const futureEpochSeconds = Math.floor(Date.now() / 1000) + 60 * 60;
    const fakeTokens = {
      access_token: makeJwt({
        sub: 'non-admin-user',
        scope: 'openid profile email',
        exp: futureEpochSeconds,
      }),
      id_token: makeJwt({
        sub: 'non-admin-user',
        email: 'viewer@example.com',
        exp: futureEpochSeconds,
      }),
      expires_at: Date.now() + 60 * 60 * 1000,
    };

    await page.addInitScript(({ tokens }) => {
      sessionStorage.setItem('oidc_tokens', JSON.stringify(tokens));
    }, { tokens: fakeTokens });

    await page.goto('/users');

    await expect(page).toHaveURL(/\/login$/, { timeout: 10000 });
    await page.waitForFunction(() => sessionStorage.getItem('oidc_tokens') === null);
    await expect(page.locator('#email')).toBeVisible();
  });

  test('moves focus into routed page content and restores trigger focus after modal close', async ({ page }) => {
    await login(page);

    await page.locator('.sidebar-nav >> text=Roles').click();
    await expect(page).toHaveURL('/roles');
    await expect(page.locator('text=Roles')).toBeVisible();

    await expect.poll(async () => {
      const focus = await getFocusState(page);
      return focus.isPageFocusTarget;
    }).toBe(true);

    await page.locator('c-button:has-text("Add Role")').click();

    const dialog = page.locator('[role="dialog"][aria-label="Create Role"]');
    await expect(dialog).toBeVisible();

    await expect.poll(async () => {
      const focus = await getFocusState(page);
      return `${focus.tagName}|${focus.ariaLabel}`;
    }).toBe('BUTTON|Close dialog');

    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();

    await expect.poll(async () => {
      const focus = await getFocusState(page);
      return focus.text;
    }).toContain('Add Role');
  });
});
