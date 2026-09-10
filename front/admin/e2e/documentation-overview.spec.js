import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test('capture core administration guide screens', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1200 });
  await login(page);

  await page.evaluate(async () => {
    const token = JSON.parse(sessionStorage.getItem('oidc_tokens')).access_token;
    await fetch('/api/realms?limit=1', {
      credentials: 'same-origin',
      headers: { Authorization: `Bearer ${token}` },
    });
  });
  const csrf = (await page.context().cookies()).find(cookie => cookie.name === 'oidc_csrf_token')?.value;
  expect(csrf).toBeTruthy();

  const sample = await page.evaluate(async csrfToken => {
    const token = JSON.parse(sessionStorage.getItem('oidc_tokens')).access_token;
    const call = async (path, options = {}) => {
      const response = await fetch(path, {
        ...options,
        credentials: 'same-origin',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
          ...(options.method && options.method !== 'GET' ? { 'X-CSRF-Token': csrfToken } : {}),
        },
      });
      const body = await response.json();
      if (!response.ok) throw new Error(`${response.status} ${JSON.stringify(body)}`);
      return body;
    };

    const realm = (await call('/api/realms?limit=1')).items[0];
    let user = (await call(`/api/users?realm_id=${realm.id}&search=guide-user&limit=5`)).items[0];
    if (!user) {
      user = await call('/api/users', {
        method: 'POST',
        body: JSON.stringify({
          realm_id: realm.id,
          email: 'guide-user@example.test',
          username: 'guide-user',
          password: 'GuideUser123!',
          given_name: 'Taylor',
          family_name: 'Morgan',
        }),
      });
    }
    return { realmId: realm.id, userId: user.id };
  }, csrf);

  await page.goto(`/users/${sample.userId}`);
  await expect(page.locator('user-detail-page input.field-input').first()).toHaveValue('guide-user@example.test');
  if (process.env.UPDATE_DOC_SCREENSHOTS) {
    await page.screenshot({ path: '../../docs/assets/user-management/user-profile.png' });
    await page.getByText('Multi-factor authentication', { exact: true }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: '../../docs/assets/user-management/user-access.png' });
  }

  await page.goto('/clients');
  await page.getByRole('button', { name: '+ Add Client' }).first().click();
  await page.getByPlaceholder('e.g. my-web-app').fill('orders-worker');
  await page.getByPlaceholder('e.g. My Web App').fill('Orders worker');
  await page.locator('c-modal select.field-select').nth(1).selectOption('confidential');
  await page.getByRole('checkbox', { name: /^Authorization Code/ }).click();
  await page.getByRole('checkbox', { name: /^Client Credentials/ }).click();
  await page.getByRole('checkbox', { name: 'PKCE Required', exact: true }).click();
  if (process.env.UPDATE_DOC_SCREENSHOTS) {
    await page.screenshot({ path: '../../docs/assets/application-integration/service-client.png', fullPage: true });
  }

  await page.goto('/api-keys/create');
  await page.getByPlaceholder('e.g. Production Service Key').fill('Workflow scheduler');
  const workflowPermission = page.locator('.scope-chip span', { hasText: 'workflows:execute' });
  await workflowPermission.scrollIntoViewIfNeeded();
  await expect(workflowPermission).toBeVisible();
  if (process.env.UPDATE_DOC_SCREENSHOTS) {
    await page.screenshot({ path: '../../docs/assets/api-keys/create-key.png', fullPage: true });
  }
});
