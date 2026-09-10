import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test('configure and preview realm presentation', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await login(page);
  await page.evaluate(async () => {
    const token = JSON.parse(sessionStorage.getItem('oidc_tokens')).access_token;
    await fetch('/api/realms?limit=1', { credentials: 'same-origin', headers: { Authorization: `Bearer ${token}` } });
  });
  const csrf = (await page.context().cookies()).find(cookie => cookie.name === 'oidc_csrf_token')?.value;
  expect(csrf).toBeTruthy();
  const realm = await page.evaluate(async (csrf) => {
    const token = JSON.parse(sessionStorage.getItem('oidc_tokens')).access_token;
    const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
    const list = await (await fetch('/api/realms?limit=1', { headers })).json();
    const realm = list.items[0];
    realm.config = {
      ...(realm.config || {}),
      theme: {
        login_title: 'Example Identity', logo_url: '', favicon_url: '', primary_color: '#6d28d9',
        background_color: '#f5f3ff', card_color: '#ffffff', text_color: '#1f1534',
        font_family: 'Arial, sans-serif', footer_text: 'Example Company identity service',
      },
      localization: {
        default_locale: 'en', supported_locales: ['en', 'fr'],
        messages: { fr: { page_title: 'Connexion', subtitle: 'Connectez-vous à votre compte', email: 'Adresse e-mail', email_placeholder: 'vous@exemple.fr', password: 'Mot de passe', sign_in: 'Se connecter', signing_in: 'Connexion…', login_failed: 'Échec de la connexion', toggle_password: 'Afficher ou masquer le mot de passe' } },
      },
      email_templates: { locales: { fr: { password_reset: {
        subject: 'Réinitialisez votre mot de passe {{realm_name}}',
        text: 'Bonjour {{user_name}},\n\nUtilisez ce lien : {{action_url}}\n\nExpiration : {{expires_in}}.',
        html: '<p>Bonjour {{user_name}},</p><p><a href="{{action_url}}">Réinitialiser mon mot de passe</a></p><p>Expiration : {{expires_in}}.</p>',
      } } } },
    };
    const response = await fetch(`/api/realms/${realm.id}`, { method: 'PUT', credentials: 'same-origin', headers: { ...headers, 'X-CSRF-Token': csrf }, body: JSON.stringify({ config: realm.config }) });
    if (!response.ok) throw new Error(await response.text());
    return realm;
  }, csrf);

  await page.goto(`/realms/${realm.id}`);
  await expect(page.getByText('Loading...')).toBeHidden();
  if (process.env.UPDATE_DOC_SCREENSHOTS) await page.locator('[data-doc-section="theme"]').screenshot({ path: '../../docs/assets/realm-presentation/theme-settings.png' });

  await page.locator('.field', { hasText: 'Edit Translations For' }).locator('select').selectOption('fr');
  await expect(page.locator('.field', { hasText: 'Sign-in button' }).locator('input')).toHaveValue('Se connecter');
  if (process.env.UPDATE_DOC_SCREENSHOTS) await page.locator('[data-doc-section="localization"]').screenshot({ path: '../../docs/assets/realm-presentation/localization.png' });

  await page.getByRole('button', { name: 'Preview saved template' }).click();
  await expect(page.getByText('Réinitialisez votre mot de passe master')).toBeVisible();
  if (process.env.UPDATE_DOC_SCREENSHOTS) await page.locator('[data-doc-section="email-templates"]').screenshot({ path: '../../docs/assets/realm-presentation/email-template.png' });

  const loginPage = await page.context().newPage();
  await loginPage.setViewportSize({ width: 1100, height: 760 });
  await loginPage.goto(`/realms/${realm.name}/login?ui_locales=fr`);
  await expect(loginPage.getByRole('button', { name: 'Se connecter' })).toBeVisible();
  await expect(loginPage.getByText('Connectez-vous à votre compte')).toBeVisible();
  const password = loginPage.locator('#password');
  const passwordToggle = loginPage.locator('#togglePw');
  await expect(passwordToggle.locator('svg:not([hidden])')).toHaveCount(1);
  await passwordToggle.click();
  await expect(password).toHaveAttribute('type', 'text');
  await expect(passwordToggle).toHaveAttribute('aria-pressed', 'true');
  await passwordToggle.click();
  await expect(password).toHaveAttribute('type', 'password');
  if (process.env.UPDATE_DOC_SCREENSHOTS) await loginPage.screenshot({ path: '../../docs/assets/realm-presentation/localized-sign-in.png', fullPage: true });
});
