import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test('create, edit, and delete policies from the console', async ({ page }) => {
  await login(page);
  await page.goto('/client-policies');
  await expect(page.getByText('Loading...')).toBeHidden();
  const suffix = Date.now();
  const profileName = `Mobile baseline ${suffix}`;
  const policyName = `Mobile clients ${suffix}`;
  const inputs = page.locator('client-policies-page input.field-input');
  await inputs.nth(0).fill(profileName);
  await page.getByRole('button', { name:'Create profile' }).click();
  await expect(page.getByText(profileName, { exact:true })).toBeVisible();

  await page.getByRole('button', { name:'Policies', exact:true }).click();
  const policyInputs = page.locator('client-policies-page input.field-input');
  await policyInputs.nth(0).fill(policyName);
  await page.getByText(profileName, { exact:true }).locator('input').check();
  await page.getByRole('button', { name:'Create policy' }).click();
  await expect(page.getByText(policyName, { exact:true })).toBeVisible();
  await page.getByRole('button', { name:'Edit' }).click();
  await page.locator('client-policies-page input.field-input').nth(2).fill('25');
  await page.getByRole('button', { name:'Update policy' }).click();
  await expect(page.getByText('Priority 25')).toBeVisible();

  page.once('dialog', dialog => dialog.accept());
  await page.getByRole('button', { name:'Delete' }).click();
  await expect(page.getByText(policyName, { exact:true })).toBeHidden();
  await page.getByRole('button', { name:'Security profiles' }).click();
  page.once('dialog', dialog => dialog.accept());
  await page.getByText(profileName, { exact:true }).locator('xpath=ancestor::div[contains(@class,"list-card")]').getByRole('button', { name:'Delete' }).click();
  await expect(page.getByText(profileName, { exact:true })).toBeHidden();
});

test('manage, evaluate, and document client policies', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1050 });
  await login(page);
  await page.evaluate(async () => {
    const token = JSON.parse(sessionStorage.getItem('oidc_tokens')).access_token;
    await fetch('/api/realms?limit=1', { credentials:'same-origin', headers:{ Authorization:`Bearer ${token}` } });
  });
  const csrf = (await page.context().cookies()).find(cookie => cookie.name === 'oidc_csrf_token')?.value;
  expect(csrf).toBeTruthy();
  const seeded = await page.evaluate(async (csrf) => {
    const token = JSON.parse(sessionStorage.getItem('oidc_tokens')).access_token;
    const call = async (path, options = {}) => {
      const response = await fetch(path, { ...options, credentials:'same-origin', headers:{ Authorization:`Bearer ${token}`, 'Content-Type':'application/json', ...(options.method && options.method !== 'GET' ? {'X-CSRF-Token':csrf}:{}) } });
      const body = response.status === 204 ? null : await response.json();
      if (!response.ok) throw new Error(`${options.method||'GET'} ${path}: ${response.status} ${JSON.stringify(body)}`);
      return body;
    };
    const realm=(await call('/api/realms?limit=1')).items[0];
    const policies=(await call(`/api/realms/${realm.id}/client-policies`)).items;
    for(const p of policies.filter(x=>x.name==='Browser applications')) await call(`/api/realms/${realm.id}/client-policies/${p.id}`,{method:'DELETE'});
    const profiles=(await call(`/api/realms/${realm.id}/client-policy-profiles`)).items;
    for(const p of profiles.filter(x=>x.name==='Secure browser baseline')) await call(`/api/realms/${realm.id}/client-policy-profiles/${p.id}`,{method:'DELETE'});
    const profile=await call(`/api/realms/${realm.id}/client-policy-profiles`,{method:'POST',body:JSON.stringify({name:'Secure browser baseline',description:'Security requirements shared by browser applications',executors:[{type:'require_pkce'},{type:'secure_redirect_uris',allow_loopback_http:true},{type:'allowed_grant_types',values:['authorization_code','refresh_token']},{type:'allowed_scopes',values:['openid','profile','email']}]})});
    const policy=await call(`/api/realms/${realm.id}/client-policies`,{method:'POST',body:JSON.stringify({name:'Browser applications',description:'Apply the browser baseline to every public application',enabled:true,priority:10,conditions:[{type:'client_type',client_type:'public'}],profile_ids:[profile.id]})});
    let client=(await call(`/api/clients?realm_id=${realm.id}&search=policy-demo-browser&limit=10`)).items.find(x=>x.client_id==='policy-demo-browser');
    if(!client) client=await call('/api/clients',{method:'POST',body:JSON.stringify({realm_id:realm.id,client_id:'policy-demo-browser',client_type:'public',name:'Customer portal',redirect_uris:['https://portal.example.test/callback'],allowed_scopes:['openid','profile'],allowed_grant_types:['authorization_code'],pkce_required:true})});
    return {realm,profile,policy,client};
  }, csrf);

  await page.goto('/client-policies');
  await expect(page.getByText('Loading...')).toBeHidden();
  await expect(page.getByText('Secure browser baseline',{exact:true})).toBeVisible();
  if(process.env.UPDATE_DOC_SCREENSHOTS) await page.screenshot({path:'../../docs/assets/client-policies/security-profiles.png',fullPage:true});

  await page.getByRole('button',{name:'Policies',exact:true}).click();
  await expect(page.getByText('Browser applications',{exact:true})).toBeVisible();
  if(process.env.UPDATE_DOC_SCREENSHOTS) await page.screenshot({path:'../../docs/assets/client-policies/policies.png',fullPage:true});

  await page.getByRole('button',{name:'Test a client'}).click();
  await page.locator('select').filter({has:page.locator(`option[value="${seeded.client.id}"]`)}).selectOption(seeded.client.id);
  await page.getByRole('button',{name:'Evaluate'}).click();
  await expect(page.getByRole('heading',{name:'Client complies'})).toBeVisible();
  await expect(page.getByText('Matched policies: Browser applications')).toBeVisible();
  if(process.env.UPDATE_DOC_SCREENSHOTS) await page.screenshot({path:'../../docs/assets/client-policies/evaluation.png',fullPage:true});
});
