import { createHmac } from 'node:crypto';
import { test, expect } from '@playwright/test';
import { DEFAULT_EMAIL, DEFAULT_PASSWORD, login } from './helpers.js';

function decodeBase32(value) {
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let buffer=0,bits=0; const bytes=[];
  for(const char of value.replace(/=+$/,'')){buffer=(buffer<<5)|alphabet.indexOf(char);bits+=5;if(bits>=8){bits-=8;bytes.push((buffer>>bits)&255);}}
  return Buffer.from(bytes);
}

function totp(secret) {
  const step=Math.floor(Date.now()/1000/30); const counter=Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(step));
  const digest=createHmac('sha1',decodeBase32(secret)).update(counter).digest(); const offset=digest[19]&15;
  const value=(digest.readUInt32BE(offset)&0x7fffffff)%1_000_000; return String(value).padStart(6,'0');
}

test('capture the multi-factor authentication guide',async({page,context})=>{
  test.skip(!process.env.UPDATE_DOC_SCREENSHOTS,'Set UPDATE_DOC_SCREENSHOTS=1 to refresh documentation images');
  await page.setViewportSize({width:1440,height:1000}); await login(page); await page.goto('/security');
  await expect(page.getByRole('heading',{name:'Sign-in security'})).toBeVisible();
  await page.getByRole('button',{name:'Set up authenticator'}).click();
  const secret=(await page.locator('pre.api-key-raw').first().textContent()).trim();
  await page.locator('input[autocomplete="one-time-code"]').fill(totp(secret));
  await page.getByText('Verify and enable').click();
  await expect(page.getByText('Authenticator app enabled')).toBeVisible();
  const recoveryCode=(await page.locator('pre.api-key-raw').first().textContent()).trim().split('\n')[0];
  await page.reload();
  await expect(page.getByText('is enabled.')).toBeVisible();

  await page.getByRole('button',{name:'Logout'}).click();
  await expect(page).toHaveURL('/login');
  await page.reload();
  await page.locator('#email').fill(DEFAULT_EMAIL); await page.locator('#password').fill(DEFAULT_PASSWORD); await page.locator('button[type="submit"]').click();
  await expect(page.getByText('Complete your sign in with a second factor.')).toBeVisible();
  await page.screenshot({path:'../../docs/assets/multi-factor-authentication/login-challenge.png'});
  await page.locator('#mfa-code').fill(totp(secret)); await page.getByRole('button',{name:'Verify',exact:true}).click(); await expect(page).toHaveURL('/');

  await page.getByRole('button',{name:'Logout'}).click(); await page.reload();
  await page.locator('#email').fill(DEFAULT_EMAIL); await page.locator('#password').fill(DEFAULT_PASSWORD); await page.locator('button[type="submit"]').click();
  await page.getByRole('button',{name:'Recovery code'}).click(); await page.locator('#mfa-code').fill(recoveryCode); await page.getByRole('button',{name:'Verify',exact:true}).click(); await expect(page).toHaveURL('/');

  const cdp=await context.newCDPSession(page); await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
  await page.goto('/security'); await page.getByRole('button',{name:'Add a passkey'}).click(); await expect(page.getByText('Passkey added')).toBeVisible();
  await page.reload(); await expect(page.getByText('Passkey',{exact:true})).toBeVisible(); await page.evaluate(()=>window.scrollTo(0,0));
  await page.screenshot({path:'../../docs/assets/multi-factor-authentication/security-settings.png'});

  await page.getByRole('button',{name:'Logout'}).click(); await page.reload();
  await page.locator('#email').fill(DEFAULT_EMAIL); await page.locator('#password').fill(DEFAULT_PASSWORD); await page.locator('button[type="submit"]').click(); await expect(page).toHaveURL('/');

  await page.goto('/users'); await page.getByRole('row',{name:new RegExp(DEFAULT_EMAIL)}).getByRole('button',{name:'View'}).click();
  await expect(page.getByText('Multi-factor authentication')).toBeVisible();
  await page.getByRole('button',{name:'Reset MFA'}).click(); await page.getByRole('button',{name:'Confirm'}).click();
});
