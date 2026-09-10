import { test, expect } from '@playwright/test';
import { login } from './helpers.js';

test('manage workflows and capture the user guide', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 2200 });
  await login(page);
  await page.evaluate(async () => {
    const token=JSON.parse(sessionStorage.getItem('oidc_tokens')).access_token;
    await fetch('/api/realms?limit=1',{credentials:'same-origin',headers:{Authorization:`Bearer ${token}`}});
  });
  const csrf=(await page.context().cookies()).find(c=>c.name==='oidc_csrf_token')?.value;
  expect(csrf).toBeTruthy();
  const seeded=await page.evaluate(async csrf=>{
    const token=JSON.parse(sessionStorage.getItem('oidc_tokens')).access_token;
    const call=async(path,options={})=>{const response=await fetch(path,{...options,credentials:'same-origin',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json',...(options.method&&options.method!=='GET'?{'X-CSRF-Token':csrf}:{})}});const body=await response.json();if(!response.ok)throw new Error(`${response.status} ${JSON.stringify(body)}`);return body};
    const realm=(await call('/api/realms?limit=1')).items[0];
    const old=(await call(`/api/realms/${realm.id}/workflows`)).items.find(w=>w.name==='Quarterly credential review');
    if(old)await call(`/api/realms/${realm.id}/workflows/${old.id}`,{method:'DELETE'});
    let user=(await call(`/api/users?realm_id=${realm.id}&search=workflow-guide&limit=5`)).items[0];
    if(!user)user=await call('/api/users',{method:'POST',body:JSON.stringify({realm_id:realm.id,email:'workflow-guide@example.test',password:'WorkflowGuide123!',username:'workflow-guide',given_name:'Morgan',family_name:'Reed'})});
    const definition={name:'Quarterly credential review',description:'Require active contractors to refresh their password and sign in again',enabled:true,trigger_events:['user.account_recovery_completed'],conditions:[{type:'user_enabled',value:true}],steps:[{action:{type:'add_required_action',action:'update_password'},after_seconds:0},{action:{type:'revoke_sessions'},after_seconds:0}],schedule:{every_seconds:7776000,batch_size:100}};
    const workflow=await call(`/api/realms/${realm.id}/workflows`,{method:'POST',body:JSON.stringify(definition)});
    await call(`/api/realms/${realm.id}/workflows/${workflow.id}/activate`,{method:'POST',body:JSON.stringify({user_id:user.id})});
    definition.conditions.push({type:'user_attribute_equals',name:'employment_type',value:'contractor'});
    await call(`/api/realms/${realm.id}/workflows/${workflow.id}`,{method:'PUT',body:JSON.stringify(definition)});
    return {workflowId:workflow.id};
  },csrf);

  await page.goto('/workflows');
  await expect(page.getByText('Loading...')).toBeHidden();
  await expect(page.getByRole('strong').filter({hasText:'Quarterly credential review'})).toBeVisible();
  if(process.env.UPDATE_DOC_SCREENSHOTS)await page.screenshot({path:'../../docs/assets/workflows/workflow-list.png',fullPage:true});

  await page.getByRole('strong').filter({hasText:'Quarterly credential review'}).locator('xpath=ancestor::div[contains(@class,"workflow-card")]').getByRole('button',{name:'Edit'}).click();
  await expect(page.locator('workflows-page input.field-input').first()).toHaveValue('Quarterly credential review');
  await expect(page.locator('workflows-page .builder-row').nth(1).locator('select').first()).toHaveValue('user_attribute_equals');
  if(process.env.UPDATE_DOC_SCREENSHOTS)await page.screenshot({path:'../../docs/assets/workflows/workflow-editor.png',fullPage:true});

  await page.getByRole('button',{name:'Execution history'}).click();
  const executionRow=page.getByRole('row').filter({hasText:'Quarterly credential review'}).first();
  await expect(executionRow).toContainText('manual');
  await expect(executionRow).toContainText('completed');
  if(process.env.UPDATE_DOC_SCREENSHOTS)await page.screenshot({path:'../../docs/assets/workflows/execution-history.png',fullPage:true});
  expect(seeded.workflowId).toBeTruthy();
});
