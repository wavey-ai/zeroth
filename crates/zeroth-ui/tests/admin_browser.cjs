// Run after rendering examples/admin_preview.rs to /tmp/zeroth-polished-admin.html.
// PLAYWRIGHT_MODULE and CHROMIUM_EXECUTABLE may point to an existing local install.
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const html = fs.readFileSync(process.argv[2] || '/tmp/zeroth-polished-admin.html', 'utf8');
const output = process.env.SCREENSHOT_DIR || '/tmp/zeroth-admin-screenshots';
fs.mkdirSync(output, {recursive: true});
let tenants = [
  {id:'acme',name:'Acme Corporation',disabled:false,clientIds:['acme-portal'],auditReaders:[{userId:'usr_morgan',canExport:true}],enterpriseProvider:'entra',entraTenantId:'8f00f3d0-00a1-4b33-8c17-12c34567d890',googleWorkspaceDomains:[],oidcClientId:null,clientSecretBinding:null,connectionConfigured:false,retentionDays:365},
  {id:'northstar',name:'Northstar Studio',disabled:false,clientIds:[],auditReaders:[],enterpriseProvider:'google_workspace',entraTenantId:null,googleWorkspaceDomains:['northstar.example'],oidcClientId:null,clientSecretBinding:null,connectionConfigured:false,retentionDays:null}
];
let users = [
  {id:'usr_morgan',displayName:'Morgan Chen',email:'morgan@acme.example',disabled:false,admin:true,identityCount:1,activeSessionCount:2,createdAt:1793750400,updatedAt:1793871000,tenant:'acme'},
  {id:'usr_samira',displayName:'Samira Patel',email:'samira@acme.example',disabled:false,admin:false,identityCount:1,activeSessionCount:1,createdAt:1793750400,updatedAt:1793871000,tenant:'acme'},
  {id:'usr_alex',displayName:'Alex Rivera',email:'alex@northstar.example',disabled:true,admin:false,identityCount:1,activeSessionCount:0,createdAt:1793750400,updatedAt:1793871000,tenant:'northstar'}
];
const client = {id:'acme-portal',name:'Acme employee portal',confidential:true,hasSecret:true,disabled:false,redirectUris:['https://portal.acme.example/callback'],allowedOrigins:['https://portal.acme.example'],allowedEmailDomains:['acme.example'],enterpriseProvider:'entra',accountSharingMode:'tenant',accountTenantId:'acme',accountNamespace:'tenant:acme',visibleLoginMethods:[]};
const events = [
  {id:'evt_09',eventType:'tenant.update',recordedAt:1793871000,actorId:'usr_morgan',actorType:'user',organizationId:'acme',targetId:'acme',outcome:'success',requestId:'req_32',details:{changedFields:['name','auditReaders']}},
  {id:'evt_08',eventType:'authorization.denied',recordedAt:1793870900,actorId:'usr_alex',actorType:'user',organizationId:'northstar',clientId:'northstar-app',outcome:'denied',reasonCode:'enterprise_identity_required',details:{policy:'corporate_users_only'}},
  {id:'evt_07',eventType:'session.login',recordedAt:1793870800,actorId:'usr_samira',actorType:'user',organizationId:'acme',clientId:'acme-portal',outcome:'success',details:{provider:'entra'}},
  {id:'evt_06',eventType:'legacy.event',createdAt:1793750400,outcome:'unknown',details:{note:'<img src=x onerror=alert(1)>'}}
];
const scim = {tenantId:'acme',enabled:false,tokenBinding:null,credentialsConfigured:false,endpoint:'https://id.example.com/scim/v2/acme',managedUsers:0,activeUsers:0,lastActivityAt:null};
const directory = {tenantId:'northstar',enabled:false,customerId:null,customerIdLocked:false,delegatedAdminEmail:null,serviceAccountSecretBinding:null,credentialsConfigured:false,managedEnforced:false,stale:false,staleAfterSeconds:900,lastAttemptAt:null,lastSuccessAt:null,lastErrorCode:null,lastSeenCount:null,lastDeactivatedCount:null,syncIntervalSeconds:300,nextSyncAt:null};
let failDirectorySync = false;
let delayScimRead = false;
let releaseDelayedScim = null;
const requests = [];
const server = http.createServer(async (req,res) => {
  const url = new URL(req.url, 'http://fixture');
  if (url.pathname === '/admin/tenants' || url.pathname === '/') {res.writeHead(200,{'Content-Type':'text/html'});return res.end(html);}
  if (url.pathname === '/admin/setup') {res.writeHead(200,{'Content-Type':'text/html'});return res.end(fs.readFileSync(path.resolve(__dirname,'../../../docs/enterprise-admin-setup.html'),'utf8'));}
  if (url.pathname === '/profile-menu.js') {res.writeHead(200,{'Content-Type':'text/javascript'});return res.end('');}
  if (url.pathname === '/favicon.svg') {res.writeHead(204);return res.end();}
  let payload = null;
  if (['POST','PATCH'].includes(req.method)) {
    let raw='';for await (const chunk of req) raw+=chunk;
    payload=JSON.parse(raw); assert.equal(req.headers['x-zeroth-csrf'],'preview-csrf');
  }
  requests.push({method:req.method,path:url.pathname,query:new URLSearchParams(url.search),payload});
  let body={};
  if (url.pathname === '/tenants') {
    if (payload) { const existing=tenants.findIndex(t=>t.id===payload.id); const next={...payload,connectionConfigured:false}; if(existing<0)tenants.push(next);else tenants[existing]=next; }
    body={tenants};
  } else if (url.pathname === '/tenants/provisioning') {
    if (payload) { assert.equal(payload.tenantId,url.searchParams.get('tenant_id'));Object.assign(scim,payload); }
    if (delayScimRead && !payload) await new Promise(resolve=>{releaseDelayedScim=resolve;});
    body=scim;
  } else if (url.pathname === '/tenants/google-directory-config') {
    Object.assign(directory,payload);directory.credentialsConfigured=Boolean(payload.serviceAccountSecretBinding);directory.managedEnforced ||= payload.enabled;directory.stale=directory.managedEnforced&&!directory.lastSuccessAt;body=directory;
  } else if (url.pathname === '/tenants/google-directory-sync') {
    assert.equal(payload.tenantId,'northstar');await new Promise(resolve=>setTimeout(resolve,200));
    directory.lastAttemptAt=1793871300;
    if(failDirectorySync){directory.lastErrorCode='directory_upstream_failed';res.writeHead(502,{'Content-Type':'application/json'});return res.end(JSON.stringify({error:'directory_sync_failed',error_description:'directory_upstream_failed'}));}
    Object.assign(directory,{lastSuccessAt:1793871300,lastErrorCode:null,lastSeenCount:3,lastDeactivatedCount:1,customerIdLocked:true,stale:false,nextSyncAt:1793871600});body=directory;
  } else if (url.pathname === '/tenants/google-directory') body=directory;
  else if (url.pathname === '/users') {
    const id=url.searchParams.get('user_id');
    if (payload) { const user=users.find(u=>u.id===id);Object.assign(user,payload);if(payload.disabled)user.activeSessionCount=0; }
    if (id) body={user:users.find(u=>u.id===id),identities:[{providerId:'entra',email:'samira@acme.example',emailVerified:true}],activeSessions:[{clientId:'acme-portal',expiresAt:1793956800}]};
    else {const tenant=url.searchParams.get('tenant_id');body={users:users.filter(u=>!tenant||u.tenant===tenant).map(u=>tenant?{...u,tenantAccess:{state:u.id==='usr_morgan'?'inactive':'active',source:'entra',updatedAt:1793871000,lastSyncAt:null,managed:true}}:u)};}
  } else if (url.pathname === '/events') {
    if (url.searchParams.get('format') === 'csv') {res.writeHead(200,{'Content-Type':'text/csv','Content-Disposition':'attachment; filename="zeroth-audit-events.csv"'});return res.end('id,event_type\r\nevt_06,legacy.event\r\n');}
    const scoped=events.filter(e=>!url.searchParams.get('organization_id')||e.organizationId===url.searchParams.get('organization_id'));
    const older=url.searchParams.has('cursor');body={events:older?scoped.slice(2):scoped.slice(0,2),hasMore:!older&&scoped.length>2,nextCursor:!older&&scoped.length>2?'older-fixture':undefined};
  } else if (url.pathname === '/clients') body={clients:[client]};
  else if (url.pathname === '/providers/status') body={providers:[{id:'entra',label:'Microsoft Entra',kind:'oidc',enabled:false,clientIdConfigured:false,clientSecretConfigured:false,notes:['Awaiting deployment credentials'],activationRequirements:[],callbackUrl:'https://id.example.com/oauth2/callback',clientIdBinding:'ENTRA_CLIENT_ID',secretBindingSets:[['ENTRA_CLIENT_SECRET']]}]};
  else if (url.pathname === '/local-auth/status') body={methods:[]};
  else if (url.pathname === '/__zeroth/db/status') body={ok:true,clientCount:1,tables:[],migrations:[],compatibilityColumns:[]};
  else {res.writeHead(404);return res.end();}
  res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify(body));
});
(async () => {
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const browser=await chromium.launch({headless:true,...(process.env.CHROMIUM_EXECUTABLE?{executablePath:process.env.CHROMIUM_EXECUTABLE}:{}),args:['--no-sandbox']});
  try {
    const base=`http://127.0.0.1:${server.address().port}`;
    const page=await browser.newPage({viewport:{width:1536,height:1080}});
    const errors=[];page.on('pageerror',error=>errors.push(error.message));
    await page.goto(`${base}/admin/tenants`);
    await page.locator('#zeroth-tenant-rows tr').filter({hasText:'Acme Corporation'}).waitFor();
    await page.screenshot({path:path.join(output,'tenants-desktop.png'),fullPage:true});
    await page.locator('[data-zeroth-edit-tenant]').first().click();
    assert.equal(await page.locator('#zeroth-tenant-id').isDisabled(),true);
    await page.locator('#zeroth-scim-panel').waitFor({state:'visible'});
    assert.equal(await page.locator('#zeroth-scim-endpoint').inputValue(),'https://id.example.com/scim/v2/acme');
    assert.match(await page.locator('#zeroth-scim-status').textContent(),/Awaiting deployment token/);
    await page.locator('#zeroth-scim-binding').fill('pasted-token-value');
    const scimBefore=requests.filter(r=>r.path==='/tenants/provisioning'&&r.method==='POST').length;
    await page.locator('#zeroth-scim-form button[type=submit]').click();
    await page.locator('#zeroth-admin-message').filter({hasText:'Never paste a token value'}).waitFor();
    assert.equal(requests.filter(r=>r.path==='/tenants/provisioning'&&r.method==='POST').length,scimBefore);
    await page.locator('#zeroth-scim-binding').fill('TENANT_ACME_SCIM_TOKEN');await page.locator('#zeroth-scim-form [name=enabled]').check();
    page.once('dialog',dialog=>{assert.match(dialog.message(),/grants will be revoked/);dialog.accept();});
    await page.locator('#zeroth-scim-form button[type=submit]').click();
    await page.waitForFunction(()=>document.querySelector('#zeroth-scim-form button[type=submit]').disabled===false&&document.querySelector('#zeroth-scim-form [name=enabled]').checked);
    const scimSaved=requests.findLast(r=>r.path==='/tenants/provisioning'&&r.method==='POST').payload;
    assert.deepEqual(scimSaved,{tenantId:'acme',enabled:true,tokenBinding:'TENANT_ACME_SCIM_TOKEN'});
    assert.match(await page.locator('#zeroth-scim-status').textContent(),/Awaiting deployment token/);
    assert.match(await page.locator('#zeroth-provisioning-policy').textContent(),/active provisioned/);
    await page.locator('nav a[href="#users"]').click();await page.locator('nav a[href="#tenants"]').click();
    await page.locator('#zeroth-provisioning').screenshot({path:path.join(output,'provisioning-scim-desktop.png')});
    assert.equal(await page.locator('#zeroth-tenant-clients').inputValue(),'acme-portal');
    assert.match(await page.locator('#zeroth-tenant-connection-status').textContent(),/Awaiting/);
    await page.screenshot({path:path.join(output,'tenant-editor-desktop.png'),fullPage:true});
    await page.locator('#zeroth-tenant-client-picker').selectOption('acme-portal');
    await page.locator('#zeroth-tenant-add-client').click();
    assert.equal(await page.locator('#zeroth-tenant-clients').inputValue(),'acme-portal');
    const tenantWrites=requests.filter(r=>r.method==='POST').length;
    await page.locator('#zeroth-tenant-secret-binding').fill('not-a-binding');
    await page.locator('#zeroth-tenant-form button[type=submit]').click();
    await page.locator('#zeroth-admin-message').filter({hasText:'Do not paste a secret value'}).waitFor();
    assert.equal(requests.filter(r=>r.method==='POST').length,tenantWrites);
    await page.locator('#zeroth-tenant-secret-binding').fill('');
    await page.locator('#zeroth-tenant-name').fill('Acme Operations');
    await page.locator('#zeroth-tenant-form button[type=submit]').click();
    await page.waitForFunction(()=>document.getElementById('zeroth-tenant-editor').hidden);
    const saved=requests.findLast(r=>r.method==='POST'&&r.path==='/tenants').payload;
    assert.equal(saved.name,'Acme Operations');assert.deepEqual(saved.clientIds,['acme-portal']);assert.deepEqual(saved.auditReaders,[{userId:'usr_morgan',canExport:true}]);
    assert.equal(saved.oidcClientId,null);assert.equal(saved.clientSecretBinding,null);
    await page.locator('#zeroth-tenant-new').click();
    await page.locator('#zeroth-tenant-id').fill('draft');await page.locator('#zeroth-tenant-name').fill('Draft organization');
    await page.locator('#zeroth-tenant-provider').selectOption('google_workspace');
    assert.equal(await page.locator('#zeroth-tenant-domains').isVisible(),true);assert.equal(await page.locator('#zeroth-tenant-entra').isVisible(),false);
    await page.locator('#zeroth-tenant-domains').fill('draft.example');await page.locator('#zeroth-tenant-form button[type=submit]').click();
    await page.waitForFunction(()=>document.getElementById('zeroth-tenant-editor').hidden);
    assert.equal(requests.findLast(r=>r.method==='POST').payload.enterpriseProvider,'google_workspace');
    await page.locator('#zeroth-tenant-rows tr').filter({hasText:'Northstar Studio'}).locator('[data-zeroth-edit-tenant]').click();
    await page.locator('#zeroth-google-directory-panel').waitFor({state:'visible'});
    await page.locator('#zeroth-directory-customer').fill('C01234567');
    await page.locator('#zeroth-directory-admin').fill('superadmin@northstar.example');
    const directoryWrites=requests.filter(r=>r.path==='/tenants/google-directory-config'&&r.method==='POST').length;
    await page.locator('#zeroth-directory-binding').fill('{"private_key":"fixture-value-must-not-leave-browser"}');
    await page.locator('#zeroth-google-directory-form button[type=submit]').click();
    await page.locator('#zeroth-admin-message').filter({hasText:'Never paste the JSON key'}).waitFor();
    assert.equal(requests.filter(r=>r.path==='/tenants/google-directory-config'&&r.method==='POST').length,directoryWrites);
    await page.locator('#zeroth-directory-binding').fill('TENANT_NORTHSTAR_GOOGLE_DIRECTORY_SERVICE_ACCOUNT');
    await page.locator('#zeroth-google-directory-form [name=enabled]').check();
    page.once('dialog',dialog=>{assert.match(dialog.message(),/Managed access becomes permanent/);dialog.accept();});
    await page.locator('#zeroth-google-directory-form button[type=submit]').click();
    await page.waitForFunction(()=>document.getElementById('zeroth-directory-sync').disabled===false);
    assert.match(await page.locator('#zeroth-google-directory-status').textContent(),/Stale/);
    page.once('dialog',dialog=>dialog.accept());await page.locator('#zeroth-directory-sync').click();
    assert.equal(await page.locator('#zeroth-directory-sync').isDisabled(),true);
    await page.locator('#zeroth-provisioning-intro').filter({hasText:'Directory sync completed'}).waitFor();
    assert.equal(await page.locator('#zeroth-directory-customer').getAttribute('readonly'),'');
    assert.match(await page.locator('#zeroth-google-directory-status').textContent(),/Fresh.*completed sync recorded/);
    await page.locator('nav a[href="#users"]').click();await page.locator('nav a[href="#tenants"]').click();
    await page.locator('#zeroth-provisioning').screenshot({path:path.join(output,'provisioning-directory-desktop.png')});
    failDirectorySync=true;
    page.once('dialog',dialog=>dialog.accept());await page.locator('#zeroth-directory-sync').click();
    await page.locator('#zeroth-admin-message').filter({hasText:'Directory sync failed'}).waitFor();
    assert.equal(directory.lastSuccessAt,1793871300);
    assert.match(await page.locator('#zeroth-google-directory-status').textContent(),/directory_upstream_failed/);
    delayScimRead=true;
    const delayedRead=page.waitForRequest(request=>new URL(request.url()).pathname==='/tenants/provisioning');
    await page.locator('#zeroth-tenant-rows tr').filter({hasText:'Acme Operations'}).locator('[data-zeroth-edit-tenant]').click();await delayedRead;
    await page.locator('#zeroth-tenant-rows tr').filter({hasText:'Northstar Studio'}).locator('[data-zeroth-edit-tenant]').click();
    await page.locator('#zeroth-google-directory-panel').waitFor({state:'visible'});
    const lateResponse=page.waitForResponse(response=>new URL(response.url()).pathname==='/tenants/provisioning');releaseDelayedScim();
    await (await lateResponse).finished();await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
    assert.equal(await page.locator('#zeroth-scim-panel').isVisible(),false);
    assert.equal(await page.locator('#zeroth-directory-admin').inputValue(),'superadmin@northstar.example');
    delayScimRead=false;
    await page.locator('nav a[href="#users"]').click();
    await page.locator('#zeroth-user-search').fill('samira');await page.waitForFunction(()=>document.querySelectorAll('#zeroth-user-rows tr').length===1);
    await page.locator('[data-zeroth-view-user]').click();await page.locator('#zeroth-user-detail-body').filter({hasText:'Linked identities (1)'}).waitFor();
    await page.locator('#zeroth-user-detail button').click();
    const before=requests.filter(r=>r.method==='PATCH').length;
    page.once('dialog',dialog=>dialog.dismiss());await page.locator('[data-zeroth-toggle-user]').click();
    assert.equal(requests.filter(r=>r.method==='PATCH').length,before);
    page.once('dialog',dialog=>{assert.match(dialog.message(),/sessions and refresh tokens/);dialog.accept();});
    await page.locator('[data-zeroth-toggle-user]').click();await page.waitForFunction(()=>document.querySelector('#zeroth-user-rows tr').dataset.userDisabled==='true');
    const afterDisable=requests.filter(r=>r.method==='PATCH').length;
    page.once('dialog',dialog=>{assert.match(dialog.message(),/entire Zeroth deployment/);dialog.dismiss();});
    await page.locator('[data-zeroth-toggle-admin]').click();
    assert.equal(requests.filter(r=>r.method==='PATCH').length,afterDisable);
    await page.locator('#zeroth-user-search').fill('');await page.locator('#zeroth-user-status-filter').selectOption('');
    await page.locator('#zeroth-user-tenant').selectOption('acme');await page.waitForFunction(()=>document.querySelectorAll('#zeroth-user-rows tr').length===2);
    const scopedMorgan=page.locator('#zeroth-user-rows tr[data-user-id="usr_morgan"]');
    assert.equal(await scopedMorgan.getAttribute('data-user-disabled'),'false');
    assert.match(await scopedMorgan.textContent(),/Account active.*Tenant: Inactive.*access denied/s);
    await page.locator('#zeroth-user-tenant-access').selectOption('inactive');
    await page.waitForFunction(()=>document.querySelectorAll('#zeroth-user-rows tr').length===1);
    assert.equal(await page.locator('#zeroth-user-rows tr').getAttribute('data-user-id'),'usr_morgan');
    await page.locator('#zeroth-user-tenant-access').selectOption('');
    await page.screenshot({path:path.join(output,'users-desktop.png'),fullPage:true});
    await page.locator('nav a[href="#events"]').click();
    await page.locator('#zeroth-events-next').click();await page.waitForFunction(()=>document.getElementById('zeroth-events-page-status').textContent.includes('Page 2'));
    await page.locator('#zeroth-event-rows details').last().locator('summary').click();
    assert.match(await page.locator('#zeroth-event-rows pre').last().textContent(),/<img src=x/);
    assert.equal(await page.locator('#zeroth-event-rows img').count(),0);
    await page.locator('#zeroth-event-org-filter').fill('unapplied-draft');
    const downloadPromise=page.waitForEvent('download');await page.locator('#zeroth-events-export').click();const download=await downloadPromise;
    assert.equal(download.suggestedFilename(),'zeroth-audit-events.csv');
    const exported=requests.findLast(r=>r.path==='/events'&&r.query.get('format')==='csv');assert.equal(exported.query.has('organization_id'),false);assert.equal(exported.query.get('cursor'),'older-fixture');
    await page.locator('#zeroth-events-filter-reset').click();await page.waitForFunction(()=>document.getElementById('zeroth-events-page-status').textContent.includes('Page 1'));
    await page.screenshot({path:path.join(output,'audit-desktop.png'),fullPage:true});
    assert.equal(await page.locator('#zeroth-event-rows img').count(),0);
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
    await page.setViewportSize({width:390,height:844});
    for (const [hash,name] of [['tenants','tenants-mobile.png'],['users','users-mobile.png'],['events','audit-mobile.png']]) {
      await page.locator(`nav a[href="#${hash}"]`).click();
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,hash);
      await page.screenshot({path:path.join(output,name),fullPage:true});
    }
    await page.locator('nav a[href="#tenants"]').click();await page.locator('[data-zeroth-edit-tenant]').first().click();
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'tenant editor');
    await page.screenshot({path:path.join(output,'tenant-editor-mobile.png'),fullPage:true});
    await page.locator('#zeroth-scim-panel').waitFor({state:'visible'});
    await page.locator('#zeroth-provisioning').screenshot({path:path.join(output,'provisioning-scim-mobile.png')});
    await page.locator('#zeroth-tenant-rows tr').filter({hasText:'Northstar Studio'}).locator('[data-zeroth-edit-tenant]').click();
    await page.locator('#zeroth-google-directory-panel').waitFor({state:'visible'});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'Directory form');
    await page.locator('#zeroth-provisioning').screenshot({path:path.join(output,'provisioning-directory-mobile.png')});
    await page.goto(`${base}/admin/setup`);
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'setup guide');
    assert.match(await page.locator('body').textContent(),/customer-owned Entra tenant and application are sufficient/);
    await page.screenshot({path:path.join(output,'provisioning-guide-mobile.png'),fullPage:true});
    assert.deepEqual(errors,[]);
    console.log('Passed: tenant/user/audit workflows; provisioning binding-only config, managed-mode confirmation, CSRF, Directory sync success/failure and immutable pin, tenant-switch race isolation, safe text, desktop/mobile layouts.');
  } finally {await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);server.close();process.exitCode=1;});
