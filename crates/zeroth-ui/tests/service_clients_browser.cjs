// Render `cargo run -p zeroth-ui --example admin_preview -- service-clients` first.
// This exercises the real admin script against a local management API fixture.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const html = fs.readFileSync(process.argv[2] || '/tmp/zeroth-service-clients-admin.html', 'utf8');
const output = process.env.SCREENSHOT_DIR || '/tmp/zeroth-service-clients-screenshots';
fs.mkdirSync(output, {recursive:true});
const publicKey = kid => ({...crypto.generateKeyPairSync('ec', {namedCurve:'prime256v1'}).publicKey.export({format:'jwk'}), kid, alg:'ES256', use:'sig'});
const tenants = [{id:'acme',name:'Acme Corporation',disabled:false,clientIds:[],auditReaders:[]},{id:'northstar',name:'Northstar Studio',disabled:false,clientIds:[],auditReaders:[]}];
let clients = [{id:'svc_release_agent',tenantId:'acme',name:'Acme release agent',audiences:['https://releases.example.com'],scopes:['releases:read','rollouts:report'],publicJwks:{keys:[publicKey('release-2026-11')]},disabled:false,revision:2,tokenTtlSeconds:600,createdAt:1793836800,updatedAt:1793871000}];
const posts = [];
let failNextSave = false;
let failNextRead = false;
let delayAcme = false;
let releaseAcme = null;
const json = (res, status, body) => {res.writeHead(status, {'Content-Type':'application/json'}); res.end(JSON.stringify(body));};
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://fixture');
    if (url.pathname === '/admin/service-clients') {res.writeHead(200, {'Content-Type':'text/html'}); return res.end(html);}
    if (url.pathname === '/profile-menu.js' || url.pathname === '/favicon.svg') {res.writeHead(204); return res.end();}
    if (url.pathname === '/service-clients') {
      if (req.method === 'POST') {
        let raw = ''; for await (const chunk of req) raw += chunk;
        assert.equal(req.headers['x-zeroth-csrf'], 'preview-csrf');
        assert.equal(raw.includes('DO_NOT_SEND_PRIVATE_MATERIAL'), false);
        const payload = JSON.parse(raw); posts.push(payload);
        if (failNextSave) {failNextSave = false; return json(res, 503, {error:'audit_unavailable',error_description:'Audit capture unavailable; no changes were saved.'});}
        const old = clients.find(item => item.id === payload.id);
        if (old && old.revision !== payload.expectedRevision) return json(res, 409, {error:'revision_conflict',error_description:'The service client changed. Refresh and reopen it before saving.'});
        if (old) assert.equal(payload.tenantId, old.tenantId);
        const next = {...payload,revision:old ? old.revision + 1 : 1}; delete next.expectedRevision;
        clients = [...clients.filter(item => item.id !== next.id),next];
        return json(res, 200, {serviceClient:next});
      }
      if (failNextRead) {failNextRead = false; return json(res, 503, {error:'temporarily_unavailable'});}
      const tenant = url.searchParams.get('tenant_id');
      const result = clients.filter(item => !tenant || item.tenantId === tenant);
      if (delayAcme && tenant === 'acme') await new Promise(resolve => {releaseAcme = resolve;});
      return json(res, 200, {serviceClients:result});
    }
    if (url.pathname === '/tenants') return json(res, 200, {tenants});
    if (url.pathname === '/__zeroth/db/status') return json(res, 200, {ok:true,tables:[],migrations:[],compatibilityColumns:[]});
    if (url.pathname === '/providers/status') return json(res, 200, {providers:[]});
    if (url.pathname === '/local-auth/status') return json(res, 200, {methods:[]});
    if (url.pathname === '/events') return json(res, 200, {events:[],hasMore:false});
    if (url.pathname === '/clients') return json(res, 200, {clients:[]});
    if (url.pathname === '/users') return json(res, 200, {users:[]});
    return json(res, 404, {error:'not_found'});
  } catch (error) {json(res, 500, {error:'fixture_error',error_description:error.message});}
});

(async () => {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const browser = await chromium.launch({headless:true,...(process.env.CHROMIUM_EXECUTABLE ? {executablePath:process.env.CHROMIUM_EXECUTABLE} : {}),args:['--no-sandbox']});
  try {
    const page = await browser.newPage({viewport:{width:1536,height:1080}});
    const errors = []; page.on('pageerror', error => errors.push(error.message));
    const base = `http://127.0.0.1:${server.address().port}`;
    await page.goto(`${base}/admin/service-clients`);
    await page.locator('#zeroth-service-summary').filter({hasText:'1 service client'}).waitFor();
    assert.equal(await page.locator('#zeroth-page-title').textContent(), 'Service clients');
    assert.equal(await page.locator('#service-clients').isVisible(), true);
    assert.equal(await page.locator('#clients').isVisible(), false);
    await page.screenshot({path:path.join(output,'service-clients-desktop.png'),fullPage:true});

    await page.locator('#zeroth-service-new').click();
    await page.locator('#zeroth-service-id').fill('svc_directory_agent');
    await page.locator('#zeroth-service-name').fill('Northstar directory agent');
    await page.locator('#zeroth-service-tenant').selectOption('northstar');
    await page.locator('#zeroth-service-audiences').fill('https://directory.example.com');
    await page.locator('#zeroth-service-scopes').fill('directory:read');
    const key = publicKey('directory-current');
    await page.locator('#zeroth-service-jwks').fill(JSON.stringify({keys:[{...key,d:'DO_NOT_SEND_PRIVATE_MATERIAL'}]}));
    await page.locator('#zeroth-service-save').click();
    await page.locator('#zeroth-admin-message').filter({hasText:'Private key material was removed'}).waitFor();
    assert.equal(posts.length, 0);
    assert.equal(await page.locator('#zeroth-service-jwks').inputValue(), '');
    await page.locator('#zeroth-service-jwks').fill(JSON.stringify({keys:[key]}));
    await page.locator('#zeroth-service-scopes').fill('openid');
    await page.locator('#zeroth-service-save').click();
    await page.locator('#zeroth-admin-message').filter({hasText:'reserved privilege scopes'}).waitFor();
    assert.equal(posts.length, 0);
    await page.locator('#zeroth-service-scopes').fill('directory:read');
    await page.locator('#zeroth-service-save').click();
    await page.locator('#zeroth-service-rows tr[data-service-client-id="svc_directory_agent"]').waitFor();
    assert.equal(posts[0].expectedRevision, undefined);
    assert.equal(posts[0].tokenTtlSeconds, 600);
    assert.equal(posts[0].tenantId, 'northstar');
    assert.equal(posts[0].publicJwks.keys[0].kid, 'directory-current');

    const row = () => page.locator('#zeroth-service-rows tr[data-service-client-id="svc_directory_agent"]');
    await row().locator('[data-zeroth-edit-service]').click();
    assert.equal(await page.locator('#zeroth-service-id').isDisabled(), true);
    assert.equal(await page.locator('#zeroth-service-tenant').isDisabled(), true);
    const rotated = {keys:[key,publicKey('directory-next')]};
    await page.locator('#zeroth-service-jwks').fill(JSON.stringify(rotated));
    await page.locator('#zeroth-service-name').fill('<img src=x onerror=alert(1)>');
    page.once('dialog', dialog => dialog.accept());
    await page.locator('#zeroth-service-save').click();
    await row().filter({hasText:'Revision 2'}).waitFor();
    assert.equal(posts[1].expectedRevision, 1);
    assert.equal(posts[1].publicJwks.keys.length, 2);
    assert.equal(await page.locator('#zeroth-service-rows img').count(), 0);

    // Concurrent administrator updates cannot overwrite a newer key revision.
    await row().locator('[data-zeroth-edit-service]').click();
    clients.find(item => item.id === 'svc_directory_agent').revision += 1;
    page.once('dialog', dialog => dialog.accept());
    await page.locator('#zeroth-service-save').click();
    await page.locator('#zeroth-admin-message').filter({hasText:'Refresh and reopen'}).waitFor();
    assert.equal(await page.locator('#zeroth-service-editor').isVisible(), true);
    assert.equal(posts.at(-1).expectedRevision, 2);
    await page.locator('#zeroth-service-close').click();
    await page.locator('#zeroth-services-refresh').click();
    await row().filter({hasText:'Revision 3'}).waitFor();

    // A failed save keeps the editor and does not claim a successful mutation.
    await row().locator('[data-zeroth-edit-service]').click();
    failNextSave = true;
    page.once('dialog', dialog => dialog.accept());
    await page.locator('#zeroth-service-save').click();
    await page.locator('#zeroth-admin-message').filter({hasText:'no changes were saved'}).waitFor();
    assert.equal(await page.locator('#zeroth-service-editor').isVisible(), true);
    assert.equal(clients.find(item => item.id === 'svc_directory_agent').revision, 3);
    assert.equal(await page.locator('#zeroth-service-save').isDisabled(), false);

    const beforeRevoke = posts.length;
    page.once('dialog', dialog => dialog.dismiss());
    await page.locator('#zeroth-service-revoke').click();
    assert.equal(posts.length, beforeRevoke);
    page.once('dialog', dialog => {assert.match(dialog.message(), /offline JWTs/); dialog.accept();});
    await page.locator('#zeroth-service-revoke').click();
    await row().filter({hasText:'Revision 4'}).waitFor();
    assert.equal(posts.at(-1).expectedRevision, 3);
    assert.equal(posts.at(-1).disabled, false);
    page.once('dialog', dialog => dialog.accept());
    await row().locator('[data-zeroth-toggle-service]').click();
    await row().filter({hasText:'Disabled'}).waitFor();
    assert.equal(posts.at(-1).disabled, true);
    assert.equal(posts.at(-1).expectedRevision, 4);

    // Late responses for a previous tenant cannot replace the selected scope.
    delayAcme = true;
    await page.locator('#zeroth-service-tenant-filter').selectOption('acme');
    await page.waitForFunction(() => document.getElementById('zeroth-service-summary').textContent.includes('Loading'));
    await page.locator('#zeroth-service-tenant-filter').selectOption('northstar');
    await row().waitFor();
    while (!releaseAcme) await new Promise(resolve => setTimeout(resolve,10));
    const late = page.waitForResponse(response => new URL(response.url()).searchParams.get('tenant_id') === 'acme');
    releaseAcme(); await (await late).finished();
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert.equal(await page.locator('#zeroth-service-rows tr[data-service-client-id="svc_release_agent"]').count(), 0);
    assert.match(await page.locator('#zeroth-service-summary').textContent(), /tenant northstar/);

    clients.find(item => item.id === 'svc_directory_agent').name = 'Northstar directory agent';
    await page.locator('#zeroth-services-refresh').click();
    await row().filter({hasText:'Northstar directory agent'}).waitFor();
    await page.setViewportSize({width:390,height:844});
    await row().locator('[data-zeroth-edit-service]').click();
    await page.screenshot({path:path.join(output,'service-clients-mobile.png'),fullPage:true});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
    assert.equal(await page.locator('#zeroth-service-jwks').isVisible(), true);
    await page.locator('#zeroth-service-close').click();
    failNextRead = true;
    await page.locator('#zeroth-services-refresh').click();
    await page.locator('#zeroth-service-summary').filter({hasText:'Could not load service clients'}).waitFor();
    assert.equal(await page.locator('#zeroth-service-rows button').count(), 0);
    clients = [];
    await page.locator('#zeroth-services-refresh').click();
    await page.locator('#zeroth-service-rows').filter({hasText:'No service clients for this tenant'}).waitFor();
    assert.deepEqual(errors, []);
    console.log('Service client browser checks passed: public-only keys, scoped registration, rotation, revision conflict, failed save, revocation, disable, late responses, empty/error states, mobile overflow.');
  } finally {await browser.close(); await new Promise(resolve => server.close(resolve));}
})().catch(error => {console.error(error); server.close(); process.exitCode = 1;});
