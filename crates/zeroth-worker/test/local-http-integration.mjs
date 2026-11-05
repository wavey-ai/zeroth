/**
 * Real workers-rs + local workerd/D1 integration. No routes or auth bypasses
 * are added to the Worker. Everything written is synthetic and isolated under
 * a new private temporary directory. No Cloudflare account is contacted.
 *
 * Requires worker-build (matching workers-rs), wasm-bindgen (matching Cargo.lock),
 * Wrangler and Python3. See README for pinned local-tool installation.
 */
import assert from 'node:assert/strict';
import {createHash, createHmac, createPublicKey, generateKeyPairSync, randomBytes, verify} from 'node:crypto';
import {spawn, spawnSync} from 'node:child_process';
import {mkdtempSync, readFileSync, readdirSync, writeFileSync, chmodSync, existsSync, openSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import net from 'node:net';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';

const startedAt = Date.now();
const timings = {};
const workerDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repo = path.resolve(workerDir, '../..');
const scratch = mkdtempSync(path.join(tmpdir(), 'zeroth-http-integration-'));
chmodSync(scratch, 0o700);
const stateDir = path.join(scratch, 'state');
const configPath = path.join(scratch, 'wrangler.json');
const wrangler = process.env.WRANGLER_BIN || 'wrangler';
const builder = process.env.WORKER_BUILD_BIN || 'worker-build';
const bindgen = process.env.WASM_BINDGEN_BIN || 'wasm-bindgen';
const buildDir = path.join(scratch, 'build');
const generated = process.env.WORKER_ENTRY || path.join(buildDir, 'index.js');
let now = Math.floor(Date.now() / 1000);
const secret = () => randomBytes(32).toString('base64url');
const adminSid = `sess_${secret()}`;
const aSid = `sess_${secret()}`;
const bSid = `sess_${secret()}`;
const aRefresh = secret();
let bRefresh = secret();
const aCode = secret();
const aAppState = secret();
const bAppState = secret();
const verifier = secret();
const csrfSecret = secret();
const privateJwk = generateKeyPairSync('ec', {namedCurve:'prime256v1'}).privateKey.export({format:'jwk'});
const credentials = {
  JWT_ES256_PRIVATE_KEY:JSON.stringify(privateJwk), JWT_KEY_ID:'local-http-only',
  CSRF_SECRET:csrfSecret, RATE_LIMIT_KEY:secret(), AUDIT_STREAM_TOKEN:secret(),
  TENANT_ALPHA_SCIM_TOKEN:secret(), TENANT_BETA_SCIM_TOKEN:secret(),
  TENANT_ALPHA_CLIENT_SECRET:secret(), TENANT_BETA_CLIENT_SECRET:secret()
};
const forbidden = [...Object.values(credentials).filter(value=>value.length>24), privateJwk.d, aRefresh, bRefresh, aCode, aAppState, bAppState];
const redact = (text) => [...forbidden,adminSid,aSid,bSid].reduce((value, token)=>value.replaceAll(token,'[synthetic credential]'),String(text));
const allowedEnvironment = new Set(['PATH','HOME','USER','LANG','LC_ALL','SHELL','TMPDIR','TEMP','TMP','CARGO_HOME','RUSTUP_HOME','RUSTUP_TOOLCHAIN','RUSTFLAGS','RUSTDOCFLAGS','SSL_CERT_FILE','SSL_CERT_DIR','HTTPS_PROXY','HTTP_PROXY','NO_PROXY','WASM_BINDGEN_BIN','ESBUILD_BIN']);
const safeEnv = Object.fromEntries(Object.entries(process.env).filter(([key])=>allowedEnvironment.has(key)));
Object.assign(safeEnv,{WRANGLER_SEND_METRICS:'false',CI:'true',NO_COLOR:'1'});
if (process.env.WASM_BINDGEN_BIN) safeEnv.PATH = `${path.dirname(bindgen)}${path.delimiter}${safeEnv.PATH || ''}`;
let server;
let databasePath;
let checks = 0;
function check(label, action) { action(); checks += 1; console.log(`ok ${checks} - ${label}`); }
function run(program,args,options={}) {
  const result=spawnSync(program,args,{cwd:scratch,env:safeEnv,encoding:'utf8',maxBuffer:32*1024*1024,...options});
  if(result.error||result.status!==0) throw new Error(`${path.basename(program)} failed: ${redact(result.error?.message || result.stderr || result.stdout)}`);
  return result.stdout;
}
function ensureNoCredentials(text) {
  if(forbidden.some(value=>text.includes(value))) throw new Error('A response or persisted audit envelope exposed synthetic credential material');
}
function sql(statements) {
  const source = `import sys,json,sqlite3\nconn=sqlite3.connect(sys.argv[1],timeout=10)\nconn.row_factory=sqlite3.Row\nconn.execute('PRAGMA foreign_keys=ON')\nresult=[]\nfor statement in json.load(sys.stdin):\n cursor=conn.execute(statement['sql'],statement.get('params',[]))\n result.append([dict(row) for row in cursor.fetchall()] if cursor.description else [])\nconn.commit()\nprint(json.dumps(result))\n`;
  return JSON.parse(run('python3',['-c',source,databasePath],{input:JSON.stringify(statements)}));
}
function one(query,params=[]) {return sql([{sql:query,params}])[0][0];}
function findDatabase(directory) {
  for(const entry of readdirSync(directory,{withFileTypes:true})) {
    const item=path.join(directory,entry.name);
    if(entry.isDirectory()) {const found=findDatabase(item);if(found)return found;}
    else if(entry.name.endsWith('.sqlite')) return item;
  }
}
function sha(value) {return createHash('sha256').update(value).digest('hex');}
function policyHash(tenant) {
  return sha(JSON.stringify(['zeroth-enterprise-policy-v1','entra',tenant.app,{kind:'entra',tenant_id:tenant.authority}]));
}
const tenants = [
  {id:'alpha',client:'app-alpha',authority:'11111111-1111-4111-8111-111111111111',app:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',oid:'10000000-0000-4000-8000-000000000001',sid:aSid,refresh:aRefresh,state:aAppState},
  {id:'beta',client:'app-beta',authority:'22222222-2222-4222-8222-222222222222',app:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',oid:'20000000-0000-4000-8000-000000000002',sid:bSid,refresh:bRefresh,state:bAppState}
];
async function availablePort() {
  const listener=net.createServer();await new Promise(resolve=>listener.listen(0,'127.0.0.1',resolve));
  const port=listener.address().port;await new Promise(resolve=>listener.close(resolve));return port;
}
let base;
async function http(route,{status=200,token,cookie,json,form,headers={},method='GET'}={}) {
  if(token)headers.Authorization=`Bearer ${token}`;
  if(cookie)headers.Cookie=`zeroth_session=${cookie}`;
  if(json!==undefined)headers['Content-Type']=route.startsWith('/scim/')?'application/scim+json':'application/json';
  if(form)headers['Content-Type']='application/x-www-form-urlencoded';
  const response=await fetch(`${base}${route}`,{method,headers,body:json!==undefined?JSON.stringify(json):form?new URLSearchParams(form):undefined,redirect:'manual'});
  const text=await response.text();ensureNoCredentials(text);
  if(![].concat(status).includes(response.status)) throw new Error(`${method} ${route}: expected ${status}, got ${response.status}: ${redact(text.slice(0,1600))}`);
  let body;try{body=JSON.parse(text);}catch{body=text;}
  return {response,body,text};
}
async function startServer() {
  const log=openSync(path.join(scratch,'workerd.log'),'a',0o600);
  server=spawn(wrangler,['dev','--local','--config',configPath,'--persist-to',stateDir,'--ip','127.0.0.1','--port',new URL(base).port,'--inspector-port','0','--log-level','warn'],{cwd:scratch,env:safeEnv,detached:process.platform!=='win32',stdio:['ignore',log,log]});
  for(let i=0;i<120;i++) {
    if(server.exitCode!==null)throw new Error(`Local Worker exited: ${redact(readFileSync(path.join(scratch,'workerd.log'),'utf8').slice(-6000))}`);
    try {if((await fetch(`${base}/health`)).ok)return;}catch{}
    await delay(250);
  }
  throw new Error(`Local Worker did not become ready; inspect private log ${path.join(scratch,'workerd.log')}`);
}
async function stopServer() {
  if(!server || server.exitCode!==null)return;
  const stopped=new Promise(resolve=>server.once('exit',resolve));
  if(process.platform==='win32')server.kill('SIGTERM');else process.kill(-server.pid,'SIGTERM');
  await Promise.race([stopped,delay(5000)]);
  if(server.exitCode===null) {if(process.platform==='win32')server.kill('SIGKILL');else process.kill(-server.pid,'SIGKILL');}
}
function seedMetadata() {
  const statements=[
    {sql:'INSERT INTO zeroth_users(id,display_name,created_at,updated_at) VALUES (?,?,?,?)',params:['usr_admin','Local integration administrator',now,now]},
    {sql:'INSERT INTO zeroth_users(id,display_name,created_at,updated_at) VALUES (?,?,?,?)',params:['usr_shared','Shared fixture user',now,now]},
    {sql:'INSERT INTO zeroth_sessions(id,user_id,created_at,expires_at) VALUES (?,?,?,?)',params:[adminSid,'usr_admin',now,now+3600]}
  ];
  for(const tenant of tenants) {
    statements.push(
      {sql:"INSERT INTO zeroth_tenants(id,name,enterprise_provider,entra_tenant_id,oidc_client_id,client_secret_binding,created_at,updated_at) VALUES (?,?,'entra',?,?,?,?,?)",params:[tenant.id,`Fixture ${tenant.id}`,tenant.authority,tenant.app,`TENANT_${tenant.id.toUpperCase()}_CLIENT_SECRET`,now,now]},
      {sql:"INSERT INTO zeroth_clients(id,name,redirect_uris_json,allowed_origins_json,enterprise_provider,account_sharing_mode,account_tenant_id,created_at,updated_at) VALUES (?,?,?,?, 'entra','tenant',?,?,?)",params:[tenant.client,tenant.client,JSON.stringify([`${base}/callback`]),JSON.stringify([base]),tenant.id,now,now]},
      {sql:"INSERT INTO zeroth_tenant_clients(client_id,tenant_id,enterprise_provider) VALUES (?,?,'entra')",params:[tenant.client,tenant.id]},
      {sql:"INSERT INTO zeroth_directory_sources(tenant_id,provider_id,authority_id,enabled,token_binding,created_at,updated_at) VALUES (?,'entra',?,1,?,?,?)",params:[tenant.id,tenant.authority,`TENANT_${tenant.id.toUpperCase()}_SCIM_TOKEN`,now,now]},
      // These immutable links model prior signature-verified corporate logins.
      {sql:"INSERT INTO zeroth_directory_links(tenant_id,provider_id,authority_id,external_id,user_id,created_at) VALUES (?,'entra',?,?,'usr_shared',?)",params:[tenant.id,tenant.authority,tenant.oid,now]},
      {sql:"INSERT INTO zeroth_account_identities(account_namespace,provider_id,provider_subject,user_id,created_at,updated_at) VALUES (?,'entra',?,'usr_shared',?,?)",params:[`tenant:${tenant.id}`,`fixture-pairwise-${tenant.id}`,now,now]},
      {sql:"INSERT INTO zeroth_sessions(id,user_id,client_id,created_at,expires_at,auth_provider,auth_policy_hash) VALUES (?,'usr_shared',?,?,?,'entra',?)",params:[tenant.sid,tenant.client,now,now+3600,policyHash(tenant)]},
      {sql:"INSERT INTO zeroth_refresh_tokens(token_hash,client_id,user_id,session_id,auth_time,scope,created_at,expires_at,auth_provider,auth_policy_hash) VALUES (?,?,'usr_shared',?,?,'openid profile offline_access',?,?,'entra',?)",params:[sha(tenant.refresh),tenant.client,tenant.sid,now,now,now+3600,policyHash(tenant)]},
      {sql:"INSERT INTO zeroth_auth_transactions(provider_state,client_id,provider_id,redirect_uri,provider_redirect_uri,scope,link_user_id,link_session_id,created_at,expires_at) VALUES (?,?,'entra',?,?,'openid','usr_shared',?,?,?)",params:[tenant.state,tenant.client,`${base}/callback`,`${base}/oauth2/callback`,tenant.sid,now,now+600]},
      {sql:'INSERT INTO zeroth_tenant_audit_readers(tenant_id,user_id,can_export) VALUES (?,\'usr_shared\',?)',params:[tenant.id,tenant.id==='alpha'?0:1]}
    );
  }
  statements.push({sql:"INSERT INTO zeroth_auth_codes(code_hash,client_id,redirect_uri,user_id,session_id,auth_time,scope,code_challenge,code_challenge_method,created_at,expires_at,auth_provider,auth_policy_hash) VALUES (?,'app-alpha',?,'usr_shared',?,?,'openid',?,'S256',?,?,'entra',?)",params:[sha(aCode),`${base}/callback`,aSid,now,createHash('sha256').update(verifier).digest('base64url'),now,now+600,policyHash(tenants[0])]});
  statements.push({sql:"UPDATE zeroth_clients SET issuer_token_audience='fixture-downstream',issuer_token_ttl_seconds=600"});
  sql(statements);
}
async function exercise() {
  const scim=(tenant,suffix='')=>`/scim/v2/${tenant}/Users${suffix}`;
  const create=(tenant)=>({schemas:['urn:ietf:params:scim:schemas:core:2.0:User'],externalId:tenant.oid,userName:`${tenant.id}@fixture.example`,displayName:`Fixture ${tenant.id}`,active:true});
  const token=(tenant)=>credentials[`TENANT_${tenant.toUpperCase()}_SCIM_TOKEN`];
  await http(scim('alpha'),{status:[401,403],token:secret()});
  await http(scim('beta'),{status:[401,403],token:token('alpha')});
  check('SCIM credentials are tenant-scoped',()=>{});
  const discovery=(await http('/scim/v2/alpha/ServiceProviderConfig',{token:token('alpha')})).body;
  check('SCIM discovery advertises the implemented user PATCH contract',()=>{assert.equal(discovery.patch.supported,true);assert.equal(discovery.bulk.supported,false);});
  const alpha=(await http(scim('alpha'),{method:'POST',token:token('alpha'),json:create(tenants[0]),status:201})).body;
  const beta=(await http(scim('beta'),{method:'POST',token:token('beta'),json:create(tenants[1]),status:201})).body;
  check('created SCIM IDs are opaque and external identity stays explicit',()=>{assert.match(alpha.id,/^dir_/);assert.notEqual(alpha.id,tenants[0].oid);assert.equal(alpha.externalId,tenants[0].oid);assert.notEqual(alpha.id,beta.id);});
  await http(scim('alpha',`/${alpha.id}`),{token:token('alpha')});
  await http(scim('beta',`/${alpha.id}`),{token:token('beta'),status:404});
  const listed=(await http(scim('alpha',`?filter=${encodeURIComponent(`externalId eq "${tenants[0].oid}"`)}`),{token:token('alpha')})).body;
  check('SCIM list/get are scoped to the immutable source object',()=>{assert.equal(listed.totalResults,1);assert.equal(listed.Resources[0].id,alpha.id);});
  await http(scim('alpha',`/${alpha.id}`),{method:'PATCH',token:token('alpha'),json:{schemas:['urn:ietf:params:scim:api:messages:2.0:PatchOp'],Operations:[{op:'replace',path:'externalId',value:'30000000-0000-4000-8000-000000000003'}]},status:[400,409]});
  check('SCIM opaque ID cannot be retargeted to another external object',()=>{assert.equal(one('SELECT external_id FROM zeroth_directory_users WHERE id=?',[alpha.id]).external_id,tenants[0].oid);});
  const adminPage=await http('/admin/tenants',{cookie:adminSid});
  const csrf=adminPage.text.match(/data-csrf-token="([^"]+)"/)?.[1];assert.ok(csrf,'real hosted admin response must supply CSRF proof');
  const config={tenantId:'alpha',enabled:true,tokenBinding:'TENANT_ALPHA_SCIM_TOKEN'};
  await http('/tenants/provisioning?tenant_id=alpha',{method:'POST',cookie:adminSid,json:config,headers:{Origin:base},status:403});
  const bucket=Math.floor(now/86400);
  const wrongFamily=`v1.${bucket}.${createHmac('sha256',Buffer.from(csrfSecret,'base64url')).update(`${adminSid}\0${bucket}\0account`).digest('base64url')}`;
  await http('/tenants/provisioning?tenant_id=alpha',{method:'POST',cookie:adminSid,json:config,headers:{Origin:base,'X-Zeroth-CSRF':wrongFamily},status:403});
  await http('/tenants/provisioning?tenant_id=alpha',{method:'POST',cookie:adminSid,json:config,headers:{Origin:'https://untrusted.invalid','X-Zeroth-CSRF':csrf},status:403});
  await http('/tenants/provisioning?tenant_id=alpha',{method:'POST',cookie:adminSid,json:config,headers:{Origin:base,'X-Zeroth-CSRF':csrf}});
  check('real session admin writes require the admin CSRF family and matching origin',()=>{});
  assert.equal((await http('/session',{cookie:bSid})).body.authenticated,true);
  await http('/audit/events?organization_id=alpha',{cookie:bSid});
  await http('/audit/events?organization_id=alpha&format=csv',{cookie:bSid,status:403});
  await http('/audit/events?organization_id=alpha&organization_id=beta',{cookie:bSid,status:400});
  await http('/audit/events?organization_id=',{cookie:bSid,status:400});
  const betaCsv=await http('/audit/events?organization_id=beta&format=csv',{cookie:bSid});
  assert.match(betaCsv.response.headers.get('Content-Type'),/text\/csv/);assert.ok(!betaCsv.text.includes(alpha.id));
  await http('/events',{cookie:bSid,status:[401,403]});
  check('an authorized reader can read A through a valid B session but cannot export or read operator history',()=>{});
  const issued=(await http('/oauth/token',{method:'POST',form:{grant_type:'refresh_token',client_id:'app-beta',refresh_token:bRefresh}})).body;
  assert.ok(issued.access_token);bRefresh=issued.refresh_token;forbidden.push(bRefresh,issued.access_token);
  const [jwtHeader,jwtPayload,jwtSignature]=issued.access_token.split('.');
  const claims=JSON.parse(Buffer.from(jwtPayload,'base64url'));
  const {kty,crv,x,y}=privateJwk;
  assert.equal(verify('sha256',Buffer.from(`${jwtHeader}.${jwtPayload}`),{key:createPublicKey({key:{kty,crv,x,y},format:'jwk'}),dsaEncoding:'ieee-p1363'},Buffer.from(jwtSignature,'base64url')),true);
  check('real enterprise refresh grants mint signed short-lived access tokens',()=>{assert.equal(claims.sub,'usr_shared');assert.equal(claims.aud,'app-beta');assert.ok(claims.exp-claims.iat<=300);});
  for(const sid of [aSid,bSid]) {
    const downstream=(await http('/tokens',{method:'POST',cookie:sid,headers:{Origin:base}})).body;
    const downstreamClaims=JSON.parse(Buffer.from(downstream.accessToken.split('.')[1],'base64url'));
    assert.equal(downstream.expiresIn,300);assert.equal(downstreamClaims.aud,'fixture-downstream');assert.ok(downstreamClaims.exp-downstreamClaims.iat<=300);
    forbidden.push(downstream.accessToken);
  }
  check('custom downstream tokens also cap enterprise lifetime and persist issuance audit',()=>{assert.ok(one("SELECT COUNT(*) AS count FROM zeroth_audit_events a JOIN zeroth_audit_outbox o ON o.event_id=a.id WHERE a.event_type='token.issue' AND a.event_json LIKE '%downstream_issuer%'").count>=2);});
  await http(scim('alpha',`/${alpha.id}`),{method:'PATCH',token:token('alpha'),json:{schemas:['urn:ietf:params:scim:api:messages:2.0:PatchOp'],Operations:[{op:'replace',path:'active',value:false}]}});
  const after=one('SELECT active,deleted,user_id FROM zeroth_directory_users WHERE id=?',[alpha.id]);
  check('SCIM deactivation commits the inactive directory member linked by stable object ID',()=>{assert.equal(after.active,0);assert.equal(after.deleted,0);assert.equal(after.user_id,'usr_shared');});
  check('offboarding A revokes A sessions, refresh grants, codes and link transactions',()=>{
    assert.ok(one('SELECT revoked_at FROM zeroth_sessions WHERE id=?',[aSid]).revoked_at);
    assert.ok(one('SELECT revoked_at FROM zeroth_refresh_tokens WHERE token_hash=?',[sha(aRefresh)]).revoked_at);
    assert.ok(one('SELECT consumed_at FROM zeroth_auth_codes WHERE code_hash=?',[sha(aCode)]).consumed_at);
    assert.ok(one('SELECT consumed_at FROM zeroth_auth_transactions WHERE provider_state=?',[aAppState]).consumed_at);
  });
  const alphaUser=(await http('/users?tenant_id=alpha',{cookie:adminSid})).body.users.find(user=>user.id==='usr_shared');
  const betaUser=(await http('/users?tenant_id=beta',{cookie:adminSid})).body.users.find(user=>user.id==='usr_shared');
  check('user-management DTO distinguishes global account from selected-tenant lifecycle',()=>{assert.equal(alphaUser.disabled,false);assert.equal(alphaUser.tenantAccess.state,'inactive');assert.equal(betaUser.disabled,false);assert.equal(betaUser.tenantAccess.state,'active');});
  check('shared user and B grants remain active',()=>{assert.equal(one("SELECT disabled_at FROM zeroth_users WHERE id='usr_shared'").disabled_at,null);assert.equal(one('SELECT revoked_at FROM zeroth_sessions WHERE id=?',[bSid]).revoked_at,null);assert.equal(one('SELECT active FROM zeroth_directory_users WHERE id=?',[beta.id]).active,1);assert.equal(one('SELECT consumed_at FROM zeroth_auth_transactions WHERE provider_state=?',[bAppState]).consumed_at,null);});
  await http('/audit/events?organization_id=alpha',{cookie:bSid,status:[401,403]});
  await http('/audit/events?organization_id=beta',{cookie:bSid});
  assert.equal((await http('/session',{cookie:bSid})).body.authenticated,true);
  await http('/tokens',{method:'POST',cookie:aSid,headers:{Origin:base},status:401});
  const survivingDownstream=(await http('/tokens',{method:'POST',cookie:bSid,headers:{Origin:base}})).body;
  assert.equal(survivingDownstream.expiresIn,300);forbidden.push(survivingDownstream.accessToken);
  await http('/oauth/token',{method:'POST',form:{grant_type:'refresh_token',client_id:'app-alpha',refresh_token:aRefresh},status:400});
  await http('/oauth/token',{method:'POST',form:{grant_type:'authorization_code',client_id:'app-alpha',code:aCode,redirect_uri:`${base}/callback`,code_verifier:verifier},status:400});
  const stillActive=(await http('/oauth/token',{method:'POST',form:{grant_type:'refresh_token',client_id:'app-beta',refresh_token:bRefresh}})).body;
  assert.ok(stillActive.access_token);forbidden.push(stillActive.access_token,stillActive.refresh_token);
  check('a valid B session cannot bypass A offboarding, while B refresh issuance remains active',()=>{});
  await http(scim('alpha',`/${alpha.id}`),{method:'DELETE',token:token('alpha'),status:[200,204]});
  await http(scim('alpha',`/${alpha.id}`),{token:token('alpha'),status:404});
  check('SCIM delete retains a denied tombstone with the original opaque identity',()=>{const row=one('SELECT id,external_id,active,deleted FROM zeroth_directory_users WHERE id=?',[alpha.id]);assert.equal(row.external_id,tenants[0].oid);assert.equal(row.active,0);assert.equal(row.deleted,1);});
  const persisted=one("SELECT COUNT(*) AS count FROM zeroth_audit_events a JOIN zeroth_audit_outbox o ON o.event_id=a.id WHERE a.organization_id='alpha' AND a.event_type IN ('directory.user.create','directory.user.disable','directory.user.delete')");
  check('lifecycle history and canonical delivery outbox are committed together',()=>assert.ok(persisted.count>=3));
  const confirmation=await http('/logout',{cookie:adminSid});
  const formCsrf=confirmation.text.match(/name="_csrf" value="([^"]+)"/)?.[1];assert.ok(formCsrf,'real logout confirmation must supply hidden form CSRF');
  await http('/logout',{method:'POST',cookie:adminSid,form:{_csrf:formCsrf},headers:{Origin:base}});
  check('hidden form CSRF fallback still authorizes browser logout',()=>assert.ok(one('SELECT revoked_at FROM zeroth_sessions WHERE id=?',[adminSid]).revoked_at));
  const envelopes=sql([{sql:'SELECT event_json FROM zeroth_audit_outbox'}])[0];for(const row of envelopes){ensureNoCredentials(row.event_json);if([adminSid,aSid,bSid].some(value=>row.event_json.includes(value)))throw new Error('Audit envelope exposed an opaque browser-session credential');}
  const stream=(await http('/audit/stream?limit=2',{token:credentials.AUDIT_STREAM_TOKEN})).body;
  assert.equal(stream.events.length,2);assert.equal(stream.hasMore,true);
  await http('/audit/stream',{token:token('alpha'),status:401});
  await http('/audit/stream/ack',{method:'POST',token:credentials.AUDIT_STREAM_TOKEN,json:{consumerId:'local-http',sequence:stream.nextSequence}});
  const following=(await http('/audit/stream?consumer=local-http&limit=2',{token:credentials.AUDIT_STREAM_TOKEN})).body;
  check('dedicated audit stream pages durable events and resumes the acknowledged checkpoint',()=>assert.ok(following.events.every(item=>item.sequence>stream.nextSequence)));
  await stopServer();await startServer();
  const retained=(await http('/audit/stream?consumer=local-http&limit=2',{token:credentials.AUDIT_STREAM_TOKEN})).body;
  check('Worker restart retains tombstones, audit history and consumer checkpoint',()=>{assert.equal(one('SELECT deleted FROM zeroth_directory_users WHERE id=?',[alpha.id]).deleted,1);assert.equal(retained.events[0].sequence,following.events[0].sequence);assert.ok(one("SELECT COUNT(*) AS count FROM zeroth_audit_events WHERE organization_id='alpha'").count>=3);});
}

try {
  const lock=readFileSync(path.join(repo,'Cargo.lock'),'utf8');
  const version=lock.match(/name = "wasm-bindgen"\nversion = "([^"]+)"/)?.[1];
  assert.match(run(bindgen,['--version']).trim(),new RegExp(` ${version.replaceAll('.','\\.')}$$`),'wasm-bindgen CLI must match Cargo.lock');
  if(!process.env.WORKER_ENTRY) {
    console.log('Building the unmodified Worker for local HTTP integration…');
    const buildStarted=Date.now();
    run(builder,['--release','--no-opt','--no-panic-recovery','--out-dir',buildDir,workerDir,'--locked'],{cwd:workerDir,env:{...safeEnv,CARGO_TARGET_DIR:process.env.ZEROTH_HTTP_TARGET_DIR||path.join(scratch,'cargo-target')}});
    timings.buildSeconds=(Date.now()-buildStarted)/1000;console.log(`Worker build completed in ${timings.buildSeconds.toFixed(1)}s`);
  }
  assert.ok(existsSync(generated),'Worker entry must exist after build');
  now=Math.floor(Date.now()/1000);base=`http://127.0.0.1:${await availablePort()}`;
  const config={name:'zeroth-local-http-integration',main:generated,compatibility_date:'2026-06-04',workers_dev:false,vars:{...credentials,PUBLIC_BASE_URL:base,PRODUCT_NAME:'Local HTTP integration',SESSION_COOKIE_NAME:'zeroth_session',ADMIN_USER_IDS:'usr_admin'},d1_databases:[{binding:'ZEROTH_DB',database_name:'zeroth-local-http',database_id:'00000000-0000-0000-0000-000000000001',remote:false}]};
  writeFileSync(configPath,JSON.stringify(config,null,2),{mode:0o600});
  const migrations=path.join(repo,'crates/zeroth-storage/migrations');
  const schema=readdirSync(migrations).filter(name=>/^\d{4}_.*\.sql$/.test(name)).sort().map(name=>`${readFileSync(path.join(migrations,name),'utf8')}\nINSERT INTO zeroth_schema_migrations(version,name,applied_at) VALUES (${Number(name.slice(0,4))},'${name.slice(5,-4)}',${now});\n`).join('\n');
  const schemaFile=path.join(scratch,'schema.sql');writeFileSync(schemaFile,schema,{mode:0o600});
  const schemaStarted=Date.now();
  run(wrangler,['d1','execute','ZEROTH_DB','--local','--config',configPath,'--persist-to',stateDir,'--file',schemaFile,'--json']);
  timings.schemaSeconds=(Date.now()-schemaStarted)/1000;
  databasePath=findDatabase(stateDir);assert.ok(databasePath,'Wrangler must create a local D1 SQLite database');
  seedMetadata();const httpStarted=Date.now();await startServer();await exercise();timings.httpSeconds=(Date.now()-httpStarted)/1000;
  console.log(`Passed ${checks} real Worker/D1 HTTP integration checks. Synthetic local state: ${scratch}`);
} catch(error) {
  console.error(redact(error.stack||error));console.error(`Private local diagnostics: ${scratch}`);process.exitCode=1;
} finally {await stopServer();timings.totalSeconds=(Date.now()-startedAt)/1000;writeFileSync(path.join(scratch,'result.json'),JSON.stringify({passed:process.exitCode!==1,checks,timings},null,2),{mode:0o600});console.log(`Local integration timings: ${JSON.stringify(timings)}`);}
