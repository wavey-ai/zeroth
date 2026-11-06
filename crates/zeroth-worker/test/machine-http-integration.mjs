/** Local workerd/D1 acceptance tests for service identities; uses only synthetic credentials. */
import assert from 'node:assert/strict';
import {createPublicKey, generateKeyPairSync, randomBytes, sign, verify} from 'node:crypto';
import {spawn, spawnSync} from 'node:child_process';
import {chmodSync, existsSync, mkdtempSync, openSync, readFileSync, readdirSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import net from 'node:net';
import path from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {fileURLToPath} from 'node:url';

const workerDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repo = path.resolve(workerDir, '../..');
const scratch = mkdtempSync(path.join(tmpdir(), 'zeroth-machine-http-'));
chmodSync(scratch, 0o700);
const stateDir = path.join(scratch, 'state');
const configPath = path.join(scratch, 'wrangler.json');
const wrangler = process.env.WRANGLER_BIN || 'wrangler';
const builder = process.env.WORKER_BUILD_BIN || 'worker-build';
const bindgen = process.env.WASM_BINDGEN_BIN || 'wasm-bindgen';
const buildDir = path.join(scratch, 'build');
const generated = process.env.WORKER_ENTRY || path.join(buildDir, 'index.js');
const secret = () => randomBytes(32).toString('base64url');
const adminSid = `sess_${secret()}`;
const issuerKey = generateKeyPairSync('ec', {namedCurve:'prime256v1'});
const issuerJwk = issuerKey.privateKey.export({format:'jwk'});
const agentV1 = generateKeyPairSync('ec', {namedCurve:'prime256v1'});
const agentV2 = generateKeyPairSync('ec', {namedCurve:'prime256v1'});
const stranger = generateKeyPairSync('ec', {namedCurve:'prime256v1'});
const publicJwk = (key,kid) => ({...key.publicKey.export({format:'jwk'}),kid,alg:'ES256',use:'sig'});
const credentials = {JWT_ES256_PRIVATE_KEY:JSON.stringify(issuerJwk),JWT_KEY_ID:'machine-http-issuer',CSRF_SECRET:secret(),RATE_LIMIT_KEY:secret()};
const forbidden = [adminSid,...Object.values(credentials),issuerJwk.d,agentV1.privateKey.export({format:'jwk'}).d,agentV2.privateKey.export({format:'jwk'}).d];
const redact = text => forbidden.reduce((result,value) => result.replaceAll(value,'[synthetic credential]'),String(text));
const safeNames = new Set(['PATH','HOME','USER','LANG','LC_ALL','SHELL','TMPDIR','CARGO_HOME','RUSTUP_HOME','RUSTUP_TOOLCHAIN','RUSTFLAGS','RUSTDOCFLAGS','SSL_CERT_FILE','SSL_CERT_DIR','HTTPS_PROXY','HTTP_PROXY','NO_PROXY','WASM_BINDGEN_BIN','ESBUILD_BIN']);
const safeEnv = {...Object.fromEntries(Object.entries(process.env).filter(([key])=>safeNames.has(key))),WRANGLER_SEND_METRICS:'false',CI:'true',NO_COLOR:'1'};
if(process.env.WASM_BINDGEN_BIN) safeEnv.PATH = `${path.dirname(bindgen)}${path.delimiter}${safeEnv.PATH || ''}`;
let base, databasePath, server, csrf, checks = 0;
const audience = 'https://control.example.test/releases';
const issuer = 'https://zeroth.example.test';
const report = {passed:false,checks:0};

function run(program,args,options={}) {
  const result = spawnSync(program,args,{cwd:scratch,env:safeEnv,encoding:'utf8',maxBuffer:32*1024*1024,...options});
  if(result.error || result.status!==0) throw new Error(`${path.basename(program)} failed: ${redact(result.error?.message || result.stderr || result.stdout)}`);
  return result.stdout;
}
function check(label,action=()=>{}) {action();checks++;console.log(`ok ${checks} - ${label}`);}
function sql(statements) {
  const source = `import sys,json,sqlite3\nc=sqlite3.connect(sys.argv[1],timeout=10)\nc.row_factory=sqlite3.Row\nc.execute('PRAGMA foreign_keys=ON')\nr=[]\nfor s in json.load(sys.stdin):\n x=c.execute(s['sql'],s.get('params',[]))\n r.append([dict(v) for v in x.fetchall()] if x.description else [])\nc.commit()\nprint(json.dumps(r))`;
  return JSON.parse(run('python3',['-c',source,databasePath],{input:JSON.stringify(statements)}));
}
function findDb(directory) {
  for(const entry of readdirSync(directory,{withFileTypes:true})) {
    const file=path.join(directory,entry.name);
    if(entry.isDirectory()) {const found=findDb(file);if(found)return found;}
    else if(entry.name.endsWith('.sqlite')) return file;
  }
}
async function port() {
  const listener=net.createServer();await new Promise(resolve=>listener.listen(0,'127.0.0.1',resolve));
  const number=listener.address().port;await new Promise(resolve=>listener.close(resolve));return number;
}
async function start() {
  const log=openSync(path.join(scratch,'workerd.log'),'a',0o600);
  server=spawn(wrangler,['dev','--local','--config',configPath,'--persist-to',stateDir,'--ip','127.0.0.1','--port',new URL(base).port,'--inspector-port','0','--log-level','warn'],{cwd:scratch,env:safeEnv,detached:true,stdio:['ignore',log,log]});
  for(let i=0;i<120;i++) {
    if(server.exitCode!==null) throw new Error(`Local Worker exited; private diagnostics: ${scratch}`);
    try {if((await fetch(`${base}/health`)).ok)return;}catch{}
    await delay(250);
  }
  throw new Error('Local Worker readiness timed out');
}
async function stop() {
  if(!server || server.exitCode!==null)return;
  const stopped=new Promise(resolve=>server.once('exit',resolve));
  process.kill(-server.pid,'SIGTERM');await Promise.race([stopped,delay(5000)]);
  if(server.exitCode===null) process.kill(-server.pid,'SIGKILL');
}
async function http(route,{method='GET',json,form,cookie,token,status=200,headers={}}={}) {
  if(cookie) headers.Cookie=`zeroth_session=${cookie}`;
  if(token) headers.Authorization=`Bearer ${token}`;
  if(json!==undefined) headers['Content-Type']='application/json';
  if(form) headers['Content-Type']='application/x-www-form-urlencoded';
  const response=await fetch(`${base}${route}`,{method,headers,body:json!==undefined?JSON.stringify(json):form?new URLSearchParams(form):undefined,redirect:'manual'});
  const text=await response.text();
  if(![].concat(status).includes(response.status)) throw new Error(`${method} ${route}: expected ${status}, got ${response.status}: ${redact(text.slice(0,1000))}`);
  let body;try {body=JSON.parse(text);}catch {body=text;}
  return {response,body,text};
}
function assertion(client,{key=agentV1,kid='agent-v1',endpoint='/oauth/token',claims={}}={}) {
  const now=Math.floor(Date.now()/1000);
  const header=Buffer.from(JSON.stringify({alg:'ES256',kid,typ:'JWT'})).toString('base64url');
  const payload=Buffer.from(JSON.stringify({iss:client.id,sub:client.id,aud:`${issuer}${endpoint}`,iat:now,exp:now+120,jti:secret(),...claims})).toString('base64url');
  const unsigned=`${header}.${payload}`;
  const token=`${unsigned}.${sign('sha256',Buffer.from(unsigned),{key:key.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url')}`;
  forbidden.push(token);return token;
}
function issueForm(client,options={}) {
  return {grant_type:'client_credentials',client_id:client.id,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:assertion(client,options),resource:audience,scope:'releases:read'};
}
async function manage(json,status=200,headers={}) {
  return (await http('/service-clients',{method:'POST',cookie:adminSid,json,status,headers:{Origin:issuer,'X-Zeroth-CSRF':csrf,...headers}})).body;
}
function draft(tenantId,id) {
  return {id,tenantId,name:`${tenantId} release agent`,audiences:[audience],scopes:['releases:read','receipts:write'],publicJwks:{keys:[publicJwk(agentV1,'agent-v1')]},disabled:false,tokenTtlSeconds:600};
}
async function introspect(client,token,key=agentV1,kid='agent-v1') {
  return (await http('/oauth/introspect',{method:'POST',form:{client_id:client.id,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:assertion(client,{key,kid,endpoint:'/oauth/introspect'}),token,token_type_hint:'access_token'}})).body;
}
async function exercise() {
  const metadata=(await http('/.well-known/openid-configuration')).body;
  check('discovery advertises machine grants and private-key authentication',()=>{assert.ok(metadata.grant_types_supported.includes('client_credentials'));assert.ok(metadata.token_endpoint_auth_methods_supported.includes('private_key_jwt'));});
  await http('/service-clients',{status:[401,403]});
  await http('/service-clients',{method:'POST',json:draft('alpha','svc_denied'),status:[401,403]});
  const page=await http('/admin/service-clients',{cookie:adminSid});
  csrf=page.text.match(/data-csrf-token="([^"]+)"/)?.[1];assert.ok(csrf);
  check('service management requires administrator authentication and renders its console');
  await http('/service-clients',{method:'POST',cookie:adminSid,json:draft('alpha','svc_denied'),headers:{Origin:base},status:403});
  await manage(draft('alpha','svc_denied'),403,{Origin:'https://untrusted.example.test'});
  check('browser service mutations require valid CSRF and same-origin proof');
  const bad=draft('alpha','svc_bad_private');bad.publicJwks.keys[0].d=agentV1.privateKey.export({format:'jwk'}).d;
  await manage(bad,400);
  const invalid=draft('missing','svc_no_tenant');await manage(invalid,[400,404,409]);
  let alpha=await manage(draft('alpha','svc_alpha_runner'));
  const beta=await manage(draft('beta','svc_beta_runner'));
  check('public-key clients register under existing tenants with explicit grants',()=>{assert.equal(alpha.tenantId,'alpha');assert.equal(alpha.revision,1);assert.equal(beta.tenantId,'beta');assert.equal(alpha.publicJwks.keys[0].d,undefined);});
  const listed=(await http('/service-clients?tenant_id=alpha',{cookie:adminSid})).body.serviceClients;
  check('tenant-filtered administration excludes the other tenant',()=>assert.deepEqual(listed.map(client=>client.id),[alpha.id]));
  await manage({...draft('beta',alpha.id),expectedRevision:alpha.revision},[400,409]);
  check('a service identity cannot be rebound across tenants');
  await http('/oauth/token',{method:'POST',form:issueForm(alpha,{key:stranger}),status:401});
  await http('/oauth/token',{method:'POST',form:issueForm(alpha,{claims:{aud:`${base}/wrong`}}),status:401});
  await http('/oauth/token',{method:'POST',form:issueForm(alpha,{claims:{exp:Math.floor(Date.now()/1000)-1}}),status:401});
  check('wrong keys, wrong endpoint audiences and expired assertions are refused');
  const disallowed=issueForm(alpha);disallowed.scope='administrator';
  await http('/oauth/token',{method:'POST',form:disallowed,status:400});
  const wrongAudience=issueForm(alpha);wrongAudience.resource='https://other.example.test';
  await http('/oauth/token',{method:'POST',form:wrongAudience,status:400});
  const ambiguous=issueForm(alpha);ambiguous.audience=audience;
  await http('/oauth/token',{method:'POST',form:ambiguous,status:400});
  check('scope and resource grants are enforced and ambiguous resource selection is refused');
  const form=issueForm(alpha);
  const issued=(await http('/oauth/token',{method:'POST',form})).body;
  assert.ok(issued.access_token);forbidden.push(issued.access_token);
  const [header,payload,signature]=issued.access_token.split('.');
  const claims=JSON.parse(Buffer.from(payload,'base64url'));
  check('machine grant returns a verifiable, bounded service access token without human grants',()=>{
    assert.equal(verify('sha256',Buffer.from(`${header}.${payload}`),{key:issuerKey.publicKey,dsaEncoding:'ieee-p1363'},Buffer.from(signature,'base64url')),true);
    assert.equal(claims.principal_type,'service');assert.equal(claims.token_use,'access');assert.equal(claims.tenant_id,'alpha');assert.equal(claims.client_id,alpha.id);assert.equal(claims.aud,audience);assert.equal(claims.scope,'releases:read');assert.ok(claims.exp-claims.iat<=600);assert.equal(issued.id_token,undefined);assert.equal(issued.refresh_token,undefined);
  });
  await http('/oauth/token',{method:'POST',form,status:401});
  const raced=issueForm(alpha);
  const outcomes=await Promise.all([http('/oauth/token',{method:'POST',form:raced,status:[200,401]}),http('/oauth/token',{method:'POST',form:raced,status:[200,401]})]);
  for(const outcome of outcomes) if(outcome.body.access_token)forbidden.push(outcome.body.access_token);
  check('concurrent replay produces exactly one successful token issuance',()=>assert.deepEqual(outcomes.map(result=>result.response.status).sort(),[200,401]));
  assert.equal((await introspect(alpha,issued.access_token)).active,true);
  assert.equal((await introspect(beta,issued.access_token)).active,false);
  check('introspection accepts the issuing service and isolates other clients');
  await http('/userinfo',{token:issued.access_token,status:[401,403]});
  await http('/service-clients',{token:issued.access_token,status:[401,403]});
  check('service access cannot become a human identity or administrator session');
  const stale=alpha.revision;
  alpha=await manage({...draft('alpha',alpha.id),publicJwks:{keys:[publicJwk(agentV1,'agent-v1'),publicJwk(agentV2,'agent-v2')]},expectedRevision:alpha.revision});
  await manage({...draft('alpha',alpha.id),expectedRevision:stale},409);
  assert.equal((await introspect(alpha,issued.access_token,agentV2,'agent-v2')).active,false);
  const fresh=(await http('/oauth/token',{method:'POST',form:issueForm(alpha,{key:agentV2,kid:'agent-v2'})})).body;
  forbidden.push(fresh.access_token);
  check('key rotation advances policy revision, rejects stale edits and invalidates prior token introspection');
  alpha=await manage({...draft('alpha',alpha.id),publicJwks:{keys:[publicJwk(agentV2,'agent-v2')]},expectedRevision:alpha.revision});
  await http('/oauth/token',{method:'POST',form:issueForm(alpha),status:401});
  const durableReplay=issueForm(alpha,{key:agentV2,kid:'agent-v2'});
  const durableIssued=(await http('/oauth/token',{method:'POST',form:durableReplay})).body;forbidden.push(durableIssued.access_token);
  await stop();await start();
  await http('/oauth/token',{method:'POST',form:durableReplay,status:401});
  assert.equal((await introspect(alpha,durableIssued.access_token,agentV2,'agent-v2')).active,true);
  check('restart retains registered key policy, issued-token status and assertion replay protection');
  alpha=await manage({...draft('alpha',alpha.id),publicJwks:{keys:[publicJwk(agentV2,'agent-v2')]},disabled:true,expectedRevision:alpha.revision});
  await http('/oauth/token',{method:'POST',form:issueForm(alpha,{key:agentV2,kid:'agent-v2'}),status:401});
  const betaIssued=(await http('/oauth/token',{method:'POST',form:issueForm(beta)})).body;forbidden.push(betaIssued.access_token);
  check('disabling one tenant service does not stop another tenant service');
  sql([{sql:'UPDATE zeroth_tenants SET disabled=1 WHERE id=?',params:['beta']}]);
  await http('/oauth/token',{method:'POST',form:issueForm(beta),status:401});
  check('disabled tenants cannot obtain fresh service tokens');
  const events=sql([{sql:'SELECT event_json FROM zeroth_audit_outbox'}])[0];
  for(const event of events) for(const value of forbidden) assert.ok(!event.event_json.includes(value),'audit data must not expose credentials');
  check('service operations leave durable tenant audit evidence without assertions, keys or bearer tokens',()=>{
    assert.ok(events.some(event=>event.event_json.includes(alpha.id) && event.event_json.includes('alpha')));
    assert.ok(events.some(event=>event.event_json.includes(beta.id) && event.event_json.includes('beta')));
  });
}

try {
  const version=readFileSync(path.join(repo,'Cargo.lock'),'utf8').match(/name = "wasm-bindgen"\nversion = "([^"]+)"/)?.[1];
  assert.ok(run(bindgen,['--version']).trim().endsWith(` ${version}`));
  if(!process.env.WORKER_ENTRY)run(builder,['--release','--no-opt','--no-panic-recovery','--out-dir',buildDir,workerDir,'--locked'],{cwd:workerDir,env:{...safeEnv,CARGO_TARGET_DIR:process.env.ZEROTH_HTTP_TARGET_DIR||path.join(scratch,'cargo-target')}});
  assert.ok(existsSync(generated));
  base=`http://127.0.0.1:${await port()}`;
  writeFileSync(configPath,JSON.stringify({name:'zeroth-machine-local',main:generated,compatibility_date:'2026-06-04',workers_dev:false,vars:{...credentials,PUBLIC_BASE_URL:issuer,PRODUCT_NAME:'Machine HTTP tests',SESSION_COOKIE_NAME:'zeroth_session',ADMIN_USER_IDS:'usr_machine_admin'},d1_databases:[{binding:'ZEROTH_DB',database_name:'zeroth-machine-local',database_id:'00000000-0000-0000-000000000001',remote:false}]},null,2),{mode:0o600});
  const now=Math.floor(Date.now()/1000);
  const directory=path.join(repo,'crates/zeroth-storage/migrations');
  const schema=readdirSync(directory).filter(name=>/^\d{4}_.*\.sql$/.test(name)).sort().map(name=>`${readFileSync(path.join(directory,name),'utf8')}\nINSERT INTO zeroth_schema_migrations(version,name,applied_at) VALUES(${Number(name.slice(0,4))},'${name.slice(5,-4)}',${now});`).join('\n');
  const schemaFile=path.join(scratch,'schema.sql');writeFileSync(schemaFile,schema,{mode:0o600});
  run(wrangler,['d1','execute','ZEROTH_DB','--local','--config',configPath,'--persist-to',stateDir,'--file',schemaFile,'--json']);
  databasePath=findDb(stateDir);assert.ok(databasePath);
  sql([
    {sql:'INSERT INTO zeroth_users(id,display_name,created_at,updated_at) VALUES (?,?,?,?)',params:['usr_machine_admin','Machine test administrator',now,now]},
    {sql:'INSERT INTO zeroth_sessions(id,user_id,created_at,expires_at) VALUES (?,?,?,?)',params:[adminSid,'usr_machine_admin',now,now+3600]},
    ...['alpha','beta'].map(id=>({sql:'INSERT INTO zeroth_tenants(id,name,created_at,updated_at) VALUES (?,?,?,?)',params:[id,`Fixture ${id}`,now,now]}))
  ]);
  await start();await exercise();report.passed=true;console.log(`Passed ${checks} real service-identity HTTP checks.`);
}catch(error) {console.error(redact(error.stack||error));console.error(`Private diagnostics: ${scratch}`);process.exitCode=1;}
finally {await stop();report.checks=checks;report.workerEntry=generated;writeFileSync(path.join(scratch,'result.json'),JSON.stringify(report,null,2),{mode:0o600});console.log(`Local results: ${scratch}`);}
