const test=require('node:test');const assert=require('node:assert/strict');const crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'atlas-sites-'));
process.env.DATA_DIR=dir;process.env.ADMIN_ID='admin';process.env.ADMIN_PASSWORD_SALT='test-salt';process.env.ADMIN_PASSWORD_HASH=crypto.scryptSync('strong-test-password','test-salt',64).toString('hex');process.env.NODE_ENV='test';process.env.SESSION_SECRET='strong-session-test-secret-'.repeat(3);process.env.SESSION_CREDENTIAL_KEY=crypto.randomBytes(32).toString('hex');
const {server,totp}=require('../server');
async function post(base,route,data,cookie=''){return fetch(base+route,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Cookie:cookie},body:new URLSearchParams(data),redirect:'manual'})}
test('website form uses three fields; session encrypted; agent statuses are truthful',async()=>{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));const base='http://127.0.0.1:'+server.address().port;
 try{
  let r=await post(base,'/login',{id:'admin',password:'strong-test-password'});assert.equal(r.status,303);let cookie=r.headers.get('set-cookie').split(';')[0];
  let html=await (await fetch(base+'/2fa/setup',{headers:{Cookie:cookie}})).text();let csrf=html.match(/name="csrf" value="([a-f0-9]+)"/)[1];let secret=JSON.parse(fs.readFileSync(path.join(dir,'store.json'))).security.totpSecret;
  r=await post(base,'/2fa/activate',{csrf,otp:totp(secret,Math.floor(Date.now()/30000))},cookie);assert.equal(r.status,303);
  html=await (await fetch(base+'/websites/new',{headers:{Cookie:cookie}})).text();assert.match(html,/Session Agent/);assert.doesNotMatch(html,/External Market ID/);assert.doesNotMatch(html,/Reference Page URL/);
  r=await post(base,'/websites/create',{csrf,name:'Site A',url:'https://example.com/agent',agentSession:'session=SECRET_TEST_TOKEN'},cookie);assert.equal(r.status,303);
  const raw=fs.readFileSync(path.join(dir,'store.json'),'utf8');assert.doesNotMatch(raw,/SECRET_TEST_TOKEN/);const saved=JSON.parse(raw);assert.equal(saved.websites[0].name,'Site A');assert.equal(saved.websites[0].hasSession,true);assert.equal(saved.websites[0].connectionStatus,'unverified');
  html=await (await fetch(base+'/agents',{headers:{Cookie:cookie}})).text();assert.match(html,/Konektor Aktif/);assert.match(html,/Belum terhubung/);
  html=await (await fetch(base+'/markets',{headers:{Cookie:cookie}})).text();assert.match(html,/Menunggu konektor/);
  const marketId=saved.websites[0].id;
  r=await post(base,'/markets/import',{csrf,websiteId:marketId,records:'JAIPUR,p6596,2310,2026-10-10,SELESAI,8036'},cookie);assert.equal(r.status,303);
  html=await (await fetch(base+'/markets',{headers:{Cookie:cookie}})).text();assert.match(html,/8036/);assert.match(html,/p6596/);
  html=await (await fetch(base+'/predictions?market=JAIPUR&prefix=80',{headers:{Cookie:cookie}})).text();assert.match(html,/100\.00%/);assert.match(html,/8036/);
  r=await post(base,'/markets/import',{csrf,websiteId:marketId,records:'JAIPUR,p6596,2310,2026-10-10,SELESAI,9999'},cookie);assert.equal(r.status,409);
  html=await (await fetch(base+'/websites',{headers:{Cookie:cookie}})).text();assert.doesNotMatch(html,/SECRET_TEST_TOKEN/);
 }finally{await new Promise(r=>server.close(r));fs.rmSync(dir,{recursive:true,force:true})}
});
