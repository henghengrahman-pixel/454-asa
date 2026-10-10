'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'atlas-persist-'));
process.env.DATA_DIR=dir;process.env.NODE_ENV='test';process.env.ADMIN_ID='admin';process.env.ADMIN_PASSWORD_SALT='persist-salt';process.env.ADMIN_PASSWORD_HASH=crypto.scryptSync('strong-test-password','persist-salt',64).toString('hex');process.env.SESSION_SECRET='secret-for-persistence-tests-'.repeat(3);
const modulePath=require.resolve('../server');
const post=(base,route,data,cookie='')=>fetch(base+route,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Cookie:cookie},body:new URLSearchParams(data),redirect:'manual'});
async function listen(server){await new Promise(r=>server.listen(0,'127.0.0.1',r));return 'http://127.0.0.1:'+server.address().port}
const close=server=>new Promise(r=>server.close(r));
test('authenticated cookie survives process reload; logout revokes the persisted session',async()=>{
 let app=require('../server');let base=await listen(app.server);
 try{
  let r=await post(base,'/login',{id:'admin',password:'strong-test-password'});assert.equal(r.status,303);const cookie=r.headers.get('set-cookie').split(';')[0];
  let html=await (await fetch(base+'/2fa/setup',{headers:{Cookie:cookie}})).text();const csrf=html.match(/name="csrf" value="([a-f0-9]+)"/)[1];
  const secret=JSON.parse(fs.readFileSync(path.join(dir,'store.json'))).security.totpSecret;
  r=await post(base,'/2fa/activate',{csrf,otp:app.totp(secret,Math.floor(Date.now()/30000))},cookie);assert.equal(r.status,303);
  await close(app.server);delete require.cache[modulePath];app=require('../server');base=await listen(app.server);
  r=await fetch(base+'/dashboard',{headers:{Cookie:cookie}});assert.equal(r.status,200);assert.match(await r.text(),/Workspace Overview/);
  r=await post(base,'/logout',{csrf},cookie);assert.equal(r.status,303);
  r=await fetch(base+'/dashboard',{headers:{Cookie:cookie}});assert.equal(r.status,200);assert.match(await r.text(),/Welcome back/);
  const stored=fs.readFileSync(path.join(dir,'store.json'),'utf8');assert.doesNotMatch(stored,new RegExp(cookie.split('=')[1]));
 }finally{if(app.server.listening)await close(app.server);fs.rmSync(dir,{recursive:true,force:true})}
});
