const test=require('node:test');const assert=require('node:assert/strict');const crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'atlas-enroll-'));
process.env.DATA_DIR=dir;process.env.ADMIN_ID='admin';process.env.ADMIN_PASSWORD_SALT='test-salt';process.env.ADMIN_PASSWORD_HASH=crypto.scryptSync('strong-test-password','test-salt',64).toString('hex');process.env.NODE_ENV='test';process.env.SESSION_SECRET='strong-session-test-secret-'.repeat(3);
const {server,totp}=require('../server');
async function submit(url,data,cookie=''){return fetch(url,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Cookie:cookie},body:new URLSearchParams(data),redirect:'manual'})}
test('First login enrolls QR TOTP and subsequent login requires code',async()=>{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));const base='http://127.0.0.1:'+server.address().port;
 try{
  let r=await submit(base+'/login',{id:'admin',password:'wrong'});assert.equal(r.status,401);
  r=await submit(base+'/login',{id:'admin',password:'strong-test-password'});assert.equal(r.status,303);assert.equal(r.headers.get('location'),'/2fa/setup');const cookie=r.headers.get('set-cookie').split(';')[0];
  r=await fetch(base+'/2fa/setup',{headers:{Cookie:cookie}});let html=await r.text();assert.match(html,/QR Code/);const csrf=html.match(/name="csrf" value="([a-f0-9]+)"/)[1];
  r=await fetch(base+'/2fa/qr',{headers:{Cookie:cookie}});assert.equal(r.status,200);assert.match(await r.text(),/<svg/);
  r=await fetch(base+'/dashboard',{headers:{Cookie:cookie}});assert.equal(r.status,200);assert.match(await r.text(),/Welcome back/);
  r=await submit(base+'/2fa/activate',{csrf,otp:'000000'},cookie);assert.equal(r.status,400);
  const secret=JSON.parse(fs.readFileSync(path.join(dir,'store.json'))).security.totpSecret;
  r=await submit(base+'/2fa/activate',{csrf,otp:totp(secret,Math.floor(Date.now()/30000))},cookie);assert.equal(r.status,303);assert.equal(r.headers.get('location'),'/dashboard');
  r=await fetch(base+'/dashboard',{headers:{Cookie:cookie}});assert.equal(r.status,200);assert.match(await r.text(),/Workspace Overview/);
  r=await submit(base+'/login',{id:'admin',password:'strong-test-password'});assert.equal(r.status,401);
  r=await submit(base+'/login',{id:'admin',password:'strong-test-password',otp:totp(secret,Math.floor(Date.now()/30000))});assert.equal(r.status,303);
 } finally {await new Promise(r=>server.close(r));fs.rmSync(dir,{recursive:true,force:true})}
});
