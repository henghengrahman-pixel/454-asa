const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');process.env.DATA_DIR=require('node:path').join(require('node:os').tmpdir(),'atlas-test-'+process.pid);const {server,validTotp,totp,esc}=require('../server');
test('TOTP rejects bad formats and validates current code',()=>{const key='JBSWY3DPEHPK3PXP';assert.equal(validTotp('123',key),false);assert.equal(validTotp(totp(key,Math.floor(Date.now()/30000)),key),true)});
test('HTML escaping prevents markup injection',()=>assert.equal(esc('<script>"&'), '&lt;script&gt;&quot;&amp;'));
test('Unauthorized request cannot enter protected workspace',async()=>{await new Promise(r=>server.listen(0,'127.0.0.1',r));const base='http://127.0.0.1:'+server.address().port;const response=await fetch(base+'/dashboard');assert.equal(response.status,200);assert.match(await response.text(),/Welcome back\./);const b=await fetch(base+'/websites/create',{method:'POST'});assert.equal(b.status,401);const css=await fetch(base+'/assets/style.css');assert.equal(css.status,200);server.close()});

test('Unauthenticated login page remains available without IP configuration',async()=>{
  
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  const r=await fetch(`http://127.0.0.1:${server.address().port}/login`,{headers:{'x-forwarded-for':'203.0.113.88'}});
  assert.equal(r.status,200);assert.match(await r.text(),/Welcome back/);
  await new Promise(r=>server.close(r));
});
