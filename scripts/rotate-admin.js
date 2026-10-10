'use strict';
// Generate replacement credentials locally; does not touch the volume or .env.
const crypto=require('node:crypto');
const password=crypto.randomBytes(24).toString('base64url');
const salt=crypto.randomBytes(16).toString('hex');
const hash=crypto.scryptSync(password,salt,64).toString('hex');
const sessionSecret=crypto.randomBytes(48).toString('hex');
console.log('ADMIN_ID=admin');
console.log('ADMIN_PASSWORD_SALT='+salt);
console.log('ADMIN_PASSWORD_HASH='+hash);
console.log('SESSION_SECRET='+sessionSecret);
console.log('\nPASSWORD ADMIN BARU (CATAT, JANGAN MASUKKAN KE RAILWAY VARIABLES): '+password);
console.log('Perbarui 3 variabel ADMIN_PASSWORD_SALT, ADMIN_PASSWORD_HASH dan SESSION_SECRET di Railway.');
console.log('JANGAN ubah SESSION_CREDENTIAL_KEY atau hapus volume /data. TOTP yang sudah aktif tetap tersimpan.');
