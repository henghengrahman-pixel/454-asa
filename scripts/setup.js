const crypto=require('node:crypto');const fs=require('node:fs');const path=require('node:path');
const pw=process.argv[2];if(!pw||pw.length<14){console.error('Usage: npm run setup -- "password-min-14-karakter"');process.exit(1)}
const salt=crypto.randomBytes(16).toString('hex');const hash=crypto.scryptSync(pw,salt,64).toString('hex');
const env=`NODE_ENV=production\nPORT=3000\nADMIN_ID=admin\nADMIN_PASSWORD_SALT=${salt}\nADMIN_PASSWORD_HASH=${hash}\nSESSION_CREDENTIAL_KEY=${crypto.randomBytes(32).toString('hex')}\nSESSION_SECRET=${crypto.randomBytes(48).toString('hex')}\nDATA_DIR=./data\n`;
const file=path.join(__dirname,'..','.env');if(fs.existsSync(file)){console.error('.env already exists; refusing overwrite');process.exit(1)}fs.writeFileSync(file,env,{mode:0o600});console.log('Created .env with admin credentials.');console.log('2FA is activated after the first verified login via QR code.');
