import base64, getpass, json, os, secrets
from cryptography.fernet import Fernet
from security import hash_password

password = getpass.getpass('Password admin (minimal 12 karakter): ')
if len(password) < 12:
    raise SystemExit('Password terlalu pendek')
print('ADMIN_USERNAME=admin')
print('ADMIN_PASSWORD_HASH=' + hash_password(password))
print('ADMIN_TOTP_SECRET=' + base64.b32encode(os.urandom(20)).decode().rstrip('='))
print('ENCRYPTION_KEY=' + Fernet.generate_key().decode())
print('APP_URL=https://GANTI-DOMAIN.up.railway.app')
print('DATA_DIR=/data')
print('COOKIE_SECURE=true')
