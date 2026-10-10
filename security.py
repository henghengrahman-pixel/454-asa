import base64, hashlib, hmac, os, struct, time
from cryptography.fernet import Fernet

def hash_password(password, salt=None):
    salt = salt or os.urandom(16).hex()
    return salt + ':' + hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()

def verify_password(password, encoded):
    try:
        return hmac.compare_digest(hash_password(password, encoded.split(':')[0]), encoded)
    except (ValueError, TypeError):
        return False

def totp(secret, step=None):
    key = base64.b32decode(secret.upper() + '=' * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack('>Q', int(time.time() // 30) if step is None else step), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f'{(struct.unpack(">I", digest[offset:offset+4])[0] & 0x7fffffff) % 1000000:06d}'

def verify_totp(secret, code):
    step = int(time.time() // 30)
    for candidate in (step-1, step, step+1):
        if hmac.compare_digest(totp(secret, candidate), code):
            return candidate
    return None

def cipher(key):
    return Fernet(key.encode())
