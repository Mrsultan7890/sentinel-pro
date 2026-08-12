import os
import hmac
import base64
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

KEY_FILE = Path.home() / ".octopus_vault" / ".key"
SALT_FILE = Path.home() / ".octopus_vault" / ".salt"

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def setup_vault(password: str):
    KEY_FILE.parent.mkdir(exist_ok=True)
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    SALT_FILE.write_bytes(salt)
    KEY_FILE.write_bytes(key)

def verify_password(password: str) -> bool:
    if not SALT_FILE.exists():
        return False
    salt = SALT_FILE.read_bytes()
    key = _derive_key(password, salt)
    return hmac.compare_digest(key, KEY_FILE.read_bytes())

def is_vault_setup() -> bool:
    return KEY_FILE.exists() and SALT_FILE.exists()

def encrypt_text(text: str) -> str:
    key = KEY_FILE.read_bytes()
    return Fernet(key).encrypt(text.encode()).decode()

def decrypt_text(token: str) -> str:
    key = KEY_FILE.read_bytes()
    return Fernet(key).decrypt(token.encode()).decode()
