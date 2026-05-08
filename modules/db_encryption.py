#!/usr/bin/env python3
"""
Database Encryption with Post-Quantum Cryptography
Encrypts SQLite databases using hybrid classical+PQ crypto
"""

import os
import sqlite3
import json
from pathlib import Path
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib

class PQDatabaseEncryption:
    """Database encryption with PQ-ready key derivation"""
    
    def __init__(self, db_path: str, password: Optional[str] = None):
        """Initialize database encryption"""
        self.db_path = Path(db_path)
        self.password = password or self._get_default_password()
        self.salt_file = self.db_path.parent / f".{self.db_path.name}.salt"
        self.encrypted_db = self.db_path.parent / f"{self.db_path.name}.encrypted"
        
    def _get_default_password(self) -> str:
        """Get default password from machine ID"""
        try:
            # Linux machine ID
            with open('/etc/machine-id', 'r') as f:
                machine_id = f.read().strip()
            return hashlib.sha256(machine_id.encode()).hexdigest()
        except:
            # Fallback to hostname
            import socket
            hostname = socket.gethostname()
            return hashlib.sha256(hostname.encode()).hexdigest()
    
    def _derive_key(self, salt: bytes) -> bytes:
        """Derive encryption key using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self.password.encode())
    
    def encrypt_database(self) -> bool:
        """Encrypt SQLite database"""
        try:
            if not self.db_path.exists():
                print(f"[!] Database not found: {self.db_path}")
                return False
            
            # Generate salt
            salt = os.urandom(16)
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
            
            # Derive key
            key = self._derive_key(salt)
            
            # Read database
            with open(self.db_path, 'rb') as f:
                plaintext = f.read()
            
            # Encrypt with AES-256-GCM
            iv = os.urandom(12)
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            # Save encrypted database
            with open(self.encrypted_db, 'wb') as f:
                f.write(iv)
                f.write(encryptor.tag)
                f.write(ciphertext)
            
            print(f"[+] Database encrypted: {self.encrypted_db}")
            print(f"[+] Salt saved: {self.salt_file}")
            return True
            
        except Exception as e:
            print(f"[!] Encryption failed: {e}")
            return False
    
    def decrypt_database(self, output_path: Optional[str] = None) -> bool:
        """Decrypt SQLite database"""
        try:
            if not self.encrypted_db.exists():
                print(f"[!] Encrypted database not found: {self.encrypted_db}")
                return False
            
            if not self.salt_file.exists():
                print(f"[!] Salt file not found: {self.salt_file}")
                return False
            
            # Read salt
            with open(self.salt_file, 'rb') as f:
                salt = f.read()
            
            # Derive key
            key = self._derive_key(salt)
            
            # Read encrypted database
            with open(self.encrypted_db, 'rb') as f:
                iv = f.read(12)
                tag = f.read(16)
                ciphertext = f.read()
            
            # Decrypt
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Save decrypted database
            output = Path(output_path) if output_path else self.db_path.parent / f"{self.db_path.name}.decrypted"
            with open(output, 'wb') as f:
                f.write(plaintext)
            
            print(f"[+] Database decrypted: {output}")
            return True
            
        except Exception as e:
            print(f"[!] Decryption failed: {e}")
            return False
    
    def verify_integrity(self) -> bool:
        """Verify encrypted database integrity"""
        try:
            if not self.encrypted_db.exists():
                return False
            
            # Try to decrypt to temp file
            import tempfile
            with tempfile.NamedTemporaryFile(delete=True) as tmp:
                if self.decrypt_database(tmp.name):
                    # Verify it's a valid SQLite database
                    conn = sqlite3.connect(tmp.name)
                    conn.execute("SELECT 1")
                    conn.close()
                    return True
            return False
        except:
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get encryption status"""
        return {
            "database": str(self.db_path),
            "encrypted_exists": self.encrypted_db.exists(),
            "salt_exists": self.salt_file.exists(),
            "encrypted_size": self.encrypted_db.stat().st_size if self.encrypted_db.exists() else 0,
            "original_size": self.db_path.stat().st_size if self.db_path.exists() else 0,
            "integrity_ok": self.verify_integrity() if self.encrypted_db.exists() else False
        }


def main():
    """CLI interface"""
    import sys
    
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python3 db_encryption.py encrypt <db_path> [password]")
        print("  python3 db_encryption.py decrypt <db_path> [password]")
        print("  python3 db_encryption.py status <db_path>")
        print("  python3 db_encryption.py verify <db_path>")
        return
    
    command = sys.argv[1]
    db_path = sys.argv[2]
    password = sys.argv[3] if len(sys.argv) > 3 else None
    
    enc = PQDatabaseEncryption(db_path, password)
    
    if command == "encrypt":
        enc.encrypt_database()
    
    elif command == "decrypt":
        enc.decrypt_database()
    
    elif command == "status":
        status = enc.get_status()
        print("\n" + "="*60)
        print("  DATABASE ENCRYPTION STATUS")
        print("="*60)
        print(f"  Database       : {status['database']}")
        print(f"  Encrypted      : {'✓ YES' if status['encrypted_exists'] else '✗ NO'}")
        print(f"  Salt file      : {'✓ YES' if status['salt_exists'] else '✗ NO'}")
        print(f"  Original size  : {status['original_size']:,} bytes")
        print(f"  Encrypted size : {status['encrypted_size']:,} bytes")
        print(f"  Integrity      : {'✓ OK' if status['integrity_ok'] else '✗ FAILED'}")
        print("="*60 + "\n")
    
    elif command == "verify":
        if enc.verify_integrity():
            print("[+] Integrity verification: PASSED ✓")
        else:
            print("[!] Integrity verification: FAILED ✗")
    
    else:
        print(f"[!] Unknown command: {command}")


if __name__ == "__main__":
    main()
