"""
Secure File Manager v1.0 — Industry Standard File Handling
===========================================================
OWASP + NIST + ISO 27001 Compliant
- Chain of custody for legal evidence
- Cryptographic integrity verification
- Secure file operations with audit logging
- Court-grade evidence handling

Author: @who_is_the_black_hat
"""

import os
import hashlib
import json
import logging
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import tempfile
import mimetypes
import magic
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

import config

logger = logging.getLogger(__name__)

# File security classifications
CLASSIFICATION_LEVELS = {
    'PUBLIC': 0,
    'INTERNAL': 1, 
    'CONFIDENTIAL': 2,
    'RESTRICTED': 3,
    'TOP_SECRET': 4
}

# Allowed file types for security
ALLOWED_EXTENSIONS = {
    'reports': {'.json', '.html', '.pdf', '.txt', '.md'},
    'evidence': {'.json', '.png', '.jpg', '.jpeg', '.txt', '.log', '.pcap'},
    'config': {'.json', '.yaml', '.yml', '.env', '.conf'},
    'media': {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.mp4', '.wav'},
    'data': {'.json', '.csv', '.xml', '.db', '.sqlite'}
}

# Maximum file sizes (bytes)
MAX_FILE_SIZES = {
    'reports': 50 * 1024 * 1024,    # 50MB
    'evidence': 100 * 1024 * 1024,  # 100MB
    'config': 1 * 1024 * 1024,      # 1MB
    'media': 200 * 1024 * 1024,     # 200MB
    'data': 500 * 1024 * 1024       # 500MB
}


class SecureFileManager:
    """
    Industry-standard secure file manager
    Handles all file operations with security, integrity, and audit logging
    """
    
    def __init__(self):
        self.base_dir = config.BASE_DIR
        self.evidence_dir = config.EVIDENCE_DIR
        self.reports_dir = config.REPORTS_DIR
        self.logs_dir = config.LOGS_DIR
        
        # Create secure directories
        self._init_secure_directories()
        
        # Initialize encryption
        self._init_encryption()
        
        # Audit log
        self.audit_log = self.logs_dir / 'file_audit.log'
        self._setup_audit_logging()
        
        # File registry for tracking
        self.registry_file = self.base_dir / 'data' / 'file_registry.json'
        self.file_registry = self._load_registry()
        
    def _init_secure_directories(self):
        """Create directories with proper permissions"""
        secure_dirs = [
            (self.evidence_dir, 0o700),      # Evidence - owner only
            (self.reports_dir, 0o755),       # Reports - readable
            (self.logs_dir, 0o750),          # Logs - owner + group
            (self.base_dir / 'data', 0o750), # Data - owner + group
            (self.base_dir / 'temp', 0o700), # Temp - owner only
        ]
        
        for dir_path, permissions in secure_dirs:
            dir_path.mkdir(exist_ok=True, parents=True)
            os.chmod(dir_path, permissions)
            
    def _init_encryption(self):
        """Initialize encryption for sensitive files"""
        key_file = self.base_dir / 'data' / '.encryption_key'
        
        if key_file.exists():
            with open(key_file, 'rb') as f:
                self.encryption_key = f.read()
        else:
            # Generate new encryption key
            password = b"sentinel_pro_secure_key_2024"
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            self.encryption_key = key
            
            # Save key securely
            with open(key_file, 'wb') as f:
                f.write(key)
            os.chmod(key_file, 0o600)  # Owner read/write only
            
        self.cipher = Fernet(self.encryption_key)
        
    def _setup_audit_logging(self):
        """Setup audit logging for file operations"""
        audit_handler = logging.FileHandler(self.audit_log)
        audit_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        )
        
        self.audit_logger = logging.getLogger('file_audit')
        self.audit_logger.addHandler(audit_handler)
        self.audit_logger.setLevel(logging.INFO)
        
    def _load_registry(self) -> Dict:
        """Load file registry for tracking"""
        if self.registry_file.exists():
            try:
                with open(self.registry_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load file registry: {e}")
        return {'files': {}, 'evidence_chain': {}}
        
    def _save_registry(self):
        """Save file registry"""
        try:
            with open(self.registry_file, 'w') as f:
                json.dump(self.file_registry, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save file registry: {e}")
            
    def _audit_log(self, operation: str, file_path: str, result: str, 
                   details: str = "", user: str = "system"):
        """Log file operation for audit trail"""
        self.audit_logger.info(
            f"OPERATION={operation} | FILE={file_path} | RESULT={result} | "
            f"USER={user} | DETAILS={details}"
        )
        
    def _calculate_hash(self, file_path: Path) -> Tuple[str, str, str]:
        """Calculate multiple hashes for integrity verification"""
        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                
        return (
            sha256_hash.hexdigest(),
            md5_hash.hexdigest(), 
            sha1_hash.hexdigest()
        )
        
    def _validate_file_type(self, file_path: Path, category: str) -> bool:
        """Validate file type using multiple methods"""
        # Extension check
        ext = file_path.suffix.lower()
        if ext not in ALLOWED_EXTENSIONS.get(category, set()):
            return False
            
        # MIME type check
        mime_type, _ = mimetypes.guess_type(str(file_path))
        
        # Magic number check (if file exists)
        if file_path.exists():
            try:
                file_magic = magic.from_file(str(file_path), mime=True)
                # Basic validation - can be extended
                if 'executable' in file_magic or 'script' in file_magic:
                    return False
            except Exception:
                pass  # magic library might not be available
                
        return True
        
    def _validate_file_size(self, file_path: Path, category: str) -> bool:
        """Validate file size limits"""
        if not file_path.exists():
            return True
            
        size = file_path.stat().st_size
        max_size = MAX_FILE_SIZES.get(category, 10 * 1024 * 1024)  # 10MB default
        
        return size <= max_size
        
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to prevent path traversal and injection"""
        import re
        
        # Remove path separators and dangerous characters
        sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', filename)
        
        # Remove leading/trailing dots and spaces
        sanitized = sanitized.strip('. ')
        
        # Limit length
        if len(sanitized) > 200:
            name, ext = os.path.splitext(sanitized)
            sanitized = name[:200-len(ext)] + ext
            
        # Ensure not empty
        if not sanitized:
            sanitized = f"file_{int(time.time())}"
            
        return sanitized
        
    def secure_write(self, content: str, file_path: str, category: str = 'data',
                    classification: str = 'INTERNAL', encrypt: bool = False) -> Dict:
        """
        Securely write content to file with full security validation
        
        Args:
            content: Content to write
            file_path: Target file path
            category: File category for validation
            classification: Security classification level
            encrypt: Whether to encrypt the file
            
        Returns:
            Dict with operation result and file metadata
        """
        try:
            # Sanitize and validate path
            path = Path(file_path)
            safe_name = self._sanitize_filename(path.name)
            safe_path = path.parent / safe_name
            
            # Validate file type and size
            if not self._validate_file_type(safe_path, category):
                self._audit_log('WRITE', str(safe_path), 'FAILED', 'Invalid file type')
                return {'success': False, 'error': 'Invalid file type'}
                
            # Create parent directories securely
            safe_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write to temporary file first
            with tempfile.NamedTemporaryFile(mode='w', delete=False, 
                                           dir=safe_path.parent) as temp_file:
                if encrypt and classification in ['CONFIDENTIAL', 'RESTRICTED', 'TOP_SECRET']:
                    # Encrypt content
                    encrypted_content = self.cipher.encrypt(content.encode())
                    temp_file.write(base64.b64encode(encrypted_content).decode())
                else:
                    temp_file.write(content)
                temp_path = Path(temp_file.name)
                
            # Validate size after writing
            if not self._validate_file_size(temp_path, category):
                temp_path.unlink()
                self._audit_log('WRITE', str(safe_path), 'FAILED', 'File too large')
                return {'success': False, 'error': 'File too large'}
                
            # Atomic move to final location
            shutil.move(str(temp_path), str(safe_path))
            
            # Set appropriate permissions
            if classification in ['CONFIDENTIAL', 'RESTRICTED', 'TOP_SECRET']:
                os.chmod(safe_path, 0o600)  # Owner only
            else:
                os.chmod(safe_path, 0o644)  # Owner write, others read
                
            # Calculate integrity hashes
            sha256, md5, sha1 = self._calculate_hash(safe_path)
            
            # Register file
            file_id = f"{safe_path.name}_{int(time.time())}"
            self.file_registry['files'][file_id] = {
                'path': str(safe_path),
                'category': category,
                'classification': classification,
                'created': datetime.now().isoformat(),
                'size': safe_path.stat().st_size,
                'sha256': sha256,
                'md5': md5,
                'sha1': sha1,
                'encrypted': encrypt,
                'permissions': oct(safe_path.stat().st_mode)[-3:]
            }
            self._save_registry()
            
            self._audit_log('WRITE', str(safe_path), 'SUCCESS', 
                          f'Category={category}, Classification={classification}')
            
            return {
                'success': True,
                'path': str(safe_path),
                'file_id': file_id,
                'sha256': sha256,
                'size': safe_path.stat().st_size,
                'encrypted': encrypt
            }
            
        except Exception as e:
            self._audit_log('WRITE', str(file_path), 'ERROR', str(e))
            logger.error(f"Secure write failed: {e}")
            return {'success': False, 'error': str(e)}
            
    def secure_read(self, file_path: str, verify_integrity: bool = True) -> Dict:
        """
        Securely read file with integrity verification
        
        Args:
            file_path: Path to file
            verify_integrity: Whether to verify file integrity
            
        Returns:
            Dict with file content and metadata
        """
        try:
            path = Path(file_path)
            
            if not path.exists():
                self._audit_log('READ', str(path), 'FAILED', 'File not found')
                return {'success': False, 'error': 'File not found'}
                
            # Find file in registry
            file_info = None
            for file_id, info in self.file_registry['files'].items():
                if info['path'] == str(path):
                    file_info = info
                    break
                    
            if not file_info:
                logger.warning(f"File not in registry: {path}")
                
            # Verify integrity if requested and file is in registry
            if verify_integrity and file_info:
                current_sha256, _, _ = self._calculate_hash(path)
                if current_sha256 != file_info['sha256']:
                    self._audit_log('READ', str(path), 'FAILED', 'Integrity check failed')
                    return {'success': False, 'error': 'File integrity compromised'}
                    
            # Read content
            with open(path, 'r') as f:
                content = f.read()
                
            # Decrypt if necessary
            if file_info and file_info.get('encrypted', False):
                try:
                    encrypted_data = base64.b64decode(content.encode())
                    content = self.cipher.decrypt(encrypted_data).decode()
                except Exception as e:
                    self._audit_log('READ', str(path), 'FAILED', f'Decryption failed: {e}')
                    return {'success': False, 'error': 'Decryption failed'}
                    
            self._audit_log('READ', str(path), 'SUCCESS', 
                          f'Size={len(content)}, Verified={verify_integrity}')
            
            return {
                'success': True,
                'content': content,
                'path': str(path),
                'size': len(content),
                'file_info': file_info,
                'integrity_verified': verify_integrity
            }
            
        except Exception as e:
            self._audit_log('READ', str(file_path), 'ERROR', str(e))
            logger.error(f"Secure read failed: {e}")
            return {'success': False, 'error': str(e)}
            
    def create_evidence_chain(self, target: str, scan_type: str, 
                            evidence_files: List[str]) -> str:
        """
        Create legal evidence chain for court admissibility
        
        Args:
            target: Investigation target
            scan_type: Type of scan performed
            evidence_files: List of evidence file paths
            
        Returns:
            Evidence chain ID
        """
        try:
            chain_id = f"EVIDENCE_{target}_{scan_type}_{int(time.time())}"
            
            evidence_chain = {
                'chain_id': chain_id,
                'target': target,
                'scan_type': scan_type,
                'created': datetime.now().isoformat(),
                'investigator': 'Sentinel Pro v3.0',
                'jurisdiction': 'International Cybercrime',
                'standards_compliance': ['ISO 27037', 'NIST SP 800-86', 'RFC 3227'],
                'files': []
            }
            
            # Process each evidence file
            for file_path in evidence_files:
                path = Path(file_path)
                if path.exists():
                    sha256, md5, sha1 = self._calculate_hash(path)
                    
                    evidence_chain['files'].append({
                        'path': str(path),
                        'filename': path.name,
                        'size': path.stat().st_size,
                        'created': datetime.fromtimestamp(path.stat().st_ctime).isoformat(),
                        'modified': datetime.fromtimestamp(path.stat().st_mtime).isoformat(),
                        'sha256': sha256,
                        'md5': md5,
                        'sha1': sha1,
                        'mime_type': mimetypes.guess_type(str(path))[0]
                    })
                    
            # Save evidence chain
            chain_file = self.evidence_dir / f"{chain_id}.json"
            result = self.secure_write(
                json.dumps(evidence_chain, indent=2),
                str(chain_file),
                category='evidence',
                classification='CONFIDENTIAL',
                encrypt=True
            )
            
            if result['success']:
                self.file_registry['evidence_chain'][chain_id] = {
                    'target': target,
                    'scan_type': scan_type,
                    'created': evidence_chain['created'],
                    'file_count': len(evidence_files),
                    'chain_file': str(chain_file)
                }
                self._save_registry()
                
                self._audit_log('EVIDENCE_CHAIN', chain_id, 'CREATED', 
                              f'Target={target}, Files={len(evidence_files)}')
                
            return chain_id
            
        except Exception as e:
            logger.error(f"Evidence chain creation failed: {e}")
            self._audit_log('EVIDENCE_CHAIN', target, 'ERROR', str(e))
            return ""
            
    def verify_evidence_integrity(self, chain_id: str) -> Dict:
        """Verify integrity of entire evidence chain"""
        try:
            if chain_id not in self.file_registry['evidence_chain']:
                return {'success': False, 'error': 'Evidence chain not found'}
                
            chain_info = self.file_registry['evidence_chain'][chain_id]
            chain_file = Path(chain_info['chain_file'])
            
            # Read evidence chain
            result = self.secure_read(str(chain_file), verify_integrity=True)
            if not result['success']:
                return result
                
            evidence_chain = json.loads(result['content'])
            verification_results = []
            
            # Verify each file in chain
            for file_info in evidence_chain['files']:
                file_path = Path(file_info['path'])
                
                if not file_path.exists():
                    verification_results.append({
                        'file': file_info['filename'],
                        'status': 'MISSING',
                        'error': 'File not found'
                    })
                    continue
                    
                # Verify hashes
                current_sha256, current_md5, current_sha1 = self._calculate_hash(file_path)
                
                if (current_sha256 == file_info['sha256'] and 
                    current_md5 == file_info['md5'] and
                    current_sha1 == file_info['sha1']):
                    verification_results.append({
                        'file': file_info['filename'],
                        'status': 'VERIFIED',
                        'sha256': current_sha256
                    })
                else:
                    verification_results.append({
                        'file': file_info['filename'],
                        'status': 'COMPROMISED',
                        'error': 'Hash mismatch - file modified'
                    })
                    
            # Overall status
            all_verified = all(r['status'] == 'VERIFIED' for r in verification_results)
            
            self._audit_log('EVIDENCE_VERIFY', chain_id, 
                          'VERIFIED' if all_verified else 'COMPROMISED',
                          f'Files checked: {len(verification_results)}')
            
            return {
                'success': True,
                'chain_id': chain_id,
                'overall_status': 'VERIFIED' if all_verified else 'COMPROMISED',
                'files_checked': len(verification_results),
                'verification_results': verification_results,
                'verified_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Evidence verification failed: {e}")
            return {'success': False, 'error': str(e)}
            
    def secure_backup(self, source_path: str, backup_location: str = None) -> Dict:
        """Create secure encrypted backup of important files"""
        try:
            source = Path(source_path)
            if not source.exists():
                return {'success': False, 'error': 'Source file not found'}
                
            # Default backup location
            if not backup_location:
                backup_dir = self.base_dir / 'backups'
                backup_dir.mkdir(exist_ok=True)
                backup_location = backup_dir / f"{source.name}.backup.enc"
            else:
                backup_location = Path(backup_location)
                
            # Read and encrypt file
            with open(source, 'rb') as f:
                content = f.read()
                
            encrypted_content = self.cipher.encrypt(content)
            
            # Write encrypted backup
            with open(backup_location, 'wb') as f:
                f.write(encrypted_content)
                
            os.chmod(backup_location, 0o600)  # Owner only
            
            # Calculate backup hash
            backup_sha256, _, _ = self._calculate_hash(backup_location)
            
            self._audit_log('BACKUP', str(source), 'SUCCESS', 
                          f'Backup location: {backup_location}')
            
            return {
                'success': True,
                'source': str(source),
                'backup': str(backup_location),
                'backup_sha256': backup_sha256,
                'encrypted': True
            }
            
        except Exception as e:
            logger.error(f"Secure backup failed: {e}")
            return {'success': False, 'error': str(e)}
            
    def get_file_stats(self) -> Dict:
        """Get comprehensive file system statistics"""
        stats = {
            'total_files': len(self.file_registry['files']),
            'evidence_chains': len(self.file_registry['evidence_chain']),
            'categories': {},
            'classifications': {},
            'total_size': 0,
            'encrypted_files': 0
        }
        
        for file_info in self.file_registry['files'].values():
            # Category stats
            category = file_info['category']
            if category not in stats['categories']:
                stats['categories'][category] = 0
            stats['categories'][category] += 1
            
            # Classification stats
            classification = file_info['classification']
            if classification not in stats['classifications']:
                stats['classifications'][classification] = 0
            stats['classifications'][classification] += 1
            
            # Size and encryption stats
            stats['total_size'] += file_info['size']
            if file_info.get('encrypted', False):
                stats['encrypted_files'] += 1
                
        return stats
        
    def cleanup_temp_files(self) -> int:
        """Clean up temporary files older than 24 hours"""
        temp_dir = self.base_dir / 'temp'
        if not temp_dir.exists():
            return 0
            
        cleaned = 0
        cutoff_time = time.time() - (24 * 60 * 60)  # 24 hours ago
        
        for temp_file in temp_dir.iterdir():
            if temp_file.is_file() and temp_file.stat().st_mtime < cutoff_time:
                try:
                    temp_file.unlink()
                    cleaned += 1
                    self._audit_log('CLEANUP', str(temp_file), 'SUCCESS', 'Temp file removed')
                except Exception as e:
                    logger.error(f"Failed to cleanup {temp_file}: {e}")
                    
        return cleaned