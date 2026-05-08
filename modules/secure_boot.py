#!/usr/bin/env python3
"""
Secure Boot Verification
Verifies boot chain integrity and detects tampering
"""

import os
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
import hashlib

class SecureBootVerifier:
    """Secure Boot verification and monitoring"""
    
    def __init__(self):
        """Initialize secure boot verifier"""
        self.efi_vars = Path('/sys/firmware/efi/efivars')
        self.secure_boot_enabled = self._check_secure_boot()
        
    def _check_secure_boot(self) -> bool:
        """Check if Secure Boot is enabled"""
        try:
            # Method 1: Check EFI variable
            sb_file = self.efi_vars / 'SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c'
            if sb_file.exists():
                with open(sb_file, 'rb') as f:
                    data = f.read()
                    # Last byte indicates status (1 = enabled)
                    return data[-1] == 1
            
            # Method 2: Check via mokutil
            result = subprocess.run(
                ['mokutil', '--sb-state'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return 'SecureBoot enabled' in result.stdout
                
        except:
            pass
        
        return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get secure boot status"""
        status = {
            'secure_boot_enabled': self.secure_boot_enabled,
            'efi_mode': self._check_efi_mode(),
            'boot_mode': self._get_boot_mode(),
            'shim_verification': self._check_shim(),
            'kernel_lockdown': self._check_kernel_lockdown()
        }
        
        if self.secure_boot_enabled:
            status['certificates'] = self._get_secure_boot_certs()
        
        return status
    
    def _check_efi_mode(self) -> bool:
        """Check if system booted in EFI mode"""
        return Path('/sys/firmware/efi').exists()
    
    def _get_boot_mode(self) -> str:
        """Get boot mode (UEFI or Legacy)"""
        if self._check_efi_mode():
            return 'UEFI'
        return 'Legacy BIOS'
    
    def _check_shim(self) -> bool:
        """Check if shim bootloader is present"""
        shim_paths = [
            Path('/boot/efi/EFI/ubuntu/shimx64.efi'),
            Path('/boot/efi/EFI/debian/shimx64.efi'),
            Path('/boot/efi/EFI/BOOT/BOOTX64.EFI')
        ]
        return any(p.exists() for p in shim_paths)
    
    def _check_kernel_lockdown(self) -> Optional[str]:
        """Check kernel lockdown mode"""
        try:
            lockdown_file = Path('/sys/kernel/security/lockdown')
            if lockdown_file.exists():
                content = lockdown_file.read_text().strip()
                # Parse: [none] integrity confidentiality
                if '[none]' in content:
                    return 'none'
                elif '[integrity]' in content:
                    return 'integrity'
                elif '[confidentiality]' in content:
                    return 'confidentiality'
        except:
            pass
        return None
    
    def _get_secure_boot_certs(self) -> List[str]:
        """Get Secure Boot certificates"""
        certs = []
        
        try:
            # Try to read db (authorized database)
            db_file = self.efi_vars / 'db-d719b2cb-3d3a-4596-a3bc-dad00e67656f'
            if db_file.exists():
                certs.append('db (Authorized Database)')
            
            # Try to read dbx (forbidden database)
            dbx_file = self.efi_vars / 'dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f'
            if dbx_file.exists():
                certs.append('dbx (Forbidden Database)')
            
            # Try to read KEK (Key Exchange Key)
            kek_file = self.efi_vars / 'KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c'
            if kek_file.exists():
                certs.append('KEK (Key Exchange Key)')
            
            # Try to read PK (Platform Key)
            pk_file = self.efi_vars / 'PK-8be4df61-93ca-11d2-aa0d-00e098032b8c'
            if pk_file.exists():
                certs.append('PK (Platform Key)')
                
        except:
            pass
        
        return certs
    
    def measure_boot_chain(self) -> Dict[str, str]:
        """Measure boot chain components"""
        measurements = {}
        
        # Measure bootloader
        bootloaders = [
            '/boot/efi/EFI/ubuntu/shimx64.efi',
            '/boot/efi/EFI/ubuntu/grubx64.efi',
            '/boot/vmlinuz',
            '/boot/initrd.img'
        ]
        
        for bootloader in bootloaders:
            path = Path(bootloader)
            if path.exists():
                try:
                    with open(path, 'rb') as f:
                        data = f.read()
                        sha256 = hashlib.sha256(data).hexdigest()
                        measurements[bootloader] = sha256
                except:
                    measurements[bootloader] = 'ERROR'
        
        return measurements
    
    def verify_boot_integrity(self) -> Dict[str, Any]:
        """Verify boot chain integrity"""
        result = {
            'status': 'UNKNOWN',
            'checks': [],
            'warnings': [],
            'critical': []
        }
        
        # Check 1: Secure Boot
        if self.secure_boot_enabled:
            result['checks'].append('✓ Secure Boot enabled')
        else:
            result['warnings'].append('⚠ Secure Boot disabled')
        
        # Check 2: EFI mode
        if self._check_efi_mode():
            result['checks'].append('✓ UEFI boot mode')
        else:
            result['warnings'].append('⚠ Legacy BIOS mode')
        
        # Check 3: Kernel lockdown
        lockdown = self._check_kernel_lockdown()
        if lockdown in ['integrity', 'confidentiality']:
            result['checks'].append(f'✓ Kernel lockdown: {lockdown}')
        else:
            result['warnings'].append(f'⚠ Kernel lockdown: {lockdown or "disabled"}')
        
        # Check 4: Boot measurements
        measurements = self.measure_boot_chain()
        if measurements:
            result['checks'].append(f'✓ Boot chain measured ({len(measurements)} components)')
        
        # Determine overall status
        if result['critical']:
            result['status'] = 'CRITICAL'
        elif result['warnings']:
            result['status'] = 'WARNING'
        else:
            result['status'] = 'OK'
        
        return result
    
    def detect_boot_tampering(self, baseline: Optional[Dict[str, str]] = None) -> List[str]:
        """Detect boot chain tampering"""
        tampering = []
        
        current = self.measure_boot_chain()
        
        if baseline:
            for component, current_hash in current.items():
                if component in baseline:
                    if baseline[component] != current_hash:
                        tampering.append(f"TAMPERED: {component}")
        
        return tampering


def main():
    """CLI interface"""
    import sys
    import json
    
    verifier = SecureBootVerifier()
    
    if len(sys.argv) < 2:
        print("\n" + "="*60)
        print("  SECURE BOOT VERIFICATION")
        print("="*60)
        
        status = verifier.get_status()
        
        print(f"  Secure Boot        : {'✓ ENABLED' if status['secure_boot_enabled'] else '✗ DISABLED'}")
        print(f"  EFI Mode           : {'✓ YES' if status['efi_mode'] else '✗ NO'}")
        print(f"  Boot Mode          : {status['boot_mode']}")
        print(f"  Shim Present       : {'✓ YES' if status['shim_verification'] else '✗ NO'}")
        print(f"  Kernel Lockdown    : {status['kernel_lockdown'] or 'disabled'}")
        
        if status.get('certificates'):
            print(f"\n  Certificates:")
            for cert in status['certificates']:
                print(f"    • {cert}")
        
        print("\n" + "="*60)
        print("\nUsage:")
        print("  python3 secure_boot.py status")
        print("  python3 secure_boot.py verify")
        print("  python3 secure_boot.py measure")
        print("="*60 + "\n")
        return
    
    cmd = sys.argv[1]
    
    if cmd == "status":
        status = verifier.get_status()
        print(json.dumps(status, indent=2))
    
    elif cmd == "verify":
        result = verifier.verify_boot_integrity()
        
        print("\n" + "="*60)
        print(f"  BOOT INTEGRITY: {result['status']}")
        print("="*60)
        
        if result['checks']:
            print("\n  Passed Checks:")
            for check in result['checks']:
                print(f"    {check}")
        
        if result['warnings']:
            print("\n  Warnings:")
            for warning in result['warnings']:
                print(f"    {warning}")
        
        if result['critical']:
            print("\n  CRITICAL Issues:")
            for critical in result['critical']:
                print(f"    {critical}")
        
        print("\n" + "="*60 + "\n")
    
    elif cmd == "measure":
        measurements = verifier.measure_boot_chain()
        
        print("\n" + "="*60)
        print("  BOOT CHAIN MEASUREMENTS")
        print("="*60 + "\n")
        
        for component, sha256 in measurements.items():
            print(f"  {component}")
            print(f"    SHA256: {sha256}\n")
        
        print("="*60 + "\n")
    
    else:
        print(f"[!] Unknown command: {cmd}")


if __name__ == "__main__":
    main()
