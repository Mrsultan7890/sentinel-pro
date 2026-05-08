#!/usr/bin/env python3
"""
Hardware Security Engine - TPM 2.0 Integration
Provides hardware-backed key storage and attestation
"""

import os
import subprocess
import json
from pathlib import Path
from typing import Optional, Dict, Any, List
import hashlib

class TPMManager:
    """TPM 2.0 Manager for hardware-backed security"""
    
    def __init__(self):
        """Initialize TPM manager"""
        self.tpm_available = self._check_tpm_available()
        self.tpm2_tools_available = self._check_tpm2_tools()
        self.key_dir = Path.home() / '.sentinel_pro' / 'tpm_keys'
        self.key_dir.mkdir(parents=True, exist_ok=True)
        
    def _check_tpm_available(self) -> bool:
        """Check if TPM 2.0 is available"""
        try:
            # Check for TPM device
            tpm_devices = [
                Path('/dev/tpm0'),
                Path('/dev/tpmrm0'),
                Path('/sys/class/tpm/tpm0')
            ]
            return any(dev.exists() for dev in tpm_devices)
        except:
            return False
    
    def _check_tpm2_tools(self) -> bool:
        """Check if tpm2-tools are installed"""
        try:
            result = subprocess.run(
                ['which', 'tpm2_createprimary'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get TPM status"""
        status = {
            'tpm_available': self.tpm_available,
            'tpm2_tools_installed': self.tpm2_tools_available,
            'key_directory': str(self.key_dir),
            'stored_keys': self._list_stored_keys()
        }
        
        if self.tpm_available and self.tpm2_tools_available:
            status.update(self._get_tpm_info())
        
        return status
    
    def _get_tpm_info(self) -> Dict[str, Any]:
        """Get TPM device information"""
        info = {}
        
        try:
            # Get TPM version
            result = subprocess.run(
                ['tpm2_getcap', 'properties-fixed'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                output = result.stdout
                # Parse manufacturer
                if 'TPM2_PT_MANUFACTURER' in output:
                    for line in output.split('\n'):
                        if 'TPM2_PT_MANUFACTURER' in line:
                            info['manufacturer'] = line.split(':')[-1].strip()
                        elif 'TPM2_PT_VENDOR_STRING' in line:
                            info['vendor'] = line.split(':')[-1].strip()
                        elif 'TPM2_PT_FIRMWARE_VERSION' in line:
                            info['firmware_version'] = line.split(':')[-1].strip()
        except Exception as e:
            info['error'] = str(e)
        
        return info
    
    def _list_stored_keys(self) -> List[str]:
        """List keys stored in key directory"""
        try:
            return [f.name for f in self.key_dir.iterdir() if f.is_file()]
        except:
            return []
    
    def create_primary_key(self, key_name: str = 'sentinel_primary') -> bool:
        """Create TPM primary key"""
        if not self.tpm_available or not self.tpm2_tools_available:
            print("[!] TPM not available or tpm2-tools not installed")
            return False
        
        try:
            ctx_file = self.key_dir / f'{key_name}.ctx'
            
            # Create primary key in owner hierarchy
            result = subprocess.run([
                'tpm2_createprimary',
                '-C', 'o',  # Owner hierarchy
                '-g', 'sha256',  # Hash algorithm
                '-G', 'rsa2048',  # Key algorithm
                '-c', str(ctx_file)
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print(f"[+] Primary key created: {ctx_file}")
                return True
            else:
                print(f"[!] Failed to create primary key: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"[!] Error creating primary key: {e}")
            return False
    
    def seal_data(self, data: bytes, key_name: str = 'sentinel_primary', 
                  sealed_name: str = 'sealed_data') -> bool:
        """Seal data to TPM (encrypt with TPM key)"""
        if not self.tpm_available or not self.tpm2_tools_available:
            print("[!] TPM not available")
            return False
        
        try:
            ctx_file = self.key_dir / f'{key_name}.ctx'
            if not ctx_file.exists():
                print("[!] Primary key not found. Create it first.")
                return False
            
            # Write data to temp file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as tmp:
                tmp.write(data)
                tmp_path = tmp.name
            
            sealed_file = self.key_dir / f'{sealed_name}.sealed'
            
            # Seal data
            result = subprocess.run([
                'tpm2_create',
                '-C', str(ctx_file),
                '-i', tmp_path,
                '-u', str(sealed_file) + '.pub',
                '-r', str(sealed_file) + '.priv'
            ], capture_output=True, text=True, timeout=30)
            
            os.unlink(tmp_path)
            
            if result.returncode == 0:
                print(f"[+] Data sealed: {sealed_file}")
                return True
            else:
                print(f"[!] Failed to seal data: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"[!] Error sealing data: {e}")
            return False
    
    def unseal_data(self, sealed_name: str = 'sealed_data', 
                    key_name: str = 'sentinel_primary') -> Optional[bytes]:
        """Unseal data from TPM (decrypt with TPM key)"""
        if not self.tpm_available or not self.tpm2_tools_available:
            print("[!] TPM not available")
            return None
        
        try:
            ctx_file = self.key_dir / f'{key_name}.ctx'
            sealed_file = self.key_dir / f'{sealed_name}.sealed'
            
            if not ctx_file.exists() or not Path(str(sealed_file) + '.pub').exists():
                print("[!] Sealed data or key not found")
                return None
            
            # Load sealed object
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ctx') as tmp:
                obj_ctx = tmp.name
            
            result = subprocess.run([
                'tpm2_load',
                '-C', str(ctx_file),
                '-u', str(sealed_file) + '.pub',
                '-r', str(sealed_file) + '.priv',
                '-c', obj_ctx
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                print(f"[!] Failed to load sealed object: {result.stderr}")
                os.unlink(obj_ctx)
                return None
            
            # Unseal data
            with tempfile.NamedTemporaryFile(mode='rb', delete=False) as tmp:
                out_path = tmp.name
            
            result = subprocess.run([
                'tpm2_unseal',
                '-c', obj_ctx,
                '-o', out_path
            ], capture_output=True, text=True, timeout=30)
            
            os.unlink(obj_ctx)
            
            if result.returncode == 0:
                with open(out_path, 'rb') as f:
                    data = f.read()
                os.unlink(out_path)
                print(f"[+] Data unsealed successfully")
                return data
            else:
                print(f"[!] Failed to unseal data: {result.stderr}")
                if os.path.exists(out_path):
                    os.unlink(out_path)
                return None
                
        except Exception as e:
            print(f"[!] Error unsealing data: {e}")
            return None
    
    def get_pcr_values(self) -> Dict[int, str]:
        """Get Platform Configuration Register (PCR) values"""
        if not self.tpm_available or not self.tpm2_tools_available:
            return {}
        
        try:
            result = subprocess.run(
                ['tpm2_pcrread', 'sha256'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                pcrs = {}
                for line in result.stdout.split('\n'):
                    if ':' in line and 'sha256' not in line.lower():
                        parts = line.strip().split(':')
                        if len(parts) == 2:
                            try:
                                pcr_num = int(parts[0].strip())
                                pcr_val = parts[1].strip()
                                pcrs[pcr_num] = pcr_val
                            except:
                                pass
                return pcrs
        except Exception as e:
            print(f"[!] Error reading PCRs: {e}")
        
        return {}
    
    def extend_pcr(self, pcr_index: int, data: bytes) -> bool:
        """Extend PCR with data (for attestation)"""
        if not self.tpm_available or not self.tpm2_tools_available:
            return False
        
        try:
            # Hash the data
            data_hash = hashlib.sha256(data).hexdigest()
            
            result = subprocess.run([
                'tpm2_pcrextend',
                f'{pcr_index}:sha256={data_hash}'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print(f"[+] PCR {pcr_index} extended")
                return True
            else:
                print(f"[!] Failed to extend PCR: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"[!] Error extending PCR: {e}")
            return False


def main():
    """CLI interface"""
    import sys
    
    tpm = TPMManager()
    
    if len(sys.argv) < 2:
        print("\n" + "="*60)
        print("  TPM 2.0 HARDWARE SECURITY ENGINE")
        print("="*60)
        
        status = tpm.get_status()
        
        print(f"  TPM Available      : {'✓ YES' if status['tpm_available'] else '✗ NO'}")
        print(f"  TPM2-Tools         : {'✓ YES' if status['tpm2_tools_installed'] else '✗ NO'}")
        
        if not status['tpm_available']:
            print("\n  [!] No TPM device found")
            print("  [!] This system does not have TPM 2.0 hardware")
        elif not status['tpm2_tools_installed']:
            print("\n  [!] tpm2-tools not installed")
            print("  [!] Install: sudo apt install tpm2-tools")
        else:
            if 'manufacturer' in status:
                print(f"  Manufacturer       : {status.get('manufacturer', 'N/A')}")
                print(f"  Vendor             : {status.get('vendor', 'N/A')}")
                print(f"  Firmware           : {status.get('firmware_version', 'N/A')}")
            
            print(f"\n  Key Directory      : {status['key_directory']}")
            print(f"  Stored Keys        : {len(status['stored_keys'])}")
            
            if status['stored_keys']:
                print("\n  Keys:")
                for key in status['stored_keys']:
                    print(f"    • {key}")
        
        print("\n" + "="*60)
        print("\nUsage:")
        print("  python3 tpm_manager.py status")
        print("  python3 tpm_manager.py create_key [name]")
        print("  python3 tpm_manager.py seal <data> [sealed_name]")
        print("  python3 tpm_manager.py unseal <sealed_name>")
        print("  python3 tpm_manager.py pcr")
        print("="*60 + "\n")
        return
    
    cmd = sys.argv[1]
    
    if cmd == "status":
        status = tpm.get_status()
        print(json.dumps(status, indent=2))
    
    elif cmd == "create_key":
        key_name = sys.argv[2] if len(sys.argv) > 2 else 'sentinel_primary'
        tpm.create_primary_key(key_name)
    
    elif cmd == "seal":
        if len(sys.argv) < 3:
            print("[!] Usage: seal <data> [sealed_name]")
            return
        data = sys.argv[2].encode()
        sealed_name = sys.argv[3] if len(sys.argv) > 3 else 'sealed_data'
        tpm.seal_data(data, sealed_name=sealed_name)
    
    elif cmd == "unseal":
        if len(sys.argv) < 3:
            print("[!] Usage: unseal <sealed_name>")
            return
        sealed_name = sys.argv[2]
        data = tpm.unseal_data(sealed_name)
        if data:
            print(f"[+] Unsealed data: {data.decode()}")
    
    elif cmd == "pcr":
        pcrs = tpm.get_pcr_values()
        print("\n[*] Platform Configuration Registers (PCRs):\n")
        for pcr_num, pcr_val in sorted(pcrs.items()):
            print(f"  PCR {pcr_num:2d}: {pcr_val}")
        print()
    
    else:
        print(f"[!] Unknown command: {cmd}")


if __name__ == "__main__":
    main()
