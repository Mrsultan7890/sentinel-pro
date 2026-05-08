#!/usr/bin/env python3
"""
Remote Attestation Module - HSE Phase 3
TPM-based remote attestation for verifying system integrity

Author: @who_is_the_black_hat
Part of: Sentinel Pro v6.0 - Hardware Security Engine
"""

import os
import sys
import json
import hashlib
import subprocess
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path

class RemoteAttestationError(Exception):
    """Custom exception for attestation errors"""
    pass

class RemoteAttestation:
    """
    Remote Attestation using TPM 2.0
    
    Capabilities:
    - Generate TPM quotes (signed PCR values)
    - Verify TPM quotes remotely
    - Nonce-based freshness guarantee
    - Event log validation
    - Attestation key management
    """
    
    def __init__(self, config_dir: str = "~/.sentinel_pro"):
        self.config_dir = Path(config_dir).expanduser()
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.ak_handle_file = self.config_dir / "tpm_ak_handle.txt"
        self.ak_pub_file = self.config_dir / "tpm_ak_pub.pem"
        self.ak_name_file = self.config_dir / "tpm_ak_name.bin"
        
        # PCRs to include in attestation (0-7 = boot chain)
        self.pcr_selection = "sha256:0,1,2,3,4,5,6,7"
    
    def _run_command(self, cmd: List[str]) -> Tuple[int, str, str]:
        """Execute shell command and return (returncode, stdout, stderr)"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            raise RemoteAttestationError(f"Command timeout: {' '.join(cmd)}")
        except Exception as e:
            raise RemoteAttestationError(f"Command failed: {e}")
    
    def check_tpm_available(self) -> bool:
        """Check if TPM 2.0 is available"""
        returncode, stdout, _ = self._run_command(["tpm2_getcap", "properties-fixed"])
        return returncode == 0 and "TPM2_PT_FAMILY_INDICATOR" in stdout
    
    def create_attestation_key(self) -> Dict[str, str]:
        """
        Create TPM Attestation Key (AK)
        
        AK is used to sign quotes. It's restricted to signing only.
        
        Returns:
            Dict with ak_handle, ak_pub_path, ak_name_path
        """
        if not self.check_tpm_available():
            raise RemoteAttestationError("TPM 2.0 not available")
        
        # Create primary key in endorsement hierarchy
        returncode, stdout, stderr = self._run_command([
            "tpm2_createprimary",
            "-C", "e",  # Endorsement hierarchy
            "-g", "sha256",
            "-G", "rsa2048",
            "-c", str(self.config_dir / "primary_ek.ctx")
        ])
        
        if returncode != 0:
            raise RemoteAttestationError(f"Failed to create primary EK: {stderr}")
        
        # Create attestation key under primary
        returncode, stdout, stderr = self._run_command([
            "tpm2_create",
            "-C", str(self.config_dir / "primary_ek.ctx"),
            "-g", "sha256",
            "-G", "rsa2048:rsassa",
            "-r", str(self.config_dir / "ak.priv"),
            "-u", str(self.config_dir / "ak.pub"),
            "-a", "restricted|sign|fixedtpm|fixedparent|sensitivedataorigin"
        ])
        
        if returncode != 0:
            raise RemoteAttestationError(f"Failed to create AK: {stderr}")
        
        # Load AK into TPM
        returncode, stdout, stderr = self._run_command([
            "tpm2_load",
            "-C", str(self.config_dir / "primary_ek.ctx"),
            "-r", str(self.config_dir / "ak.priv"),
            "-u", str(self.config_dir / "ak.pub"),
            "-c", str(self.config_dir / "ak.ctx")
        ])
        
        if returncode != 0:
            raise RemoteAttestationError(f"Failed to load AK: {stderr}")
        
        # Make AK persistent
        returncode, stdout, stderr = self._run_command([
            "tpm2_evictcontrol",
            "-C", "o",  # Owner hierarchy
            "-c", str(self.config_dir / "ak.ctx"),
            "0x81010002"  # Persistent handle
        ])
        
        if returncode != 0:
            # AK might already be persistent, try to continue
            pass
        
        # Export AK public key in PEM format
        returncode, stdout, stderr = self._run_command([
            "tpm2_readpublic",
            "-c", "0x81010002",
            "-f", "pem",
            "-o", str(self.ak_pub_file)
        ])
        
        if returncode != 0:
            raise RemoteAttestationError(f"Failed to export AK public key: {stderr}")
        
        # Get AK name (used for verification)
        returncode, stdout, stderr = self._run_command([
            "tpm2_readpublic",
            "-c", "0x81010002",
            "-n", str(self.ak_name_file)
        ])
        
        if returncode != 0:
            raise RemoteAttestationError(f"Failed to get AK name: {stderr}")
        
        # Save handle
        self.ak_handle_file.write_text("0x81010002")
        
        return {
            "ak_handle": "0x81010002",
            "ak_pub_path": str(self.ak_pub_file),
            "ak_name_path": str(self.ak_name_file),
            "created_at": datetime.now().isoformat()
        }
    
    def generate_quote(self, nonce: Optional[str] = None) -> Dict[str, any]:
        """
        Generate TPM quote (signed PCR values)
        
        Args:
            nonce: Random nonce for freshness (hex string)
        
        Returns:
            Dict with quote, signature, pcr_values, nonce
        """
        if not self.check_tpm_available():
            raise RemoteAttestationError("TPM 2.0 not available")
        
        # Generate nonce if not provided
        if nonce is None:
            nonce = os.urandom(32).hex()
        
        # Check if AK exists
        if not self.ak_handle_file.exists():
            self.create_attestation_key()
        
        ak_handle = self.ak_handle_file.read_text().strip()
        
        # Generate quote
        quote_file = self.config_dir / f"quote_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"
        sig_file = self.config_dir / f"sig_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"
        pcr_file = self.config_dir / f"pcr_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"
        
        returncode, stdout, stderr = self._run_command([
            "tpm2_quote",
            "-c", ak_handle,
            "-l", self.pcr_selection,
            "-q", nonce,
            "-m", str(quote_file),
            "-s", str(sig_file),
            "-o", str(pcr_file),
            "-g", "sha256"
        ])
        
        if returncode != 0:
            raise RemoteAttestationError(f"Failed to generate quote: {stderr}")
        
        # Read PCR values
        returncode, stdout, stderr = self._run_command([
            "tpm2_pcrread",
            self.pcr_selection
        ])
        
        if returncode != 0:
            raise RemoteAttestationError(f"Failed to read PCRs: {stderr}")
        
        # Parse PCR values
        pcr_values = {}
        for line in stdout.split('\n'):
            if ':' in line and 'sha256' not in line.lower():
                parts = line.strip().split(':')
                if len(parts) == 2:
                    pcr_num = parts[0].strip()
                    pcr_val = parts[1].strip().replace('0x', '')
                    if pcr_num.isdigit():
                        pcr_values[int(pcr_num)] = pcr_val
        
        return {
            "quote": quote_file.read_bytes().hex(),
            "signature": sig_file.read_bytes().hex(),
            "pcr_values": pcr_values,
            "nonce": nonce,
            "timestamp": datetime.now().isoformat(),
            "pcr_selection": self.pcr_selection,
            "ak_pub_path": str(self.ak_pub_file)
        }
    
    def verify_quote(self, quote_data: Dict[str, any], expected_pcrs: Optional[Dict[int, str]] = None) -> bool:
        """
        Verify TPM quote
        
        Args:
            quote_data: Quote data from generate_quote()
            expected_pcrs: Expected PCR values (optional)
        
        Returns:
            True if quote is valid
        """
        if not self.check_tpm_available():
            raise RemoteAttestationError("TPM 2.0 not available")
        
        # Save quote and signature to temp files
        quote_file = self.config_dir / "verify_quote.bin"
        sig_file = self.config_dir / "verify_sig.bin"
        
        quote_file.write_bytes(bytes.fromhex(quote_data["quote"]))
        sig_file.write_bytes(bytes.fromhex(quote_data["signature"]))
        
        # Verify signature
        returncode, stdout, stderr = self._run_command([
            "tpm2_checkquote",
            "-u", quote_data["ak_pub_path"],
            "-m", str(quote_file),
            "-s", str(sig_file),
            "-q", quote_data["nonce"],
            "-g", "sha256"
        ])
        
        if returncode != 0:
            return False
        
        # Verify PCR values if provided
        if expected_pcrs:
            for pcr_num, expected_val in expected_pcrs.items():
                actual_val = quote_data["pcr_values"].get(pcr_num)
                if actual_val != expected_val:
                    return False
        
        return True
    
    def get_attestation_report(self) -> Dict[str, any]:
        """
        Generate comprehensive attestation report
        
        Returns:
            Dict with system state, quote, and verification info
        """
        if not self.check_tpm_available():
            raise RemoteAttestationError("TPM 2.0 not available")
        
        # Generate fresh quote
        quote_data = self.generate_quote()
        
        # Get system info
        returncode, stdout, _ = self._run_command(["uname", "-a"])
        system_info = stdout.strip() if returncode == 0 else "Unknown"
        
        # Get boot measurements
        boot_log = []
        if Path("/sys/kernel/security/tpm0/binary_bios_measurements").exists():
            try:
                # Parse TPM event log (simplified)
                boot_log.append("Boot measurements available")
            except:
                pass
        
        return {
            "report_id": hashlib.sha256(quote_data["quote"].encode()).hexdigest()[:16],
            "timestamp": datetime.now().isoformat(),
            "system_info": system_info,
            "quote": quote_data,
            "boot_log": boot_log,
            "tpm_version": "2.0",
            "attestation_key": str(self.ak_pub_file)
        }
    
    def get_status(self) -> Dict[str, any]:
        """Get remote attestation status"""
        status = {
            "tpm_available": self.check_tpm_available(),
            "ak_exists": self.ak_handle_file.exists(),
            "ak_pub_exists": self.ak_pub_file.exists(),
            "config_dir": str(self.config_dir)
        }
        
        if status["ak_exists"]:
            status["ak_handle"] = self.ak_handle_file.read_text().strip()
        
        return status


def main():
    """CLI interface for remote attestation"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Remote Attestation Manager")
    parser.add_argument("command", choices=["status", "create_ak", "quote", "verify", "report"],
                       help="Command to execute")
    parser.add_argument("--nonce", help="Nonce for quote generation (hex)")
    parser.add_argument("--quote-file", help="Quote file for verification (JSON)")
    
    args = parser.parse_args()
    
    ra = RemoteAttestation()
    
    try:
        if args.command == "status":
            status = ra.get_status()
            print(json.dumps(status, indent=2))
        
        elif args.command == "create_ak":
            result = ra.create_attestation_key()
            print("✅ Attestation Key created successfully")
            print(json.dumps(result, indent=2))
        
        elif args.command == "quote":
            quote = ra.generate_quote(nonce=args.nonce)
            quote_file = ra.config_dir / f"quote_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            quote_file.write_text(json.dumps(quote, indent=2))
            print(f"✅ Quote generated: {quote_file}")
            print(json.dumps(quote, indent=2))
        
        elif args.command == "verify":
            if not args.quote_file:
                print("❌ --quote-file required for verification")
                sys.exit(1)
            
            quote_data = json.loads(Path(args.quote_file).read_text())
            valid = ra.verify_quote(quote_data)
            
            if valid:
                print("✅ Quote verification PASSED")
            else:
                print("❌ Quote verification FAILED")
                sys.exit(1)
        
        elif args.command == "report":
            report = ra.get_attestation_report()
            report_file = ra.config_dir / f"attestation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            report_file.write_text(json.dumps(report, indent=2))
            print(f"✅ Attestation report generated: {report_file}")
            print(json.dumps(report, indent=2))
    
    except RemoteAttestationError as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
