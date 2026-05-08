#!/usr/bin/env python3
"""
DMA Attack Prevention Module - HSE Phase 5
IOMMU-based protection against DMA attacks (Thunderbolt, PCIe, etc.)

Author: @who_is_the_black_hat
Part of: Sentinel Pro v6.0 - Hardware Security Engine

DMA Attacks:
- Thunderbolt DMA attacks
- PCIe device attacks
- Firewire attacks
- USB-C with Thunderbolt
- Malicious peripherals

Protection:
- IOMMU (VT-d/AMD-Vi) enforcement
- Device whitelisting
- DMA remapping
- Interrupt remapping
"""

import os
import sys
import json
import subprocess
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path

class DMAProtectionError(Exception):
    """Custom exception for DMA protection errors"""
    pass

class DMAProtection:
    """
    DMA Attack Prevention Manager
    
    Capabilities:
    - Detect IOMMU support (Intel VT-d, AMD-Vi)
    - Enable/disable IOMMU
    - Device whitelisting
    - DMA remapping status
    - Thunderbolt security levels
    - PCIe device monitoring
    """
    
    def __init__(self, config_dir: str = "~/.sentinel_pro"):
        self.config_dir = Path(config_dir).expanduser()
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.whitelist_file = self.config_dir / "dma_whitelist.json"
        self.log_file = self.config_dir / "dma_protection.log"
    
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
            raise DMAProtectionError(f"Command timeout: {' '.join(cmd)}")
        except Exception as e:
            raise DMAProtectionError(f"Command failed: {e}")
    
    def _log(self, message: str):
        """Log message to file"""
        timestamp = datetime.now().isoformat()
        log_entry = f"[{timestamp}] {message}\n"
        
        with open(self.log_file, 'a') as f:
            f.write(log_entry)
    
    def check_iommu_support(self) -> Dict[str, any]:
        """
        Check IOMMU support
        
        Returns:
            Dict with iommu_available, iommu_type, iommu_enabled
        """
        result = {
            "iommu_available": False,
            "iommu_type": None,  # "intel" or "amd"
            "iommu_enabled": False,
            "iommu_groups": 0,
            "dma_remapping": False,
            "interrupt_remapping": False
        }
        
        # Check for Intel VT-d
        returncode, stdout, _ = self._run_command(["dmesg"])
        if returncode == 0:
            if "Intel-IOMMU" in stdout or "DMAR" in stdout:
                result["iommu_type"] = "intel"
                result["iommu_available"] = True
                
                if "Intel-IOMMU: enabled" in stdout:
                    result["iommu_enabled"] = True
                
                if "DMAR: DMA remapping" in stdout:
                    result["dma_remapping"] = True
                
                if "DMAR: Interrupt remapping" in stdout:
                    result["interrupt_remapping"] = True
            
            # Check for AMD-Vi
            elif "AMD-Vi" in stdout or "AMD IOMMU" in stdout:
                result["iommu_type"] = "amd"
                result["iommu_available"] = True
                
                if "AMD-Vi: Enabled" in stdout or "AMD-Vi: Initialized" in stdout:
                    result["iommu_enabled"] = True
        
        # Check IOMMU groups
        iommu_groups_dir = Path("/sys/kernel/iommu_groups")
        if iommu_groups_dir.exists():
            result["iommu_groups"] = len(list(iommu_groups_dir.iterdir()))
        
        # Check kernel parameters
        try:
            cmdline = Path("/proc/cmdline").read_text()
            if "iommu=on" in cmdline or "intel_iommu=on" in cmdline or "amd_iommu=on" in cmdline:
                result["iommu_enabled"] = True
        except:
            pass
        
        return result
    
    def check_thunderbolt_security(self) -> Dict[str, any]:
        """
        Check Thunderbolt security level
        
        Security levels:
        - none: No security (DMA attacks possible)
        - user: User authorization required
        - secure: Challenge-response authentication
        - dponly: DisplayPort only (no PCIe tunneling)
        """
        result = {
            "thunderbolt_present": False,
            "security_level": None,
            "devices": []
        }
        
        # Check for Thunderbolt controllers
        tb_dir = Path("/sys/bus/thunderbolt/devices")
        if tb_dir.exists():
            result["thunderbolt_present"] = True
            
            # Check security level
            for domain in tb_dir.glob("domain*"):
                security_file = domain / "security"
                if security_file.exists():
                    result["security_level"] = security_file.read_text().strip()
            
            # List devices
            for device in tb_dir.glob("*-*"):
                device_name_file = device / "device_name"
                if device_name_file.exists():
                    result["devices"].append({
                        "name": device_name_file.read_text().strip(),
                        "path": str(device)
                    })
        
        return result
    
    def get_pcie_devices(self) -> List[Dict[str, str]]:
        """
        Get list of PCIe devices
        
        Returns:
            List of PCIe devices with vendor, device, class
        """
        devices = []
        
        returncode, stdout, _ = self._run_command(["lspci", "-nn"])
        if returncode == 0:
            for line in stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        devices.append({
                            "address": parts[0],
                            "description": ' '.join(parts[1:])
                        })
        
        return devices
    
    def get_usb_devices(self) -> List[Dict[str, str]]:
        """
        Get list of USB devices (potential DMA via USB-C/Thunderbolt)
        
        Returns:
            List of USB devices
        """
        devices = []
        
        returncode, stdout, _ = self._run_command(["lsusb"])
        if returncode == 0:
            for line in stdout.split('\n'):
                if line.strip():
                    devices.append({
                        "description": line.strip()
                    })
        
        return devices
    
    def enable_iommu(self) -> Dict[str, str]:
        """
        Enable IOMMU (requires reboot)
        
        Returns:
            Dict with instructions
        """
        iommu_support = self.check_iommu_support()
        
        if not iommu_support["iommu_available"]:
            raise DMAProtectionError("IOMMU not supported by hardware")
        
        if iommu_support["iommu_enabled"]:
            return {
                "status": "already_enabled",
                "message": "IOMMU is already enabled"
            }
        
        # Determine kernel parameter
        if iommu_support["iommu_type"] == "intel":
            param = "intel_iommu=on"
        elif iommu_support["iommu_type"] == "amd":
            param = "amd_iommu=on"
        else:
            param = "iommu=on"
        
        # Instructions for enabling
        grub_file = "/etc/default/grub"
        
        instructions = f"""
To enable IOMMU, add the following to {grub_file}:

GRUB_CMDLINE_LINUX_DEFAULT="... {param}"

Then run:
  sudo update-grub
  sudo reboot

For maximum security, also add:
  iommu=force
  iommu.passthrough=0
  iommu.strict=1
"""
        
        self._log(f"IOMMU enable requested: {param}")
        
        return {
            "status": "instructions_provided",
            "parameter": param,
            "instructions": instructions,
            "grub_file": grub_file
        }
    
    def set_thunderbolt_security(self, level: str) -> Dict[str, str]:
        """
        Set Thunderbolt security level
        
        Args:
            level: Security level (user, secure, dponly)
        
        Returns:
            Dict with status
        """
        valid_levels = ["user", "secure", "dponly"]
        if level not in valid_levels:
            raise DMAProtectionError(f"Invalid security level. Must be one of: {valid_levels}")
        
        tb_status = self.check_thunderbolt_security()
        
        if not tb_status["thunderbolt_present"]:
            raise DMAProtectionError("Thunderbolt not present on this system")
        
        # Find Thunderbolt domain
        tb_dir = Path("/sys/bus/thunderbolt/devices")
        security_file = None
        
        for domain in tb_dir.glob("domain*"):
            security_file = domain / "security"
            if security_file.exists():
                break
        
        if not security_file:
            raise DMAProtectionError("Thunderbolt security file not found")
        
        # Set security level (requires root)
        try:
            returncode, stdout, stderr = self._run_command([
                "sudo", "sh", "-c", f"echo {level} > {security_file}"
            ])
            
            if returncode != 0:
                raise DMAProtectionError(f"Failed to set security level: {stderr}")
            
            self._log(f"Thunderbolt security set to: {level}")
            
            return {
                "status": "success",
                "level": level,
                "message": f"Thunderbolt security set to {level}"
            }
        
        except Exception as e:
            raise DMAProtectionError(f"Failed to set security level: {e}")
    
    def add_device_to_whitelist(self, device_id: str, description: str = ""):
        """
        Add device to DMA whitelist
        
        Args:
            device_id: Device identifier (PCI address or USB ID)
            description: Human-readable description
        """
        whitelist = self.load_whitelist()
        
        whitelist[device_id] = {
            "description": description,
            "added_at": datetime.now().isoformat()
        }
        
        self.save_whitelist(whitelist)
        self._log(f"Device added to whitelist: {device_id}")
    
    def remove_device_from_whitelist(self, device_id: str):
        """Remove device from DMA whitelist"""
        whitelist = self.load_whitelist()
        
        if device_id in whitelist:
            del whitelist[device_id]
            self.save_whitelist(whitelist)
            self._log(f"Device removed from whitelist: {device_id}")
        else:
            raise DMAProtectionError(f"Device not in whitelist: {device_id}")
    
    def load_whitelist(self) -> Dict[str, Dict]:
        """Load device whitelist"""
        if self.whitelist_file.exists():
            return json.loads(self.whitelist_file.read_text())
        return {}
    
    def save_whitelist(self, whitelist: Dict[str, Dict]):
        """Save device whitelist"""
        self.whitelist_file.write_text(json.dumps(whitelist, indent=2))
    
    def scan_for_threats(self) -> List[Dict[str, any]]:
        """
        Scan for potential DMA threats
        
        Returns:
            List of potential threats
        """
        threats = []
        
        # Check IOMMU status
        iommu_support = self.check_iommu_support()
        if not iommu_support["iommu_enabled"]:
            threats.append({
                "type": "iommu_disabled",
                "severity": "HIGH",
                "message": "IOMMU is not enabled - DMA attacks possible",
                "recommendation": "Enable IOMMU in BIOS and kernel parameters"
            })
        
        # Check Thunderbolt security
        tb_status = self.check_thunderbolt_security()
        if tb_status["thunderbolt_present"]:
            if tb_status["security_level"] == "none":
                threats.append({
                    "type": "thunderbolt_insecure",
                    "severity": "CRITICAL",
                    "message": "Thunderbolt security is disabled",
                    "recommendation": "Set Thunderbolt security to 'secure' or 'dponly'"
                })
            elif tb_status["security_level"] == "user":
                threats.append({
                    "type": "thunderbolt_weak",
                    "severity": "MEDIUM",
                    "message": "Thunderbolt security is set to 'user' (weak)",
                    "recommendation": "Consider upgrading to 'secure' level"
                })
        
        # Check for unknown devices
        whitelist = self.load_whitelist()
        pcie_devices = self.get_pcie_devices()
        
        for device in pcie_devices:
            if device["address"] not in whitelist:
                threats.append({
                    "type": "unknown_device",
                    "severity": "LOW",
                    "message": f"Unknown PCIe device: {device['description']}",
                    "device": device,
                    "recommendation": "Review device and add to whitelist if trusted"
                })
        
        return threats
    
    def get_status(self) -> Dict[str, any]:
        """Get comprehensive DMA protection status"""
        return {
            "iommu": self.check_iommu_support(),
            "thunderbolt": self.check_thunderbolt_security(),
            "pcie_devices": len(self.get_pcie_devices()),
            "usb_devices": len(self.get_usb_devices()),
            "whitelist_size": len(self.load_whitelist()),
            "threats": self.scan_for_threats(),
            "config_dir": str(self.config_dir)
        }


def main():
    """CLI interface for DMA protection"""
    import argparse
    
    parser = argparse.ArgumentParser(description="DMA Attack Prevention Manager")
    parser.add_argument("command", choices=["status", "check", "enable", "scan", "whitelist", "thunderbolt"],
                       help="Command to execute")
    parser.add_argument("--level", help="Thunderbolt security level (user/secure/dponly)")
    parser.add_argument("--device", help="Device ID for whitelist")
    parser.add_argument("--description", help="Device description")
    parser.add_argument("--action", choices=["add", "remove", "list"], help="Whitelist action")
    
    args = parser.parse_args()
    
    dma = DMAProtection()
    
    try:
        if args.command == "status":
            status = dma.get_status()
            print(json.dumps(status, indent=2))
        
        elif args.command == "check":
            print("\n=== IOMMU Status ===")
            iommu = dma.check_iommu_support()
            print(f"Available:           {iommu['iommu_available']}")
            print(f"Type:                {iommu['iommu_type']}")
            print(f"Enabled:             {iommu['iommu_enabled']}")
            print(f"IOMMU Groups:        {iommu['iommu_groups']}")
            print(f"DMA Remapping:       {iommu['dma_remapping']}")
            print(f"Interrupt Remapping: {iommu['interrupt_remapping']}")
            
            print("\n=== Thunderbolt Status ===")
            tb = dma.check_thunderbolt_security()
            print(f"Present:             {tb['thunderbolt_present']}")
            print(f"Security Level:      {tb['security_level']}")
            print(f"Devices:             {len(tb['devices'])}")
        
        elif args.command == "enable":
            result = dma.enable_iommu()
            print(result["instructions"])
        
        elif args.command == "scan":
            threats = dma.scan_for_threats()
            print(f"\n=== DMA Threat Scan ===")
            print(f"Threats found: {len(threats)}\n")
            
            for threat in threats:
                print(f"[{threat['severity']}] {threat['type']}")
                print(f"  {threat['message']}")
                print(f"  → {threat['recommendation']}\n")
        
        elif args.command == "whitelist":
            if args.action == "add":
                if not args.device:
                    print("❌ --device required")
                    sys.exit(1)
                dma.add_device_to_whitelist(args.device, args.description or "")
                print(f"✅ Device added to whitelist: {args.device}")
            
            elif args.action == "remove":
                if not args.device:
                    print("❌ --device required")
                    sys.exit(1)
                dma.remove_device_from_whitelist(args.device)
                print(f"✅ Device removed from whitelist: {args.device}")
            
            elif args.action == "list":
                whitelist = dma.load_whitelist()
                print(f"\n=== Device Whitelist ({len(whitelist)} devices) ===\n")
                for device_id, info in whitelist.items():
                    print(f"{device_id}")
                    print(f"  Description: {info['description']}")
                    print(f"  Added: {info['added_at']}\n")
        
        elif args.command == "thunderbolt":
            if not args.level:
                print("❌ --level required (user/secure/dponly)")
                sys.exit(1)
            
            result = dma.set_thunderbolt_security(args.level)
            print(f"✅ {result['message']}")
    
    except DMAProtectionError as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
