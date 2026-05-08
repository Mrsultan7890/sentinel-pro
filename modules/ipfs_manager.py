#!/usr/bin/env python3
"""
IPFS Integration Module - DTIE Phase 2
Distributed storage for threat intelligence artifacts

Author: @who_is_the_black_hat
Part of: Sentinel Pro v6.0 - Distributed Threat Intelligence Engine

Use Cases:
- Store large IOC datasets (malware samples, PCAP files)
- Distribute threat reports across nodes
- Immutable artifact storage
- Content-addressed retrieval
"""

import os
import sys
import json
import hashlib
import subprocess
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path

class IPFSError(Exception):
    """Custom exception for IPFS errors"""
    pass

class IPFSManager:
    """
    IPFS Manager for Distributed Threat Intelligence
    
    Capabilities:
    - Add files to IPFS
    - Retrieve files by CID (Content Identifier)
    - Pin important artifacts
    - Publish to IPNS (mutable pointers)
    - Peer discovery and connection
    - Gateway access
    """
    
    def __init__(self, config_dir: str = "~/.sentinel_pro"):
        self.config_dir = Path(config_dir).expanduser()
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.ipfs_dir = self.config_dir / "ipfs_cache"
        self.ipfs_dir.mkdir(parents=True, exist_ok=True)
        
        self.metadata_file = self.config_dir / "ipfs_metadata.json"
        self.pins_file = self.config_dir / "ipfs_pins.json"
    
    def _run_command(self, cmd: List[str]) -> Tuple[int, str, str]:
        """Execute shell command and return (returncode, stdout, stderr)"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            raise IPFSError(f"Command timeout: {' '.join(cmd)}")
        except Exception as e:
            raise IPFSError(f"Command failed: {e}")
    
    def check_ipfs_installed(self) -> bool:
        """Check if IPFS is installed"""
        returncode, stdout, _ = self._run_command(["which", "ipfs"])
        return returncode == 0 and stdout.strip() != ""
    
    def check_ipfs_daemon(self) -> bool:
        """Check if IPFS daemon is running"""
        returncode, stdout, _ = self._run_command(["ipfs", "id"])
        return returncode == 0
    
    def init_ipfs(self) -> Dict[str, str]:
        """
        Initialize IPFS repository
        
        Returns:
            Dict with peer_id and status
        """
        if not self.check_ipfs_installed():
            raise IPFSError("IPFS not installed. Install: https://docs.ipfs.tech/install/")
        
        # Check if already initialized
        returncode, stdout, stderr = self._run_command(["ipfs", "id"])
        if returncode == 0:
            # Already initialized
            peer_id = json.loads(stdout)["ID"]
            return {
                "status": "already_initialized",
                "peer_id": peer_id
            }
        
        # Initialize
        returncode, stdout, stderr = self._run_command(["ipfs", "init"])
        if returncode != 0:
            raise IPFSError(f"Failed to initialize IPFS: {stderr}")
        
        # Get peer ID
        returncode, stdout, _ = self._run_command(["ipfs", "id"])
        peer_id = json.loads(stdout)["ID"]
        
        return {
            "status": "initialized",
            "peer_id": peer_id
        }
    
    def start_daemon(self) -> Dict[str, str]:
        """
        Start IPFS daemon (non-blocking)
        
        Returns:
            Dict with status and instructions
        """
        if self.check_ipfs_daemon():
            return {
                "status": "already_running",
                "message": "IPFS daemon is already running"
            }
        
        # Start daemon in background
        instructions = """
To start IPFS daemon, run in a separate terminal:

    ipfs daemon

Or run in background:

    nohup ipfs daemon > /tmp/ipfs.log 2>&1 &

Then retry this command.
"""
        
        return {
            "status": "not_running",
            "message": "IPFS daemon not running",
            "instructions": instructions
        }
    
    def add_file(self, file_path: str, description: str = "") -> Dict[str, str]:
        """
        Add file to IPFS
        
        Args:
            file_path: Path to file
            description: Human-readable description
        
        Returns:
            Dict with CID, size, and metadata
        """
        if not self.check_ipfs_daemon():
            raise IPFSError("IPFS daemon not running. Run: ipfs daemon")
        
        file_path = Path(file_path)
        if not file_path.exists():
            raise IPFSError(f"File not found: {file_path}")
        
        # Add to IPFS
        returncode, stdout, stderr = self._run_command([
            "ipfs", "add", "-Q", str(file_path)
        ])
        
        if returncode != 0:
            raise IPFSError(f"Failed to add file: {stderr}")
        
        cid = stdout.strip()
        
        # Get file info
        file_size = file_path.stat().st_size
        file_hash = self._hash_file(file_path)
        
        # Save metadata
        metadata = {
            "cid": cid,
            "filename": file_path.name,
            "size": file_size,
            "sha256": file_hash,
            "description": description,
            "added_at": datetime.now().isoformat()
        }
        
        self._save_metadata(cid, metadata)
        
        return metadata
    
    def add_directory(self, dir_path: str, description: str = "") -> Dict[str, any]:
        """
        Add directory to IPFS (recursive)
        
        Args:
            dir_path: Path to directory
            description: Human-readable description
        
        Returns:
            Dict with root CID and file list
        """
        if not self.check_ipfs_daemon():
            raise IPFSError("IPFS daemon not running. Run: ipfs daemon")
        
        dir_path = Path(dir_path)
        if not dir_path.is_dir():
            raise IPFSError(f"Directory not found: {dir_path}")
        
        # Add directory recursively
        returncode, stdout, stderr = self._run_command([
            "ipfs", "add", "-r", "-Q", str(dir_path)
        ])
        
        if returncode != 0:
            raise IPFSError(f"Failed to add directory: {stderr}")
        
        # Last line is root CID
        lines = stdout.strip().split('\n')
        root_cid = lines[-1]
        
        metadata = {
            "cid": root_cid,
            "dirname": dir_path.name,
            "file_count": len(lines),
            "description": description,
            "added_at": datetime.now().isoformat()
        }
        
        self._save_metadata(root_cid, metadata)
        
        return metadata
    
    def get_file(self, cid: str, output_path: Optional[str] = None) -> str:
        """
        Retrieve file from IPFS
        
        Args:
            cid: Content Identifier
            output_path: Where to save (default: ipfs_cache/)
        
        Returns:
            Path to downloaded file
        """
        if not self.check_ipfs_daemon():
            raise IPFSError("IPFS daemon not running. Run: ipfs daemon")
        
        if output_path is None:
            output_path = self.ipfs_dir / cid
        else:
            output_path = Path(output_path)
        
        # Get from IPFS
        returncode, stdout, stderr = self._run_command([
            "ipfs", "get", cid, "-o", str(output_path)
        ])
        
        if returncode != 0:
            raise IPFSError(f"Failed to get file: {stderr}")
        
        return str(output_path)
    
    def cat_file(self, cid: str) -> bytes:
        """
        Read file content from IPFS (without saving)
        
        Args:
            cid: Content Identifier
        
        Returns:
            File content as bytes
        """
        if not self.check_ipfs_daemon():
            raise IPFSError("IPFS daemon not running. Run: ipfs daemon")
        
        returncode, stdout, stderr = self._run_command([
            "ipfs", "cat", cid
        ])
        
        if returncode != 0:
            raise IPFSError(f"Failed to cat file: {stderr}")
        
        return stdout.encode() if isinstance(stdout, str) else stdout
    
    def pin_add(self, cid: str, description: str = "") -> Dict[str, str]:
        """
        Pin CID (prevent garbage collection)
        
        Args:
            cid: Content Identifier
            description: Why this is pinned
        
        Returns:
            Dict with pin status
        """
        if not self.check_ipfs_daemon():
            raise IPFSError("IPFS daemon not running. Run: ipfs daemon")
        
        returncode, stdout, stderr = self._run_command([
            "ipfs", "pin", "add", cid
        ])
        
        if returncode != 0:
            raise IPFSError(f"Failed to pin: {stderr}")
        
        # Save pin metadata
        pins = self._load_pins()
        pins[cid] = {
            "description": description,
            "pinned_at": datetime.now().isoformat()
        }
        self._save_pins(pins)
        
        return {
            "cid": cid,
            "status": "pinned",
            "description": description
        }
    
    def pin_rm(self, cid: str) -> Dict[str, str]:
        """
        Unpin CID (allow garbage collection)
        
        Args:
            cid: Content Identifier
        
        Returns:
            Dict with unpin status
        """
        if not self.check_ipfs_daemon():
            raise IPFSError("IPFS daemon not running. Run: ipfs daemon")
        
        returncode, stdout, stderr = self._run_command([
            "ipfs", "pin", "rm", cid
        ])
        
        if returncode != 0:
            raise IPFSError(f"Failed to unpin: {stderr}")
        
        # Remove from pins
        pins = self._load_pins()
        if cid in pins:
            del pins[cid]
            self._save_pins(pins)
        
        return {
            "cid": cid,
            "status": "unpinned"
        }
    
    def list_pins(self) -> List[Dict[str, str]]:
        """List all pinned CIDs"""
        pins = self._load_pins()
        
        result = []
        for cid, info in pins.items():
            result.append({
                "cid": cid,
                "description": info.get("description", ""),
                "pinned_at": info.get("pinned_at", "")
            })
        
        return result
    
    def get_gateway_url(self, cid: str, gateway: str = "https://ipfs.io") -> str:
        """
        Get public gateway URL for CID
        
        Args:
            cid: Content Identifier
            gateway: IPFS gateway (default: ipfs.io)
        
        Returns:
            Public URL
        """
        return f"{gateway}/ipfs/{cid}"
    
    def connect_peer(self, peer_addr: str) -> Dict[str, str]:
        """
        Connect to IPFS peer
        
        Args:
            peer_addr: Multiaddr (e.g., /ip4/1.2.3.4/tcp/4001/p2p/QmPeerID)
        
        Returns:
            Dict with connection status
        """
        if not self.check_ipfs_daemon():
            raise IPFSError("IPFS daemon not running. Run: ipfs daemon")
        
        returncode, stdout, stderr = self._run_command([
            "ipfs", "swarm", "connect", peer_addr
        ])
        
        if returncode != 0:
            raise IPFSError(f"Failed to connect: {stderr}")
        
        return {
            "peer": peer_addr,
            "status": "connected"
        }
    
    def list_peers(self) -> List[str]:
        """List connected peers"""
        if not self.check_ipfs_daemon():
            return []
        
        returncode, stdout, _ = self._run_command(["ipfs", "swarm", "peers"])
        
        if returncode != 0:
            return []
        
        return [line.strip() for line in stdout.split('\n') if line.strip()]
    
    def _hash_file(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file"""
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def _save_metadata(self, cid: str, metadata: Dict):
        """Save CID metadata"""
        all_metadata = {}
        if self.metadata_file.exists():
            all_metadata = json.loads(self.metadata_file.read_text())
        
        all_metadata[cid] = metadata
        self.metadata_file.write_text(json.dumps(all_metadata, indent=2))
    
    def _load_pins(self) -> Dict:
        """Load pins from file"""
        if self.pins_file.exists():
            return json.loads(self.pins_file.read_text())
        return {}
    
    def _save_pins(self, pins: Dict):
        """Save pins to file"""
        self.pins_file.write_text(json.dumps(pins, indent=2))
    
    def get_status(self) -> Dict[str, any]:
        """Get IPFS status"""
        status = {
            "ipfs_installed": self.check_ipfs_installed(),
            "daemon_running": self.check_ipfs_daemon(),
            "peer_id": None,
            "peers_connected": 0,
            "pins_count": len(self._load_pins()),
            "cache_dir": str(self.ipfs_dir)
        }
        
        if status["daemon_running"]:
            try:
                returncode, stdout, _ = self._run_command(["ipfs", "id"])
                if returncode == 0:
                    status["peer_id"] = json.loads(stdout)["ID"]
                
                status["peers_connected"] = len(self.list_peers())
            except:
                pass
        
        return status


def main():
    """CLI interface for IPFS manager"""
    import argparse
    
    parser = argparse.ArgumentParser(description="IPFS Manager for Threat Intelligence")
    parser.add_argument("command", choices=["status", "init", "daemon", "add", "get", "cat", 
                                           "pin", "unpin", "pins", "peers", "gateway"],
                       help="Command to execute")
    parser.add_argument("--file", help="File path for add/get")
    parser.add_argument("--dir", help="Directory path for add")
    parser.add_argument("--cid", help="Content Identifier")
    parser.add_argument("--output", help="Output path for get")
    parser.add_argument("--description", help="Description for add/pin")
    parser.add_argument("--peer", help="Peer address for connect")
    
    args = parser.parse_args()
    
    ipfs = IPFSManager()
    
    try:
        if args.command == "status":
            status = ipfs.get_status()
            print(json.dumps(status, indent=2))
        
        elif args.command == "init":
            result = ipfs.init_ipfs()
            print(f"✅ {result['status']}")
            print(f"Peer ID: {result['peer_id']}")
        
        elif args.command == "daemon":
            result = ipfs.start_daemon()
            print(result["message"])
            if "instructions" in result:
                print(result["instructions"])
        
        elif args.command == "add":
            if args.file:
                result = ipfs.add_file(args.file, args.description or "")
                print(f"✅ File added to IPFS")
                print(f"CID: {result['cid']}")
                print(f"Size: {result['size']} bytes")
                print(f"Gateway: {ipfs.get_gateway_url(result['cid'])}")
            elif args.dir:
                result = ipfs.add_directory(args.dir, args.description or "")
                print(f"✅ Directory added to IPFS")
                print(f"Root CID: {result['cid']}")
                print(f"Files: {result['file_count']}")
                print(f"Gateway: {ipfs.get_gateway_url(result['cid'])}")
            else:
                print("❌ --file or --dir required")
                sys.exit(1)
        
        elif args.command == "get":
            if not args.cid:
                print("❌ --cid required")
                sys.exit(1)
            
            output = ipfs.get_file(args.cid, args.output)
            print(f"✅ File retrieved: {output}")
        
        elif args.command == "cat":
            if not args.cid:
                print("❌ --cid required")
                sys.exit(1)
            
            content = ipfs.cat_file(args.cid)
            print(content.decode('utf-8', errors='ignore'))
        
        elif args.command == "pin":
            if not args.cid:
                print("❌ --cid required")
                sys.exit(1)
            
            result = ipfs.pin_add(args.cid, args.description or "")
            print(f"✅ Pinned: {result['cid']}")
        
        elif args.command == "unpin":
            if not args.cid:
                print("❌ --cid required")
                sys.exit(1)
            
            result = ipfs.pin_rm(args.cid)
            print(f"✅ Unpinned: {result['cid']}")
        
        elif args.command == "pins":
            pins = ipfs.list_pins()
            print(f"\n=== Pinned CIDs ({len(pins)}) ===\n")
            for pin in pins:
                print(f"CID: {pin['cid']}")
                print(f"  Description: {pin['description']}")
                print(f"  Pinned: {pin['pinned_at']}\n")
        
        elif args.command == "peers":
            peers = ipfs.list_peers()
            print(f"\n=== Connected Peers ({len(peers)}) ===\n")
            for peer in peers:
                print(peer)
        
        elif args.command == "gateway":
            if not args.cid:
                print("❌ --cid required")
                sys.exit(1)
            
            url = ipfs.get_gateway_url(args.cid)
            print(f"Gateway URL: {url}")
    
    except IPFSError as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
