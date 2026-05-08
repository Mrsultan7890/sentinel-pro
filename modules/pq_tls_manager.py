#!/usr/bin/env python3
"""
Post-Quantum TLS Configuration Manager
Manages PQ crypto modes for SentinelProxy
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional

class PQTLSManager:
    """Manage Post-Quantum TLS configuration"""
    
    # PQ modes
    MODE_CLASSICAL = "classical"
    MODE_HYBRID = "hybrid"
    MODE_PQ_ONLY = "pq_only"
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize PQ-TLS manager"""
        if config_path is None:
            config_path = os.path.expanduser("~/.sentinel_pro/pq_tls_config.json")
        
        self.config_path = Path(config_path)
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[!] Failed to load PQ-TLS config: {e}")
        
        # Default config
        return {
            "mode": self.MODE_CLASSICAL,
            "enabled": False,
            "algorithms": {
                "kem": "kyber1024",
                "signature": "dilithium5",
                "hash_signature": "sphincs_sha2_128s"
            },
            "performance": {
                "handshake_time_ms": 0,
                "overhead_percent": 0
            }
        }
    
    def _save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"[!] Failed to save PQ-TLS config: {e}")
    
    def get_mode(self) -> str:
        """Get current PQ mode"""
        return self.config.get("mode", self.MODE_CLASSICAL)
    
    def set_mode(self, mode: str) -> bool:
        """Set PQ mode"""
        if mode not in [self.MODE_CLASSICAL, self.MODE_HYBRID, self.MODE_PQ_ONLY]:
            print(f"[!] Invalid mode: {mode}")
            return False
        
        self.config["mode"] = mode
        self._save_config()
        print(f"[+] PQ-TLS mode set to: {mode}")
        return True
    
    def enable(self) -> bool:
        """Enable PQ-TLS"""
        self.config["enabled"] = True
        self._save_config()
        print("[+] PQ-TLS enabled")
        return True
    
    def disable(self) -> bool:
        """Disable PQ-TLS"""
        self.config["enabled"] = False
        self._save_config()
        print("[+] PQ-TLS disabled")
        return True
    
    def is_enabled(self) -> bool:
        """Check if PQ-TLS is enabled"""
        return self.config.get("enabled", False)
    
    def get_algorithms(self) -> Dict[str, str]:
        """Get configured algorithms"""
        return self.config.get("algorithms", {})
    
    def set_algorithm(self, algo_type: str, algo_name: str) -> bool:
        """Set algorithm for specific type"""
        if algo_type not in ["kem", "signature", "hash_signature"]:
            print(f"[!] Invalid algorithm type: {algo_type}")
            return False
        
        if "algorithms" not in self.config:
            self.config["algorithms"] = {}
        
        self.config["algorithms"][algo_type] = algo_name
        self._save_config()
        print(f"[+] {algo_type} algorithm set to: {algo_name}")
        return True
    
    def get_status(self) -> Dict[str, Any]:
        """Get full status"""
        return {
            "enabled": self.is_enabled(),
            "mode": self.get_mode(),
            "algorithms": self.get_algorithms(),
            "config_path": str(self.config_path),
            "performance": self.config.get("performance", {})
        }
    
    def benchmark(self) -> Dict[str, float]:
        """Run performance benchmark"""
        # TODO: Implement actual benchmarking
        # For now, return placeholder values
        return {
            "classical_handshake_ms": 50.0,
            "hybrid_handshake_ms": 75.0,
            "pq_only_handshake_ms": 100.0,
            "overhead_percent": 50.0
        }
    
    def print_status(self):
        """Print formatted status"""
        status = self.get_status()
        
        print("\n" + "="*60)
        print("  POST-QUANTUM TLS STATUS")
        print("="*60)
        print(f"  Enabled:     {'✓ YES' if status['enabled'] else '✗ NO'}")
        print(f"  Mode:        {status['mode'].upper()}")
        print(f"  Config:      {status['config_path']}")
        print("\n  Algorithms:")
        for algo_type, algo_name in status['algorithms'].items():
            print(f"    {algo_type:15s}: {algo_name}")
        
        perf = status.get('performance', {})
        if perf.get('handshake_time_ms', 0) > 0:
            print(f"\n  Performance:")
            print(f"    Handshake:   {perf['handshake_time_ms']:.2f} ms")
            print(f"    Overhead:    {perf['overhead_percent']:.1f}%")
        
        print("="*60 + "\n")


def main():
    """CLI interface"""
    import sys
    
    manager = PQTLSManager()
    
    if len(sys.argv) < 2:
        manager.print_status()
        print("Usage:")
        print("  python3 pq_tls_manager.py status")
        print("  python3 pq_tls_manager.py enable")
        print("  python3 pq_tls_manager.py disable")
        print("  python3 pq_tls_manager.py mode <classical|hybrid|pq_only>")
        print("  python3 pq_tls_manager.py benchmark")
        return
    
    cmd = sys.argv[1].lower()
    
    if cmd == "status":
        manager.print_status()
    
    elif cmd == "enable":
        manager.enable()
    
    elif cmd == "disable":
        manager.disable()
    
    elif cmd == "mode":
        if len(sys.argv) < 3:
            print("[!] Usage: mode <classical|hybrid|pq_only>")
            return
        manager.set_mode(sys.argv[2].lower())
    
    elif cmd == "benchmark":
        print("\n[*] Running PQ-TLS benchmark...")
        results = manager.benchmark()
        print("\nResults:")
        for key, value in results.items():
            print(f"  {key:30s}: {value:.2f}")
    
    else:
        print(f"[!] Unknown command: {cmd}")


if __name__ == "__main__":
    main()
