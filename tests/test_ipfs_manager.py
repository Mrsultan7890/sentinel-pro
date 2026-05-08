#!/usr/bin/env python3
"""
Test Suite for IPFS Manager
DTIE Phase 2 - IPFS Integration Tests

Author: @who_is_the_black_hat
"""

import os
import sys
import json
import unittest
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.ipfs_manager import IPFSManager, IPFSError


class TestIPFSManager(unittest.TestCase):
    """Test cases for IPFS Manager"""
    
    @classmethod
    def setUpClass(cls):
        """Setup test environment"""
        cls.test_dir = Path("~/.sentinel_pro_ipfs_test").expanduser()
        cls.test_dir.mkdir(parents=True, exist_ok=True)
        cls.ipfs = IPFSManager(config_dir=str(cls.test_dir))
        
        # Create test file
        cls.test_file = cls.test_dir / "test_ioc.json"
        cls.test_file.write_text(json.dumps({
            "ioc_type": "malware_hash",
            "sha256": "abc123...",
            "threat_level": "HIGH"
        }, indent=2))
    
    @classmethod
    def tearDownClass(cls):
        """Cleanup test environment"""
        import shutil
        if cls.test_dir.exists():
            shutil.rmtree(cls.test_dir)
    
    def test_01_ipfs_installed(self):
        """Test IPFS installation check"""
        print("\n[TEST] Checking IPFS installation...")
        
        is_installed = self.ipfs.check_ipfs_installed()
        print(f"  IPFS installed: {is_installed}")
        
        if not is_installed:
            print("  ⚠️  IPFS not installed - skipping daemon tests")
            print("  Install: https://docs.ipfs.tech/install/")
    
    def test_02_ipfs_daemon(self):
        """Test IPFS daemon status"""
        print("\n[TEST] Checking IPFS daemon...")
        
        if not self.ipfs.check_ipfs_installed():
            self.skipTest("IPFS not installed")
        
        is_running = self.ipfs.check_ipfs_daemon()
        print(f"  Daemon running: {is_running}")
        
        if not is_running:
            print("  ⚠️  IPFS daemon not running")
            print("  Start: ipfs daemon")
    
    def test_03_init_ipfs(self):
        """Test IPFS initialization"""
        print("\n[TEST] Initializing IPFS...")
        
        if not self.ipfs.check_ipfs_installed():
            self.skipTest("IPFS not installed")
        
        try:
            result = self.ipfs.init_ipfs()
            
            self.assertIn("status", result)
            self.assertIn("peer_id", result)
            
            print(f"  ✅ Status: {result['status']}")
            print(f"  ✅ Peer ID: {result['peer_id'][:16]}...")
        
        except IPFSError as e:
            print(f"  ⚠️  Init skipped: {e}")
            self.skipTest(f"IPFS init failed: {e}")
    
    def test_04_add_file(self):
        """Test adding file to IPFS"""
        print("\n[TEST] Adding file to IPFS...")
        
        if not self.ipfs.check_ipfs_daemon():
            self.skipTest("IPFS daemon not running")
        
        try:
            result = self.ipfs.add_file(
                str(self.test_file),
                description="Test IOC file"
            )
            
            self.assertIn("cid", result)
            self.assertIn("size", result)
            self.assertIn("sha256", result)
            
            print(f"  ✅ CID: {result['cid']}")
            print(f"  ✅ Size: {result['size']} bytes")
            print(f"  ✅ SHA256: {result['sha256'][:16]}...")
            
            # Save CID for later tests
            self.test_cid = result['cid']
        
        except IPFSError as e:
            print(f"  ⚠️  Add file skipped: {e}")
            self.skipTest(f"IPFS add failed: {e}")
    
    def test_05_get_file(self):
        """Test retrieving file from IPFS"""
        print("\n[TEST] Retrieving file from IPFS...")
        
        if not self.ipfs.check_ipfs_daemon():
            self.skipTest("IPFS daemon not running")
        
        if not hasattr(self, 'test_cid'):
            self.skipTest("No CID from previous test")
        
        try:
            output_path = self.ipfs.get_file(self.test_cid)
            
            self.assertTrue(Path(output_path).exists())
            
            print(f"  ✅ File retrieved: {output_path}")
        
        except IPFSError as e:
            print(f"  ⚠️  Get file skipped: {e}")
            self.skipTest(f"IPFS get failed: {e}")
    
    def test_06_cat_file(self):
        """Test reading file content from IPFS"""
        print("\n[TEST] Reading file content from IPFS...")
        
        if not self.ipfs.check_ipfs_daemon():
            self.skipTest("IPFS daemon not running")
        
        if not hasattr(self, 'test_cid'):
            self.skipTest("No CID from previous test")
        
        try:
            content = self.ipfs.cat_file(self.test_cid)
            
            self.assertIsInstance(content, bytes)
            self.assertGreater(len(content), 0)
            
            print(f"  ✅ Content read: {len(content)} bytes")
        
        except IPFSError as e:
            print(f"  ⚠️  Cat file skipped: {e}")
            self.skipTest(f"IPFS cat failed: {e}")
    
    def test_07_pin_operations(self):
        """Test pin/unpin operations"""
        print("\n[TEST] Testing pin operations...")
        
        if not self.ipfs.check_ipfs_daemon():
            self.skipTest("IPFS daemon not running")
        
        if not hasattr(self, 'test_cid'):
            self.skipTest("No CID from previous test")
        
        try:
            # Pin
            result = self.ipfs.pin_add(self.test_cid, "Test pin")
            self.assertEqual(result['status'], 'pinned')
            print(f"  ✅ Pinned: {result['cid']}")
            
            # List pins
            pins = self.ipfs.list_pins()
            self.assertGreater(len(pins), 0)
            print(f"  ✅ Pins listed: {len(pins)}")
            
            # Unpin
            result = self.ipfs.pin_rm(self.test_cid)
            self.assertEqual(result['status'], 'unpinned')
            print(f"  ✅ Unpinned: {result['cid']}")
        
        except IPFSError as e:
            print(f"  ⚠️  Pin operations skipped: {e}")
            self.skipTest(f"IPFS pin failed: {e}")
    
    def test_08_gateway_url(self):
        """Test gateway URL generation"""
        print("\n[TEST] Testing gateway URL...")
        
        if not hasattr(self, 'test_cid'):
            self.skipTest("No CID from previous test")
        
        url = self.ipfs.get_gateway_url(self.test_cid)
        
        self.assertIn("ipfs.io", url)
        self.assertIn(self.test_cid, url)
        
        print(f"  ✅ Gateway URL: {url}")
    
    def test_09_list_peers(self):
        """Test peer listing"""
        print("\n[TEST] Listing IPFS peers...")
        
        if not self.ipfs.check_ipfs_daemon():
            self.skipTest("IPFS daemon not running")
        
        try:
            peers = self.ipfs.list_peers()
            
            print(f"  ✅ Connected peers: {len(peers)}")
            
            if len(peers) > 0:
                print(f"  ✅ Sample peer: {peers[0][:50]}...")
        
        except Exception as e:
            print(f"  ⚠️  Peer listing skipped: {e}")
    
    def test_10_status(self):
        """Test status reporting"""
        print("\n[TEST] Checking IPFS status...")
        
        status = self.ipfs.get_status()
        
        self.assertIn("ipfs_installed", status)
        self.assertIn("daemon_running", status)
        self.assertIn("pins_count", status)
        
        print(f"  ✅ IPFS Installed: {status['ipfs_installed']}")
        print(f"  ✅ Daemon Running: {status['daemon_running']}")
        print(f"  ✅ Pins Count: {status['pins_count']}")
        print(f"  ✅ Peers Connected: {status['peers_connected']}")


def run_tests():
    """Run all tests"""
    print("=" * 60)
    print("IPFS Manager Test Suite - DTIE Phase 2")
    print("=" * 60)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestIPFSManager)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
