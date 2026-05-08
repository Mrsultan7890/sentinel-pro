#!/usr/bin/env python3
"""
Test Suite for Intel SGX Enclave Manager
HSE Phase 4 - SGX Enclave Tests

Author: @who_is_the_black_hat
"""

import os
import sys
import json
import unittest
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.sgx_enclave_manager import SGXEnclaveManager, SGXError


class TestSGXEnclaveManager(unittest.TestCase):
    """Test cases for SGX Enclave Manager"""
    
    @classmethod
    def setUpClass(cls):
        """Setup test environment"""
        cls.test_dir = Path("~/.sentinel_pro_sgx_test").expanduser()
        cls.test_dir.mkdir(parents=True, exist_ok=True)
        cls.sgx = SGXEnclaveManager(config_dir=str(cls.test_dir))
    
    @classmethod
    def tearDownClass(cls):
        """Cleanup test environment"""
        import shutil
        if cls.test_dir.exists():
            shutil.rmtree(cls.test_dir)
    
    def test_01_sgx_support_check(self):
        """Test SGX support detection"""
        print("\n[TEST] Checking SGX support...")
        
        support = self.sgx.check_sgx_support()
        
        self.assertIn("sgx_available", support)
        self.assertIn("cpu_support", support)
        self.assertIn("sgx_driver", support)
        self.assertIn("sgx_enabled", support)
        
        print(f"  CPU Support:     {support['cpu_support']}")
        print(f"  SGX Driver:      {support['sgx_driver']}")
        print(f"  SGX Enabled:     {support['sgx_enabled']}")
        print(f"  SGX Available:   {support['sgx_available']}")
        
        if not support['sgx_available']:
            print("  ⚠️  SGX not available - using software fallback")
    
    def test_02_create_enclave_config(self):
        """Test enclave configuration creation"""
        print("\n[TEST] Creating enclave configuration...")
        
        config_file = self.sgx.create_enclave_config("test_enclave")
        
        self.assertTrue(Path(config_file).exists())
        
        # Verify config content
        config_content = Path(config_file).read_text()
        self.assertIn("<EnclaveConfiguration>", config_content)
        self.assertIn("<StackMaxSize>", config_content)
        self.assertIn("<HeapMaxSize>", config_content)
        
        print(f"  ✅ Config created: {config_file}")
    
    def test_03_create_simple_enclave(self):
        """Test simple enclave creation"""
        print("\n[TEST] Creating simple enclave...")
        
        try:
            result = self.sgx.create_simple_enclave("test_crypto")
            
            self.assertIn("enclave_c", result)
            self.assertIn("enclave_edl", result)
            self.assertIn("enclave_config", result)
            
            # Verify files exist
            self.assertTrue(Path(result["enclave_c"]).exists())
            self.assertTrue(Path(result["enclave_edl"]).exists())
            self.assertTrue(Path(result["enclave_config"]).exists())
            
            print(f"  ✅ Enclave created: {result['enclave_name']}")
            print(f"  ✅ Source: {result['enclave_c']}")
            print(f"  ✅ EDL: {result['enclave_edl']}")
        
        except SGXError as e:
            print(f"  ⚠️  Enclave creation skipped: {e}")
            self.skipTest(f"SGX not available: {e}")
    
    def test_04_seal_unseal_data(self):
        """Test data sealing and unsealing"""
        print("\n[TEST] Testing data sealing/unsealing...")
        
        # Test data
        test_data = b"This is sensitive data that should be sealed"
        
        # Seal data
        sealed_file = self.sgx.seal_data(test_data, "test_seal")
        self.assertTrue(Path(sealed_file).exists())
        print(f"  ✅ Data sealed: {sealed_file}")
        
        # Verify sealed data is different from original
        sealed_content = Path(sealed_file).read_bytes()
        self.assertNotEqual(sealed_content, test_data)
        print(f"  ✅ Sealed data is encrypted")
        
        # Unseal data
        unsealed_data = self.sgx.unseal_data(sealed_file)
        self.assertEqual(unsealed_data, test_data)
        print(f"  ✅ Data unsealed successfully")
    
    def test_05_seal_large_data(self):
        """Test sealing large data"""
        print("\n[TEST] Testing large data sealing...")
        
        # Generate 1MB of random data
        large_data = os.urandom(1024 * 1024)
        
        sealed_file = self.sgx.seal_data(large_data, "test_large")
        self.assertTrue(Path(sealed_file).exists())
        print(f"  ✅ Large data sealed (1MB)")
        
        unsealed_data = self.sgx.unseal_data(sealed_file)
        self.assertEqual(unsealed_data, large_data)
        print(f"  ✅ Large data unsealed successfully")
    
    def test_06_machine_binding(self):
        """Test machine-specific sealing"""
        print("\n[TEST] Testing machine binding...")
        
        test_data = b"Machine-bound secret"
        
        # Seal on this machine
        sealed_file = self.sgx.seal_data(test_data, "test_machine")
        
        # Verify machine ID is used
        machine_id = self.sgx._get_machine_id()
        self.assertIsNotNone(machine_id)
        self.assertGreater(len(machine_id), 0)
        
        print(f"  ✅ Machine ID: {machine_id[:16]}...")
        print(f"  ✅ Data sealed with machine binding")
        
        # Unseal should work on same machine
        unsealed_data = self.sgx.unseal_data(sealed_file)
        self.assertEqual(unsealed_data, test_data)
        print(f"  ✅ Unsealing works on same machine")
    
    def test_07_enclave_measurement(self):
        """Test enclave measurement"""
        print("\n[TEST] Testing enclave measurement...")
        
        # Create enclave first
        try:
            self.sgx.create_simple_enclave("test_measure")
        except SGXError:
            self.skipTest("SGX not available")
        
        # Get measurement (will be None if not signed)
        measurement = self.sgx.get_enclave_measurement("test_measure")
        
        # Measurement might be None if enclave not signed yet
        if measurement:
            self.assertEqual(len(measurement), 64)  # SHA256 hex
            print(f"  ✅ MRENCLAVE: {measurement[:32]}...")
        else:
            print(f"  ⚠️  Enclave not signed yet (expected)")
    
    def test_08_status(self):
        """Test status reporting"""
        print("\n[TEST] Checking SGX status...")
        
        status = self.sgx.get_status()
        
        self.assertIn("sgx_available", status)
        self.assertIn("config_dir", status)
        self.assertIn("enclave_dir", status)
        self.assertIn("enclaves", status)
        
        print(f"  ✅ SGX Available: {status['sgx_available']}")
        print(f"  ✅ Config Dir: {status['config_dir']}")
        print(f"  ✅ Enclaves: {len(status['enclaves'])}")


def run_tests():
    """Run all tests"""
    print("=" * 60)
    print("Intel SGX Enclave Manager Test Suite - HSE Phase 4")
    print("=" * 60)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestSGXEnclaveManager)
    
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
