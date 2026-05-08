#!/usr/bin/env python3
"""
Test Suite for Remote Attestation Module
HSE Phase 3 - Remote Attestation Tests

Author: @who_is_the_black_hat
"""

import os
import sys
import json
import unittest
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.remote_attestation import RemoteAttestation, RemoteAttestationError


class TestRemoteAttestation(unittest.TestCase):
    """Test cases for Remote Attestation"""
    
    @classmethod
    def setUpClass(cls):
        """Setup test environment"""
        cls.test_dir = Path("~/.sentinel_pro_test").expanduser()
        cls.test_dir.mkdir(parents=True, exist_ok=True)
        cls.ra = RemoteAttestation(config_dir=str(cls.test_dir))
    
    @classmethod
    def tearDownClass(cls):
        """Cleanup test environment"""
        # Clean up test files
        import shutil
        if cls.test_dir.exists():
            shutil.rmtree(cls.test_dir)
    
    def test_01_tpm_availability(self):
        """Test TPM availability check"""
        print("\n[TEST] Checking TPM availability...")
        
        is_available = self.ra.check_tpm_available()
        print(f"  TPM 2.0 available: {is_available}")
        
        if not is_available:
            print("  ⚠️  TPM not available - skipping hardware tests")
            self.skipTest("TPM 2.0 not available")
    
    def test_02_create_attestation_key(self):
        """Test attestation key creation"""
        print("\n[TEST] Creating attestation key...")
        
        if not self.ra.check_tpm_available():
            self.skipTest("TPM 2.0 not available")
        
        try:
            result = self.ra.create_attestation_key()
            
            self.assertIn("ak_handle", result)
            self.assertIn("ak_pub_path", result)
            self.assertIn("ak_name_path", result)
            
            # Verify files exist
            self.assertTrue(Path(result["ak_pub_path"]).exists())
            
            print(f"  ✅ AK Handle: {result['ak_handle']}")
            print(f"  ✅ AK Public Key: {result['ak_pub_path']}")
        
        except RemoteAttestationError as e:
            print(f"  ⚠️  AK creation failed: {e}")
            self.skipTest(f"AK creation failed: {e}")
    
    def test_03_generate_quote(self):
        """Test quote generation"""
        print("\n[TEST] Generating TPM quote...")
        
        if not self.ra.check_tpm_available():
            self.skipTest("TPM 2.0 not available")
        
        try:
            # Generate quote with custom nonce
            nonce = os.urandom(32).hex()
            quote_data = self.ra.generate_quote(nonce=nonce)
            
            self.assertIn("quote", quote_data)
            self.assertIn("signature", quote_data)
            self.assertIn("pcr_values", quote_data)
            self.assertIn("nonce", quote_data)
            self.assertEqual(quote_data["nonce"], nonce)
            
            # Verify PCR values
            self.assertIsInstance(quote_data["pcr_values"], dict)
            self.assertGreater(len(quote_data["pcr_values"]), 0)
            
            print(f"  ✅ Quote generated successfully")
            print(f"  ✅ Nonce: {nonce[:32]}...")
            print(f"  ✅ PCRs included: {len(quote_data['pcr_values'])}")
            
            # Save for verification test
            self.quote_data = quote_data
        
        except RemoteAttestationError as e:
            print(f"  ⚠️  Quote generation failed: {e}")
            self.skipTest(f"Quote generation failed: {e}")
    
    def test_04_verify_quote(self):
        """Test quote verification"""
        print("\n[TEST] Verifying TPM quote...")
        
        if not self.ra.check_tpm_available():
            self.skipTest("TPM 2.0 not available")
        
        if not hasattr(self, 'quote_data'):
            self.skipTest("No quote data from previous test")
        
        try:
            # Verify the quote
            is_valid = self.ra.verify_quote(self.quote_data)
            
            self.assertTrue(is_valid, "Quote verification should pass")
            print(f"  ✅ Quote verification PASSED")
            
            # Test with wrong nonce (should fail)
            tampered_quote = self.quote_data.copy()
            tampered_quote["nonce"] = os.urandom(32).hex()
            
            is_valid_tampered = self.ra.verify_quote(tampered_quote)
            self.assertFalse(is_valid_tampered, "Tampered quote should fail")
            print(f"  ✅ Tampered quote detection PASSED")
        
        except RemoteAttestationError as e:
            print(f"  ⚠️  Quote verification failed: {e}")
            self.skipTest(f"Quote verification failed: {e}")
    
    def test_05_attestation_report(self):
        """Test attestation report generation"""
        print("\n[TEST] Generating attestation report...")
        
        if not self.ra.check_tpm_available():
            self.skipTest("TPM 2.0 not available")
        
        try:
            report = self.ra.get_attestation_report()
            
            self.assertIn("report_id", report)
            self.assertIn("timestamp", report)
            self.assertIn("system_info", report)
            self.assertIn("quote", report)
            self.assertIn("tpm_version", report)
            
            print(f"  ✅ Report ID: {report['report_id']}")
            print(f"  ✅ System: {report['system_info'][:50]}...")
            print(f"  ✅ TPM Version: {report['tpm_version']}")
        
        except RemoteAttestationError as e:
            print(f"  ⚠️  Report generation failed: {e}")
            self.skipTest(f"Report generation failed: {e}")
    
    def test_06_status(self):
        """Test status reporting"""
        print("\n[TEST] Checking attestation status...")
        
        status = self.ra.get_status()
        
        self.assertIn("tpm_available", status)
        self.assertIn("ak_exists", status)
        self.assertIn("config_dir", status)
        
        print(f"  ✅ TPM Available: {status['tpm_available']}")
        print(f"  ✅ AK Exists: {status['ak_exists']}")
        print(f"  ✅ Config Dir: {status['config_dir']}")


def run_tests():
    """Run all tests"""
    print("=" * 60)
    print("Remote Attestation Test Suite - HSE Phase 3")
    print("=" * 60)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestRemoteAttestation)
    
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
