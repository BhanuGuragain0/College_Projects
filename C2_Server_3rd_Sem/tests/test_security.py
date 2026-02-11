"""
Security Tests for SecureComm
Tests MITM prevention, replay protection, rate limiting, and input validation

Author: Shadow Junior
"""

import os
import sys
import unittest
import time
import secrets
import threading

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.securecomm.security import SecurityModule, SecurityError
from src.securecomm.crypto_engine import CryptoEngine
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


class MockCertificate:
    """Mock certificate for testing"""
    def __init__(self, data):
        self._data = data
    
    def public_bytes(self, encoding):
        return self._data


class TestCertificatePinning(unittest.TestCase):
    """Test certificate pinning (MITM prevention)"""
    
    def setUp(self):
        self.security = SecurityModule()
        self.cert1 = MockCertificate(b"certificate_data_1")
        self.cert2 = MockCertificate(b"certificate_data_2")
    
    def test_01_pin_certificate(self):
        """Test certificate pinning"""
        agent_id = "agent001"
        
        # Pin certificate
        self.security.pin_certificate(agent_id, self.cert1)
        
        # Verify pinned
        self.assertIn(agent_id, self.security.pinned_certs)
    
    def test_02_validate_pinned_certificate(self):
        """Test validation of pinned certificate"""
        agent_id = "agent001"
        
        # Pin certificate
        self.security.pin_certificate(agent_id, self.cert1)
        
        # Validate same certificate
        valid = self.security.validate_pinned_certificate(agent_id, self.cert1)
        self.assertTrue(valid)
    
    def test_03_detect_mitm(self):
        """Test MITM detection with different certificate"""
        agent_id = "agent001"
        
        # Pin certificate
        self.security.pin_certificate(agent_id, self.cert1)
        
        # Try different certificate (MITM)
        with self.assertRaises(SecurityError) as context:
            self.security.validate_pinned_certificate(agent_id, self.cert2)
        
        self.assertIn("MITM", str(context.exception))
    
    def test_04_tofu_model(self):
        """Test Trust On First Use (TOFU) model"""
        agent_id = "agent002"
        
        # First connection pins certificate
        valid = self.security.validate_pinned_certificate(agent_id, self.cert1)
        self.assertTrue(valid)
        
        # Verify pinned
        self.assertIn(agent_id, self.security.pinned_certs)
    
    def test_05_unpin_certificate(self):
        """Test certificate unpinning"""
        agent_id = "agent001"
        
        # Pin and unpin
        self.security.pin_certificate(agent_id, self.cert1)
        self.security.unpin_certificate(agent_id)
        
        # Verify unpinned
        self.assertNotIn(agent_id, self.security.pinned_certs)


class TestReplayProtection(unittest.TestCase):
    """Test replay attack prevention"""
    
    def setUp(self):
        self.security = SecurityModule(replay_window=300)
    
    def test_01_valid_nonce(self):
        """Test valid nonce acceptance"""
        nonce = secrets.token_hex(32)
        timestamp = int(time.time())
        
        valid = self.security.validate_nonce(nonce, timestamp)
        self.assertTrue(valid)
    
    def test_02_replay_attack(self):
        """Test replay attack detection"""
        nonce = secrets.token_hex(32)
        timestamp = int(time.time())
        
        # First use
        self.security.validate_nonce(nonce, timestamp)
        
        # Replay attempt
        with self.assertRaises(SecurityError) as context:
            self.security.validate_nonce(nonce, timestamp)
        
        self.assertIn("Replay", str(context.exception))
    
    def test_03_old_timestamp(self):
        """Test old timestamp rejection"""
        nonce = secrets.token_hex(32)
        old_timestamp = int(time.time()) - 400  # 6.7 minutes ago
        
        with self.assertRaises(SecurityError) as context:
            self.security.validate_nonce(nonce, old_timestamp)
        
        self.assertIn("window", str(context.exception))
    
    def test_04_future_timestamp(self):
        """Test future timestamp rejection"""
        nonce = secrets.token_hex(32)
        future_timestamp = int(time.time()) + 400  # 6.7 minutes in future
        
        with self.assertRaises(SecurityError) as context:
            self.security.validate_nonce(nonce, future_timestamp)
        
        self.assertIn("window", str(context.exception))
    
    def test_05_nonce_cleanup(self):
        """Test nonce cache cleanup"""
        # Add many nonces
        for i in range(10):
            nonce = secrets.token_hex(32)
            timestamp = int(time.time())
            self.security.validate_nonce(nonce, timestamp)
        
        # Verify cache size
        self.assertEqual(self.security.get_nonce_cache_size(), 10)
        
        # Cleanup
        self.security._cleanup_nonces()
        
        # All nonces should still be there (not old enough)
        self.assertEqual(self.security.get_nonce_cache_size(), 10)


class TestRateLimiting(unittest.TestCase):
    """Test rate limiting"""
    
    def setUp(self):
        self.security = SecurityModule(
            rate_limit_window=60,
            rate_limit_max=5
        )
    
    def test_01_within_limit(self):
        """Test requests within rate limit"""
        agent_id = "agent001"
        
        # Make 5 requests (at limit)
        for i in range(5):
            valid = self.security.check_rate_limit(agent_id)
            self.assertTrue(valid)
    
    def test_02_exceed_limit(self):
        """Test exceeding rate limit"""
        agent_id = "agent001"
        
        # Make 5 requests
        for i in range(5):
            self.security.check_rate_limit(agent_id)
        
        # 6th request should fail
        with self.assertRaises(SecurityError) as context:
            self.security.check_rate_limit(agent_id)
        
        self.assertIn("Rate limit", str(context.exception))
    
    def test_03_different_agents(self):
        """Test rate limiting per agent"""
        agent1 = "agent001"
        agent2 = "agent002"
        
        # Exhaust agent1's limit
        for i in range(5):
            self.security.check_rate_limit(agent1)
        
        # Agent2 should still be able to make requests
        for i in range(5):
            valid = self.security.check_rate_limit(agent2)
            self.assertTrue(valid)
    
    def test_04_rate_limit_status(self):
        """Test rate limit status"""
        agent_id = "agent001"
        
        # Make 3 requests
        for i in range(3):
            self.security.check_rate_limit(agent_id)
        
        # Get status
        status = self.security.get_rate_limit_status(agent_id)
        
        self.assertEqual(status["requests_in_window"], 3)
        self.assertEqual(status["limit"], 5)
        self.assertEqual(status["percentage_used"], 60.0)
    
    def test_05_reset_rate_limit(self):
        """Test rate limit reset"""
        agent_id = "agent001"
        
        # Exhaust limit
        for i in range(5):
            self.security.check_rate_limit(agent_id)
        
        # Reset
        self.security.reset_rate_limit(agent_id)
        
        # Should be able to make requests again
        valid = self.security.check_rate_limit(agent_id)
        self.assertTrue(valid)


class TestCommandValidation(unittest.TestCase):
    """Test command validation"""
    
    def setUp(self):
        self.security = SecurityModule()
    
    def test_01_valid_command(self):
        """Test valid command validation"""
        command = {
            'task_id': 'task001',
            'operator_id': 'op001',
            'agent_id': 'agent001',
            'type': 'exec',
            'payload': 'whoami',
            'nonce': secrets.token_hex(32),
            'timestamp': int(time.time()),
            'signature': 'a' * 128  # 64 bytes = 128 hex chars
        }
        
        valid = self.security.validate_command(command)
        self.assertTrue(valid)
    
    def test_02_missing_field(self):
        """Test command with missing field"""
        command = {
            'task_id': 'task001',
            'type': 'exec',
            'payload': 'whoami',
            'nonce': secrets.token_hex(32),
            'timestamp': int(time.time()),
            'signature': 'a' * 128
        }
        
        with self.assertRaises(SecurityError) as context:
            self.security.validate_command(command)
        
        self.assertIn("Missing", str(context.exception))
    
    def test_03_invalid_command_type(self):
        """Test command with invalid type"""
        command = {
            'task_id': 'task001',
            'operator_id': 'op001',
            'agent_id': 'agent001',
            'type': 'invalid_type',
            'payload': 'whoami',
            'nonce': secrets.token_hex(32),
            'timestamp': int(time.time()),
            'signature': 'a' * 128
        }
        
        with self.assertRaises(SecurityError) as context:
            self.security.validate_command(command)
        
        self.assertIn("Invalid command type", str(context.exception))
    
    def test_04_invalid_nonce(self):
        """Test command with invalid nonce"""
        command = {
            'task_id': 'task001',
            'operator_id': 'op001',
            'agent_id': 'agent001',
            'type': 'exec',
            'payload': 'whoami',
            'nonce': 'invalid_nonce',
            'timestamp': int(time.time()),
            'signature': 'a' * 128
        }
        
        with self.assertRaises(SecurityError) as context:
            self.security.validate_command(command)
        
        self.assertIn("Invalid nonce", str(context.exception))


class TestInputSanitization(unittest.TestCase):
    """Test input sanitization"""
    
    def setUp(self):
        self.security = SecurityModule()
    
    def test_01_valid_input(self):
        """Test valid input sanitization"""
        data = "Hello World"
        sanitized = self.security.sanitize_input(data)
        self.assertEqual(sanitized, data)
    
    def test_02_null_bytes(self):
        """Test null byte removal"""
        data = "Hello\x00World"
        sanitized = self.security.sanitize_input(data)
        self.assertEqual(sanitized, "HelloWorld")
    
    def test_03_dangerous_patterns(self):
        """Test dangerous pattern detection"""
        dangerous = "rm -rf / --no-preserve-root"
        
        with self.assertRaises(SecurityError) as context:
            self.security.sanitize_input(dangerous)
        
        self.assertIn("Dangerous", str(context.exception))
    
    def test_04_long_input(self):
        """Test long input rejection"""
        long_data = "A" * 5000
        
        with self.assertRaises(SecurityError) as context:
            self.security.sanitize_input(long_data, max_length=4096)
        
        self.assertIn("too long", str(context.exception))


class TestSecurityStats(unittest.TestCase):
    """Test security statistics"""
    
    def setUp(self):
        self.security = SecurityModule()
    
    def test_01_initial_stats(self):
        """Test initial security statistics"""
        stats = self.security.get_security_stats()
        
        self.assertEqual(stats["pinned_certificates"], 0)
        self.assertEqual(stats["nonce_cache_size"], 0)
        self.assertEqual(stats["rate_limited_agents"], 0)
        self.assertEqual(stats["replay_window_seconds"], 300)
        self.assertEqual(stats["rate_limit_max"], 100)
    
    def test_02_stats_after_operations(self):
        """Test statistics after operations"""
        # Pin certificate
        cert = MockCertificate(b"test")
        self.security.pin_certificate("agent001", cert)
        
        # Add nonce
        self.security.validate_nonce(secrets.token_hex(32), int(time.time()))
        
        # Rate limit
        self.security.check_rate_limit("agent001")
        
        # Get stats
        stats = self.security.get_security_stats()
        
        self.assertEqual(stats["pinned_certificates"], 1)
        self.assertEqual(stats["nonce_cache_size"], 1)
        self.assertEqual(stats["rate_limited_agents"], 1)


class TestConcurrentAccess(unittest.TestCase):
    """Test thread safety"""
    
    def setUp(self):
        self.security = SecurityModule(rate_limit_max=100)
    
    def test_01_concurrent_nonce_validation(self):
        """Test concurrent nonce validation"""
        errors = []
        
        def validate_nonce():
            try:
                nonce = secrets.token_hex(32)
                timestamp = int(time.time())
                self.security.validate_nonce(nonce, timestamp)
            except Exception as e:
                errors.append(e)
        
        # Run 100 threads
        threads = [threading.Thread(target=validate_nonce) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # No errors should occur
        self.assertEqual(len(errors), 0)
    
    def test_02_concurrent_rate_limiting(self):
        """Test concurrent rate limiting"""
        agent_id = "agent001"
        errors = []
        
        def check_limit():
            try:
                self.security.check_rate_limit(agent_id)
            except Exception as e:
                errors.append(e)
        
        # Run 150 threads (exceeds 100 limit)
        threads = [threading.Thread(target=check_limit) for _ in range(150)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should have rate limit errors
        self.assertGreater(len(errors), 0)


class TestIntegration(unittest.TestCase):
    """Integration tests combining multiple security features"""
    
    def setUp(self):
        self.security = SecurityModule()
        self.crypto = CryptoEngine()
    
    def test_01_full_security_workflow(self):
        """Test complete security workflow"""
        agent_id = "agent001"
        cert = MockCertificate(b"test_cert")
        
        # 1. Pin certificate
        self.security.pin_certificate(agent_id, cert)
        
        # 2. Validate certificate
        valid = self.security.validate_pinned_certificate(agent_id, cert)
        self.assertTrue(valid)
        
        # 3. Check rate limit
        valid = self.security.check_rate_limit(agent_id)
        self.assertTrue(valid)
        
        # 4. Validate nonce
        nonce = secrets.token_hex(32)
        timestamp = int(time.time())
        valid = self.security.validate_nonce(nonce, timestamp)
        self.assertTrue(valid)
        
        # 5. Validate command
        command = {
            'task_id': 'task001',
            'operator_id': 'op001',
            'agent_id': agent_id,
            'type': 'exec',
            'payload': 'whoami',
            'nonce': secrets.token_hex(32),
            'timestamp': int(time.time()),
            'signature': 'a' * 128
        }
        valid = self.security.validate_command(command)
        self.assertTrue(valid)
    
    def test_02_attack_simulation(self):
        """Simulate various attacks"""
        agent_id = "agent001"
        cert = MockCertificate(b"test_cert")
        
        # Pin certificate
        self.security.pin_certificate(agent_id, cert)
        
        # MITM attack
        mitm_cert = MockCertificate(b"mitm_cert")
        with self.assertRaises(SecurityError):
            self.security.validate_pinned_certificate(agent_id, mitm_cert)
        
        # Replay attack
        nonce = secrets.token_hex(32)
        timestamp = int(time.time())
        self.security.validate_nonce(nonce, timestamp)
        
        with self.assertRaises(SecurityError):
            self.security.validate_nonce(nonce, timestamp)
        
        # Rate limit attack
        for _ in range(100):
            try:
                self.security.check_rate_limit(agent_id)
            except SecurityError:
                break
        
        # Should be rate limited now
        with self.assertRaises(SecurityError):
            self.security.check_rate_limit(agent_id)


def run_tests():
    """Run all security tests"""
    print("=" * 70)
    print("🔥 SecureComm Security Test Suite 🔥")
    print("=" * 70)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestCertificatePinning))
    suite.addTests(loader.loadTestsFromTestCase(TestReplayProtection))
    suite.addTests(loader.loadTestsFromTestCase(TestRateLimiting))
    suite.addTests(loader.loadTestsFromTestCase(TestCommandValidation))
    suite.addTests(loader.loadTestsFromTestCase(TestInputSanitization))
    suite.addTests(loader.loadTestsFromTestCase(TestSecurityStats))
    suite.addTests(loader.loadTestsFromTestCase(TestConcurrentAccess))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 70)
    print("Test Summary:")
    print(f"  Tests run: {result.testsRun}")
    print(f"  Failures: {len(result.failures)}")
    print(f"  Errors: {len(result.errors)}")
    print(f"  Skipped: {len(result.skipped)}")
    
    if result.wasSuccessful():
        print("\n✅ All security tests passed!")
    else:
        print("\n❌ Some security tests failed!")
    
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
