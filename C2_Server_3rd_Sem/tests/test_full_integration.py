"""
Full Integration Tests for SecureComm
Tests end-to-end workflow: operator -> server -> agent

Author: Shadow Junior
"""

import os
import sys
import unittest
import asyncio
import tempfile
import shutil
import time
import threading
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.securecomm.pki_manager import PKIManager
from src.securecomm.crypto_engine import CryptoEngine
from src.securecomm.security import SecurityModule
from src.securecomm.session import SessionManager
from src.securecomm.operational_db import OperationalDatabase
from src.securecomm.audit import AuditLogger


class TestFullIntegration(unittest.TestCase):
    """Full integration test suite"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        cls.temp_dir = tempfile.mkdtemp()
        cls.pki_path = Path(cls.temp_dir) / "pki"
        cls.db_path = Path(cls.temp_dir) / "test_db.json"
        cls.log_dir = Path(cls.temp_dir) / "logs"
        
        # Create PKI
        cls.pki = PKIManager(pki_path=str(cls.pki_path))
        cls.ca_cert, cls.ca_key = cls.pki.generate_root_ca()
        cls.op_cert, cls.op_key = cls.pki.issue_certificate("admin", cert_type="operator")
        cls.agent_cert, cls.agent_key = cls.pki.issue_certificate("agent001", cert_type="agent")
        
        # Initialize components
        cls.crypto = CryptoEngine()
        cls.security = SecurityModule()
        cls.sessions = SessionManager()
        cls.operational_db = OperationalDatabase(storage_path=str(cls.db_path))
        cls.audit = AuditLogger(log_dir=str(cls.log_dir))
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test environment"""
        shutil.rmtree(cls.temp_dir, ignore_errors=True)
    
    def test_01_pki_workflow(self):
        """Test complete PKI workflow"""
        # Validate certificates
        self.assertTrue(self.pki.validate_certificate(self.op_cert, self.ca_cert))
        self.assertTrue(self.pki.validate_certificate(self.agent_cert, self.ca_cert))
        
        # Check certificate info
        op_info = self.pki.get_certificate_info(str(self.op_cert.serial_number))
        self.assertIsNotNone(op_info)
        self.assertEqual(op_info["type"], "operator")
        
        agent_info = self.pki.get_certificate_info(str(self.agent_cert.serial_number))
        self.assertIsNotNone(agent_info)
        self.assertEqual(agent_info["type"], "agent")
    
    def test_02_certificate_revocation(self):
        """Test certificate revocation"""
        serial = str(self.agent_cert.serial_number)
        
        # Revoke certificate
        self.pki.revoke_certificate(serial, "key_compromise")
        
        # Verify revoked
        self.assertTrue(self.pki.is_revoked(serial))
        
        # Validation should fail
        with self.assertRaises(ValueError):
            self.pki.validate_certificate(self.agent_cert, self.ca_cert)
    
    def test_03_crypto_workflow(self):
        """Test complete cryptographic workflow"""
        # Generate ECDH keys for Alice
        alice_crypto = CryptoEngine()
        alice_private, alice_public = alice_crypto.generate_ecdh_keypair()
        
        # Generate ECDH keys for Bob
        bob_crypto = CryptoEngine()
        bob_private, bob_public = bob_crypto.generate_ecdh_keypair()
        
        # Exchange public keys
        alice_pub_bytes = alice_crypto.serialize_ecdh_public_key()
        bob_pub_bytes = bob_crypto.serialize_ecdh_public_key()
        
        # Perform key exchange
        alice_shared = alice_crypto.perform_key_exchange(bob_pub_bytes)
        bob_shared = bob_crypto.perform_key_exchange(alice_pub_bytes)
        
        # Verify shared secrets match
        self.assertEqual(alice_shared, bob_shared)
        
        # Derive session keys
        alice_session = alice_crypto.derive_session_key(alice_shared)
        bob_session = bob_crypto.derive_session_key(bob_shared)
        
        self.assertEqual(alice_session, bob_session)
        
        # Encrypt and decrypt message
        plaintext = b"Test message"
        encrypted = alice_crypto.encrypt_message(plaintext, alice_session)
        decrypted = bob_crypto.decrypt_message(encrypted, bob_session)
        
        self.assertEqual(plaintext, decrypted)
    
    def test_04_session_management(self):
        """Test session management workflow"""
        agent_id = "test_agent"
        session_key = self.crypto.generate_random_bytes(32)
        ecdh_public = self.crypto.generate_random_bytes(32)
        
        # Create session
        session = self.sessions.create_session(agent_id, session_key, ecdh_public)
        self.assertIsNotNone(session)
        
        # Get session
        retrieved = self.sessions.get_session(agent_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.agent_id, agent_id)
        
        # Record command
        nonce = self.crypto.generate_nonce()
        result = self.sessions.record_command(agent_id, nonce)
        self.assertTrue(result)
        
        # Replay should fail
        result = self.sessions.record_command(agent_id, nonce)
        self.assertFalse(result)
        
        # Get stats
        stats = self.sessions.get_session_stats(agent_id)
        self.assertIsNotNone(stats)
        self.assertEqual(stats["agent_id"], agent_id)
        
        # Remove session
        self.sessions.remove_session(agent_id)
        self.assertIsNone(self.sessions.get_session(agent_id))
    
    def test_05_operational_database(self):
        """Test operational database workflow"""
        from src.securecomm.operational_db import AgentRecord, CommandRecord
        from datetime import datetime, timezone
        
        # Register agent
        agent = AgentRecord(
            agent_id="test_agent",
            ip_address="127.0.0.1",
            status="connected",
            connected_at=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            certificate_fingerprint="abc123",
            certificate_subject="CN=test_agent"
        )
        self.operational_db.register_agent(agent)
        
        # List agents
        agents = self.operational_db.list_agents()
        self.assertEqual(len(agents), 1)
        
        # Get agent
        retrieved = self.operational_db.get_agent("test_agent")
        self.assertIsNotNone(retrieved)
        
        # Update status
        self.operational_db.update_agent_status("test_agent", "active")
        retrieved = self.operational_db.get_agent("test_agent")
        self.assertEqual(retrieved.status, "active")
        
        # Record command
        command = CommandRecord(
            task_id="task_001",
            operator_id="admin",
            agent_id="test_agent",
            command_type="exec",
            payload="whoami",
            nonce="nonce123",
            timestamp=int(time.time()),
            signature="sig123"
        )
        self.operational_db.record_command(command)
        
        # List commands
        commands = self.operational_db.list_commands()
        self.assertEqual(len(commands), 1)
        
        # Record response
        self.operational_db.record_response("task_001", {"output": "user"}, "success")
        
        # Get command
        retrieved_cmd = self.operational_db.get_command("task_001")
        self.assertIsNotNone(retrieved_cmd)
        self.assertEqual(retrieved_cmd.status, "success")
    
    def test_06_security_workflow(self):
        """Test security features workflow"""
        agent_id = "agent001"
        
        # Certificate pinning - use real agent certificate
        self.security.pin_certificate(agent_id, self.agent_cert)
        
        # Validate pinned certificate
        self.assertTrue(self.security.validate_pinned_certificate(agent_id, self.agent_cert))
        
        # MITM detection - use operator cert as different cert
        with self.assertRaises(Exception):
            self.security.validate_pinned_certificate(agent_id, self.op_cert)
        
        # Nonce validation
        nonce = self.crypto.generate_nonce()
        timestamp = int(time.time())
        self.assertTrue(self.security.validate_nonce(nonce, timestamp))
        
        # Replay detection
        with self.assertRaises(Exception):
            self.security.validate_nonce(nonce, timestamp)
        
        # Rate limiting
        for _ in range(100):
            try:
                self.security.check_rate_limit(agent_id)
            except Exception:
                break
        
        # Should be rate limited now
        with self.assertRaises(Exception):
            self.security.check_rate_limit(agent_id)
    
    def test_07_audit_logging(self):
        """Test audit logging workflow"""
        # Log command
        self.audit.log_command(
            agent_id="test_agent",
            cmd_type="exec",
            payload="whoami",
            task_id="task_001",
            operator_id="admin"
        )
        
        # Log connection
        self.audit.log_connection(
            agent_id="test_agent",
            event="handshake",
            details={"ip": "127.0.0.1"}
        )
        
        # Log security event
        self.audit.log_security_event(
            event_type="mitm_detected",
            details={"agent_id": "test_agent"}
        )


class TestEndToEndWorkflow(unittest.TestCase):
    """End-to-end workflow tests"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.pki_path = Path(self.temp_dir) / "pki"
        
        # Create PKI
        self.pki = PKIManager(pki_path=str(self.pki_path))
        self.ca_cert, self.ca_key = self.pki.generate_root_ca()
        self.op_cert, self.op_key = self.pki.issue_certificate("admin", cert_type="operator")
        self.agent_cert, self.agent_key = self.pki.issue_certificate("agent001", cert_type="agent")
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_01_complete_handshake(self):
        """Test complete handshake workflow"""
        crypto = CryptoEngine()
        
        # Generate ECDH keys (simulating agent)
        agent_private, agent_public = crypto.generate_ecdh_keypair()
        agent_pub_bytes = crypto.serialize_ecdh_public_key()
        
        # Generate ECDH keys (simulating operator)
        op_crypto = CryptoEngine()
        op_private, op_public = op_crypto.generate_ecdh_keypair()
        op_pub_bytes = op_crypto.serialize_ecdh_public_key()
        
        # Perform key exchange (both sides)
        agent_shared = crypto.perform_key_exchange(op_pub_bytes)
        op_shared = op_crypto.perform_key_exchange(agent_pub_bytes)
        
        # Verify shared secrets match
        self.assertEqual(agent_shared, op_shared)
        
        # Derive session keys
        agent_session = crypto.derive_session_key(agent_shared)
        op_session = op_crypto.derive_session_key(op_shared)
        
        self.assertEqual(agent_session, op_session)
        
        # Test encrypted communication
        plaintext = b"Command: whoami"
        encrypted = crypto.encrypt_message(plaintext, agent_session)
        decrypted = op_crypto.decrypt_message(encrypted, op_session)
        
        self.assertEqual(plaintext, decrypted)
    
    def test_02_command_lifecycle(self):
        """Test complete command lifecycle"""
        from src.securecomm.operational_db import OperationalDatabase, CommandRecord
        from datetime import datetime, timezone
        
        db_path = Path(self.temp_dir) / "test_db.json"
        db = OperationalDatabase(storage_path=str(db_path))
        
        # Record command
        command = CommandRecord(
            task_id="task_001",
            operator_id="admin",
            agent_id="agent001",
            command_type="exec",
            payload="whoami",
            nonce="nonce123",
            timestamp=int(time.time()),
            signature="sig123"
        )
        db.record_command(command)
        
        # Verify command recorded
        commands = db.list_commands()
        self.assertEqual(len(commands), 1)
        
        # Record response
        db.record_response("task_001", {"output": "user"}, "success")
        
        # Verify response recorded
        cmd = db.get_command("task_001")
        self.assertEqual(cmd.status, "success")
        self.assertIsNotNone(cmd.response)


def run_tests():
    """Run all integration tests"""
    print("=" * 70)
    print("🔥 SecureComm Full Integration Test Suite 🔥")
    print("=" * 70)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestFullIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestEndToEndWorkflow))
    
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
        print("\n✅ All integration tests passed!")
    else:
        print("\n❌ Some integration tests failed!")
    
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
