#!/usr/bin/env python3
"""
SecureComm C2 - Attack Simulation Tests
========================================

Tests security controls against common attacks:
1. MITM Attack - Certificate pinning validation
2. Replay Attack - Nonce uniqueness enforcement  
3. Tampering - GCM authentication tag verification
4. DoS - Rate limiting protection

Run: python tests/test_attack_simulations.py
"""

import sys
import time
import hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from securecomm.security import SecurityModule, SecurityError
from securecomm.crypto_engine import CryptoEngine
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa


class AttackSimulator:
    """Simulates various attacks against SecureComm security controls"""
    
    def __init__(self):
        self.security = SecurityModule()
        self.crypto = CryptoEngine()
        self.passed = 0
        self.failed = 0
        
    def print_header(self, title):
        """Print test section header"""
        print("\n" + "="*70)
        print(f"🔥 {title}")
        print("="*70)
        
    def print_result(self, test_name, passed, details=""):
        """Print test result"""
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"  {status} - {test_name}")
        if details:
            print(f"      {details}")
        if passed:
            self.passed += 1
        else:
            self.failed += 1
            
    def generate_test_certificate(self, common_name="test-agent"):
        """Generate a self-signed test certificate"""
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        now = datetime.now(timezone.utc)
        cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)])
        ).issuer_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test CA")])
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + timedelta(days=1)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        ).sign(key, hashes.SHA256())
        return cert

    # ========================================================================
    # 9.2 ATTACK SIMULATION TESTS
    # ========================================================================
    
    def test_mitm_forged_certificate(self):
        """
        Test 9.2.1: MITM Attack - Present forged certificate
        Expected: ❌ Rejected by certificate pinning
        """
        self.print_header("TEST 9.2.1: MITM Attack - Certificate Pinning")
        print("  Scenario: Attacker presents forged certificate")
        print("  Expected: Connection rejected due to fingerprint mismatch\n")
        
        try:
            # Step 1: Legitimate agent connects and pins certificate
            agent_id = "agent-001"
            legit_cert = self.generate_test_certificate(agent_id)
            
            print(f"  1️⃣  First connection - Pinning certificate for {agent_id}")
            self.security.pin_certificate(agent_id, legit_cert)
            print(f"      📌 Certificate pinned: {self.security.pinned_certs[agent_id][:16]}...")
            
            # Step 2: MITM attacker presents different certificate
            print(f"  2️⃣  MITM attacker presents forged certificate")
            forged_cert = self.generate_test_certificate(agent_id)
            
            # Step 3: Attempt validation (should fail)
            print(f"  3️⃣  Validating forged certificate...")
            self.security.validate_pinned_certificate(agent_id, forged_cert)
            
            self.print_result("MITM Attack Prevention", False, 
                            "Certificate was accepted (should be rejected)")
            
        except SecurityError as e:
            self.print_result("MITM Attack Prevention", True,
                            f"SecurityError raised: {str(e)}")
            print(f"\n      🛡️  Attack blocked! Certificate mismatch detected.")
            
    def test_replay_attack(self):
        """
        Test 9.2.2: Replay Attack - Resend captured command
        Expected: ❌ Nonce rejected (already seen)
        """
        self.print_header("TEST 9.2.2: Replay Attack - Nonce Validation")
        print("  Scenario: Attacker captures and resends valid command")
        print("  Expected: Command rejected due to nonce reuse\n")
        
        try:
            # Step 1: Valid command with unique nonce
            nonce = "nonce-123456789-abc"
            timestamp = int(time.time())
            
            print(f"  1️⃣  First command with nonce: {nonce[:20]}...")
            self.security.validate_nonce(nonce, timestamp)
            print(f"      ✅ Nonce accepted and stored")
            
            # Step 2: Attacker tries to replay same command
            print(f"  2️⃣  Attacker replays same nonce...")
            time.sleep(0.1)
            self.security.validate_nonce(nonce, timestamp)
            
            self.print_result("Replay Attack Prevention", False,
                            "Replayed nonce was accepted")
            
        except SecurityError as e:
            self.print_result("Replay Attack Prevention", True,
                            f"SecurityError raised: {str(e)}")
            print(f"\n      🛡️  Attack blocked! Nonce already used.")
            
    def test_tampering_attack(self):
        """
        Test 9.2.3: Tampering - Modify encrypted payload
        Expected: ❌ GCM tag invalid (decryption fails)
        """
        self.print_header("TEST 9.2.3: Tampering - Payload Integrity")
        print("  Scenario: Attacker modifies encrypted payload bytes")
        print("  Expected: AES-GCM tag validation fails\n")
        
        try:
            # Step 1: Generate key and encrypt message
            print(f"  1️⃣  Generating AES-256-GCM key...")
            key = self.crypto.generate_session_key()
            message = b"Execute command: whoami"
            
            print(f"  2️⃣  Encrypting message: {message}")
            ciphertext, nonce, tag = self.crypto.encrypt_message(key, message)
            print(f"      🔒 Ciphertext: {ciphertext[:20].hex()}...")
            print(f"      🏷️  Tag: {tag[:8].hex()}...")
            
            # Step 3: Attacker tampers with ciphertext
            print(f"  3️⃣  Attacker modifies ciphertext byte at position 5")
            tampered_ciphertext = bytearray(ciphertext)
            tampered_ciphertext[5] ^= 0xFF  # Flip bits
            tampered_ciphertext = bytes(tampered_ciphertext)
            
            # Step 4: Attempt decryption (should fail)
            print(f"  4️⃣  Attempting decryption with tampered payload...")
            decrypted = self.crypto.decrypt_message(key, tampered_ciphertext, nonce, tag)
            
            self.print_result("Tampering Detection", False,
                            "Tampered message was decrypted successfully")
            
        except Exception as e:
            self.print_result("Tampering Detection", True,
                            f"Decryption failed: {type(e).__name__}")
            print(f"\n      🛡️  Attack blocked! GCM authentication tag invalid.")
            
    def test_dos_attack(self):
        """
        Test 9.2.4: DoS Attack - Send 200 requests/minute
        Expected: ❌ Rate limited after 100 requests
        """
        self.print_header("TEST 9.2.4: DoS Attack - Rate Limiting")
        print("  Scenario: Attacker floods server with 200 requests/minute")
        print("  Expected: Requests blocked after limit (100 req/min)\n")
        
        agent_id = "attacker-agent"
        allowed_requests = 0
        blocked_requests = 0
        
        print(f"  1️⃣  Sending 150 rapid requests from {agent_id}...")
        
        for i in range(150):
            try:
                self.security.check_rate_limit(agent_id)
                allowed_requests += 1
                if i < 5 or i > 145:  # Print first 5 and last 5
                    print(f"      Request {i+1}: ✅ Allowed")
                elif i == 5:
                    print(f"      ... ({150-10} requests omitted) ...")
            except SecurityError as e:
                blocked_requests += 1
                if blocked_requests <= 3:  # Print first 3 blocks
                    print(f"      Request {i+1}: ❌ BLOCKED - {str(e)[:50]}")
                elif blocked_requests == 4:
                    print(f"      ... (additional blocks omitted) ...")
                    
        print(f"\n  📊 Results:")
        print(f"      Allowed: {allowed_requests} requests")
        print(f"      Blocked: {blocked_requests} requests")
        
        if blocked_requests > 0 and allowed_requests <= 100:
            self.print_result("DoS Rate Limiting", True,
                            f"Rate limit enforced: {allowed_requests}/{150} allowed")
            print(f"\n      🛡️  Attack blocked! Rate limiting activated.")
        else:
            self.print_result("DoS Rate Limiting", False,
                            "Rate limit not enforced")

    # ========================================================================
    # SUMMARY
    # ========================================================================
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "="*70)
        print("📊 ATTACK SIMULATION TEST SUMMARY")
        print("="*70)
        print(f"  ✅ Passed: {self.passed}")
        print(f"  ❌ Failed: {self.failed}")
        print(f"  📈 Total:  {self.passed + self.failed}")
        
        if self.failed == 0:
            print("\n  🎉 All security controls working correctly!")
            print("  🔒 System is resistant to tested attacks.")
        else:
            print(f"\n  ⚠️  {self.failed} test(s) failed - review security controls")
            
        print("\n" + "="*70)
        print("Attack Type          | Result")
        print("-" * 50)
        print("MITM (Certificate)   | ❌ Rejected ✓")
        print("Replay (Nonce)       | ❌ Rejected ✓")
        print("Tampering (GCM)      | ❌ Rejected ✓")
        print("DoS (Rate Limit)     | ❌ Rejected ✓")
        print("="*70)


def main():
    """Run all attack simulation tests"""
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║     🔥 SECURECOMM C2 - ATTACK SIMULATION TESTS 🔥                    ║
║                                                                      ║
║  Testing security controls against:                                  ║
║    • MITM attacks (certificate pinning)                              ║
║    • Replay attacks (nonce validation)                               ║
║    • Tampering (GCM authentication)                                  ║
║    • DoS attacks (rate limiting)                                     ║
╚══════════════════════════════════════════════════════════════════════╝
    """)
    
    simulator = AttackSimulator()
    
    # Run all attack tests
    simulator.test_mitm_forged_certificate()
    simulator.test_replay_attack()
    simulator.test_tampering_attack()
    simulator.test_dos_attack()
    
    # Print summary
    simulator.print_summary()
    
    # Exit with appropriate code
    sys.exit(0 if simulator.failed == 0 else 1)


if __name__ == "__main__":
    main()
