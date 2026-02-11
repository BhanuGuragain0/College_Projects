"""
Dashboard API Tests for SecureComm v2.0
Comprehensive tests for REST API and WebSocket endpoints

Author: Shadow Junior
"""

import os
import sys
import unittest
import asyncio
import json
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timezone

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop
from aiohttp.web import AppKey, WSMsgType
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from src.securecomm.dashboard_server import create_app, DashboardStats, DashboardWebSocketManager
from src.securecomm.pki_manager import PKIManager
from src.securecomm.crypto_engine import CryptoEngine
from src.securecomm.operational_db import OperationalDatabase, AgentRecord, CommandRecord


class TestDashboardWebSocket(unittest.TestCase):
    """Test WebSocket functionality"""
    
    def setUp(self):
        self.ws_manager = DashboardWebSocketManager()
    
    def test_01_websocket_manager_init(self):
        """Test WebSocket manager initialization"""
        self.assertEqual(len(self.ws_manager.connections), 0)
    
    def test_02_broadcast_empty(self):
        """Test broadcast with no connections"""
        # Should not raise error
        asyncio.run(self.ws_manager.broadcast({"test": "message"}))


class TestDashboardStats(unittest.TestCase):
    """Test dashboard statistics"""
    
    def test_01_stats_initialization(self):
        """Test stats initialization"""
        stats = DashboardStats()
        self.assertEqual(stats.total_agents, 0)
        self.assertEqual(stats.active_agents, 0)
        self.assertEqual(stats.total_commands, 0)
    
    def test_02_stats_to_dict(self):
        """Test stats serialization"""
        stats = DashboardStats(
            total_agents=5,
            active_agents=3,
            total_commands=100,
            commands_per_minute=12.5
        )
        data = stats.to_dict()
        self.assertEqual(data["total_agents"], 5)
        self.assertEqual(data["active_agents"], 3)
        self.assertEqual(data["commands_per_minute"], 12.5)


class TestDashboardAPI(AioHTTPTestCase):
    """Test suite for Dashboard API endpoints"""
    
    async def get_application(self):
        """Create test application"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_db.json"
        self.log_dir = Path(self.temp_dir) / "logs"
        self.pki_path = Path(self.temp_dir) / "pki"
        
        # Create PKI
        self.pki = PKIManager(pki_path=str(self.pki_path))
        ca_cert, ca_key = self.pki.generate_root_ca()
        op_cert, op_key = self.pki.issue_certificate("admin", cert_type="operator")
        agent_cert, agent_key = self.pki.issue_certificate("agent001", cert_type="agent")
        
        # Create app with test token
        self.token = "test_dashboard_token_12345"
        
        app = create_app(
            db_path=self.db_path,
            audit_log_dir=self.log_dir,
            refresh_seconds=5,
            token=self.token,
            command_server=None,
        )
        
        return app
    
    async def tearDownAsync(self):
        """Clean up test data"""
        if hasattr(self, 'temp_dir'):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        
        # Close aiohttp client session properly
        if hasattr(self, 'client'):
            await self.client.close()
    
    # ==================== AUTHENTICATION TESTS ====================
    
    async def test_01_unauthorized_access(self):
        """Test unauthorized access is blocked"""
        resp = await self.client.request("GET", "/")
        self.assertEqual(resp.status, 401)
    
    async def test_02_authorized_access(self):
        """Test authorized access with token"""
        headers = {"Authorization": f"Bearer {self.token}"}
        resp = await self.client.request("GET", "/", headers=headers)
        self.assertEqual(resp.status, 200)
        self.assertIn("text/html", resp.headers.get("Content-Type", ""))
    
    async def test_03_invalid_token(self):
        """Test invalid token rejection"""
        headers = {"Authorization": "Bearer invalid_token"}
        resp = await self.client.request("GET", "/", headers=headers)
        self.assertEqual(resp.status, 401)
    
    async def test_04_query_token(self):
        """Test token via query parameter"""
        resp = await self.client.request("GET", f"/?token={self.token}")
        self.assertEqual(resp.status, 200)
    
    # ==================== SECURITY HEADERS TESTS ====================
    
    async def test_05_security_headers_present(self):
        """Test security headers are present"""
        headers = {"Authorization": f"Bearer {self.token}"}
        resp = await self.client.request("GET", "/", headers=headers)
        
        self.assertIn("X-Content-Type-Options", resp.headers)
        self.assertIn("X-Frame-Options", resp.headers)
        self.assertIn("Content-Security-Policy", resp.headers)
        self.assertIn("X-XSS-Protection", resp.headers)
        self.assertEqual(resp.headers["X-Frame-Options"], "DENY")
    
    # ==================== HEALTH CHECK TESTS ====================
    
    async def test_06_health_check_no_auth(self):
        """Test health check without authentication"""
        resp = await self.client.request("GET", "/health")
        self.assertEqual(resp.status, 200)
        
        data = await resp.json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("version", data)
        self.assertIn("uptime_seconds", data)
    
    # ==================== API STATE TESTS ====================
    
    async def test_07_api_state(self):
        """Test API state endpoint"""
        headers = {"Authorization": f"Bearer {self.token}"}
        resp = await self.client.request("GET", "/api/state", headers=headers)
        self.assertEqual(resp.status, 200)
        
        data = await resp.json()
        self.assertIn("stats", data)
        self.assertIn("agents", data)
        self.assertIn("commands", data)
        self.assertIn("timestamp", data)
    
    async def test_08_api_agents(self):
        """Test API agents endpoint"""
        headers = {"Authorization": f"Bearer {self.token}"}
        resp = await self.client.request("GET", "/api/agents", headers=headers)
        self.assertEqual(resp.status, 200)
        
        data = await resp.json()
        self.assertIn("agents", data)
        self.assertIsInstance(data["agents"], list)
    
    async def test_09_api_agent_detail_not_found(self):
        """Test API agent detail for non-existent agent"""
        headers = {"Authorization": f"Bearer {self.token}"}
        resp = await self.client.request("GET", "/api/agents/nonexistent", headers=headers)
        self.assertEqual(resp.status, 404)
    
    async def test_10_api_commands(self):
        """Test API commands endpoint"""
        headers = {"Authorization": f"Bearer {self.token}"}
        resp = await self.client.request("GET", "/api/commands", headers=headers)
        self.assertEqual(resp.status, 200)
        
        data = await resp.json()
        self.assertIn("commands", data)
        self.assertIsInstance(data["commands"], list)
    
    async def test_11_api_audit(self):
        """Test API audit endpoint"""
        headers = {"Authorization": f"Bearer {self.token}"}
        resp = await self.client.request("GET", "/api/audit", headers=headers)
        self.assertEqual(resp.status, 200)
        
        data = await resp.json()
        self.assertIn("entries", data)
        self.assertIsInstance(data["entries"], list)
    
    async def test_12_api_stats(self):
        """Test API stats endpoint"""
        headers = {"Authorization": f"Bearer {self.token}"}
        resp = await self.client.request("GET", "/api/stats", headers=headers)
        self.assertEqual(resp.status, 200)
        
        data = await resp.json()
        self.assertIn("total_agents", data)
        self.assertIn("total_commands", data)
    
    # ==================== PAGE RENDERING TESTS ====================
    
    async def test_13_page_agents(self):
        """Test agents page rendering"""
        headers = {"Authorization": f"Bearer {self.token}"}
        resp = await self.client.request("GET", "/agents", headers=headers)
        self.assertEqual(resp.status, 200)
        self.assertIn("text/html", resp.headers.get("Content-Type", ""))
    
    async def test_14_page_commands(self):
        """Test commands page rendering"""
        headers = {"Authorization": f"Bearer {self.token}"}
        resp = await self.client.request("GET", "/commands", headers=headers)
        self.assertEqual(resp.status, 200)
    
    async def test_15_page_audit(self):
        """Test audit page rendering"""
        headers = {"Authorization": f"Bearer {self.token}"}
        resp = await self.client.request("GET", "/audit", headers=headers)
        self.assertEqual(resp.status, 200)
    
    async def test_16_page_files(self):
        """Test files page rendering"""
        headers = {"Authorization": f"Bearer {self.token}"}
        resp = await self.client.request("GET", "/files", headers=headers)
        self.assertEqual(resp.status, 200)
    
    async def test_17_page_stats(self):
        """Test stats page rendering"""
        headers = {"Authorization": f"Bearer {self.token}"}
        resp = await self.client.request("GET", "/stats", headers=headers)
        self.assertEqual(resp.status, 200)
    
    # ==================== COMMAND SUBMISSION TESTS ====================
    
    async def test_18_submit_command_unauthorized(self):
        """Test command submission without auth"""
        resp = await self.client.request(
            "POST",
            "/api/command",
            json={"agent_id": "agent001", "type": "exec", "payload": "whoami"}
        )
        self.assertEqual(resp.status, 401)
    
    async def test_19_submit_command_invalid_agent(self):
        """Test command submission for non-existent agent"""
        headers = {"Authorization": f"Bearer {self.token}"}
        resp = await self.client.request(
            "POST",
            "/api/command",
            headers=headers,
            json={"agent_id": "nonexistent", "type": "exec", "payload": "whoami"}
        )
        self.assertEqual(resp.status, 404)
    
    async def test_20_submit_command_invalid_type(self):
        """Test command submission with invalid type"""
        headers = {"Authorization": f"Bearer {self.token}"}
        resp = await self.client.request(
            "POST",
            "/api/command",
            headers=headers,
            json={"agent_id": "agent001", "type": "invalid_type", "payload": "whoami"}
        )
        self.assertEqual(resp.status, 400)
    
    async def test_21_submit_command_missing_fields(self):
        """Test command submission with missing fields"""
        headers = {"Authorization": f"Bearer {self.token}"}
        
        # Missing agent_id
        resp = await self.client.request(
            "POST",
            "/api/command",
            headers=headers,
            json={"type": "exec", "payload": "whoami"}
        )
        self.assertEqual(resp.status, 400)
        
        # Missing type
        resp = await self.client.request(
            "POST",
            "/api/command",
            headers=headers,
            json={"agent_id": "agent001", "payload": "whoami"}
        )
        self.assertEqual(resp.status, 400)
    
    async def test_22_submit_command_invalid_json(self):
        """Test command submission with invalid JSON"""
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        resp = await self.client.request(
            "POST",
            "/api/command",
            headers=headers,
            data="invalid json"
        )
        self.assertEqual(resp.status, 400)
    
    # ==================== WEBSOCKET TESTS ====================
    
    async def test_23_websocket_connection(self):
        """Test WebSocket connection"""
        ws = await self.client.ws_connect(f"/ws?token={self.token}")
        self.assertIsNotNone(ws)
        await ws.close()
    
    async def test_24_websocket_ping_pong(self):
        """Test WebSocket ping/pong"""
        ws = await self.client.ws_connect(f"/ws?token={self.token}")
        
        await ws.send_json({"type": "ping"})
        msg = await ws.receive()
        self.assertEqual(msg.type, 1)  # WSMsgType.TEXT
        
        data = json.loads(msg.data)
        self.assertEqual(data["type"], "pong")
        
        await ws.close()
    
    async def test_25_websocket_unauthorized(self):
        """Test WebSocket without token"""
        resp = await self.client.request("GET", "/ws")
        self.assertEqual(resp.status, 401)


class TestDashboardIntegration(unittest.TestCase):
    """Integration tests for dashboard"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_db.json"
        self.log_dir = Path(self.temp_dir) / "logs"
        
        # Create PKI
        self.pki_path = Path(self.temp_dir) / "pki"
        self.pki = PKIManager(pki_path=str(self.pki_path))
        self.ca_cert, self.ca_key = self.pki.generate_root_ca()
        self.op_cert, self.op_key = self.pki.issue_certificate("admin", cert_type="operator")
        self.agent_cert, self.agent_key = self.pki.issue_certificate("agent001", cert_type="agent")
    
    def tearDown(self):
        """Clean up test data"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_01_app_creation(self):
        """Test app creation with valid parameters"""
        app = create_app(
            db_path=self.db_path,
            audit_log_dir=self.log_dir,
            refresh_seconds=5,
            token="test_token",
            command_server=None,
        )
        
        self.assertIsNotNone(app)
    
    def test_02_pki_validation(self):
        """Test PKI certificate validation"""
        # Validate operator certificate
        valid = self.pki.validate_certificate(self.op_cert, self.ca_cert)
        self.assertTrue(valid)
        
        # Validate agent certificate
        valid = self.pki.validate_certificate(self.agent_cert, self.ca_cert)
        self.assertTrue(valid)
    
    def test_03_certificate_revocation(self):
        """Test certificate revocation"""
        serial = str(self.agent_cert.serial_number)
        
        # Revoke certificate
        self.pki.revoke_certificate(serial, "key_compromise")
        
        # Verify revoked
        is_revoked = self.pki.is_revoked(serial)
        self.assertTrue(is_revoked)
        
        # Validation should fail
        with self.assertRaises(ValueError):
            self.pki.validate_certificate(self.agent_cert, self.ca_cert)


class TestDashboardWithData(unittest.TestCase):
    """Test dashboard with sample data"""
    
    def setUp(self):
        """Set up test environment with data"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_db.json"
        self.log_dir = Path(self.temp_dir) / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create database with sample data
        self.db = OperationalDatabase(storage_path=str(self.db_path))
        
        # Add sample agents
        from datetime import datetime, timezone
        
        agent1 = AgentRecord(
            agent_id="agent001",
            ip_address="192.168.1.100",
            status="connected",
            connected_at=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            certificate_fingerprint="abc123",
            certificate_subject="CN=agent001"
        )
        self.db.register_agent(agent1)
        
        # Add sample commands
        cmd1 = CommandRecord(
            task_id="task_001",
            operator_id="admin",
            agent_id="agent001",
            command_type="exec",
            payload="whoami",
            nonce="nonce123",
            timestamp=int(datetime.now(timezone.utc).timestamp()),
            signature="sig123",
            status="success"
        )
        self.db.record_command(cmd1)
    
    def tearDown(self):
        """Clean up test data"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_01_database_with_data(self):
        """Test database with sample data"""
        agents = self.db.list_agents()
        self.assertEqual(len(agents), 1)
        self.assertEqual(agents[0].agent_id, "agent001")
        
        commands = self.db.list_commands()
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0].task_id, "task_001")


def run_tests():
    """Run all dashboard API tests"""
    print("=" * 70)
    print("🔥 SecureComm Dashboard API Test Suite v2.0 🔥")
    print("=" * 70)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestDashboardWebSocket))
    suite.addTests(loader.loadTestsFromTestCase(TestDashboardStats))
    suite.addTests(loader.loadTestsFromTestCase(TestDashboardAPI))
    suite.addTests(loader.loadTestsFromTestCase(TestDashboardIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestDashboardWithData))
    
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
        print("\n✅ All dashboard API tests passed!")
    else:
        print("\n❌ Some dashboard API tests failed!")
    
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
