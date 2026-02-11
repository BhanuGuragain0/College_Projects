#!/usr/bin/env python3
"""
SecureComm Autodrive Test Suite
Comprehensive system validation and feature verification

This script:
1. Starts the dashboard server
2. Tests all API endpoints
3. Verifies frontend/backend alignment
4. Tests complete workflows
5. Validates PKI integration
6. Tests all features from payload builder to audit logging
7. Generates detailed verification report

Usage:
    python tests/autodrive.py [--verbose] [--skip-server-start]
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID, ExtensionOID

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from securecomm.config import (
    DASHBOARD_HOST,
    DASHBOARD_PORT,
    PKI_PATH,
    OPERATIONAL_DB_PATH,
    AUDIT_LOG_DIR,
)
from securecomm.operational_db import OperationalDatabase, AgentRecord, CommandRecord
from securecomm.audit import AuditLogger
from securecomm.pki_manager import PKIManager
from securecomm.security import SecurityModule

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("AutoDrive")


class AutodriveTestRunner:
    """Comprehensive system test runner"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8080, skip_server_start: bool = False):
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
        self.skip_server_start = skip_server_start
        self.server_process = None
        self.session = None
        self.token = None
        self.results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tests": [],
            "passed": 0,
            "failed": 0,
            "warnings": 0,
            "total": 0,
            "features": {},
        }
        
    async def setup(self):
        """Setup test environment"""
        logger.info("🔧 Setting up test environment...")
        
        # Create PKI if not exists
        self._setup_pki()
        
        # Create session
        self.session = aiohttp.ClientSession()
        
        # Start server if not skipped
        if not self.skip_server_start:
            self._start_server()
            await self._wait_for_server()
        
        # Get dashboard token
        self.token = self._get_dashboard_token()
        logger.info(f"✅ Test environment ready (token: {self.token[:20]}...)")
    
    def _setup_pki(self):
        """Ensure PKI is set up"""
        pki_path = Path(PKI_PATH)
        ca_cert = pki_path / "ca" / "ca_root.crt"
        
        if not ca_cert.exists():
            logger.info("📋 Generating PKI infrastructure...")
            from securecomm.pki_manager import PKIManager
            pki = PKIManager(pki_path)
            pki.generate_ca()
            
            # Generate operator cert
            pki.generate_operator_certificate("admin", "admin")
            logger.info("✅ PKI generated")
    
    def _start_server(self):
        """Start dashboard server"""
        logger.info("🚀 Starting dashboard server...")
        launcher_path = Path(__file__).parent.parent / "launcher.py"
        
        # Set environment variable to disable token auth for testing
        env = os.environ.copy()
        env["SECURECOMM_DASHBOARD_TOKEN"] = ""
        
        self.server_process = subprocess.Popen(
            [sys.executable, str(launcher_path), "dashboard", 
             "--host", self.host, "--port", str(self.port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            env=env
        )
        logger.info(f"✅ Server started (PID: {self.server_process.pid})")
    
    async def _wait_for_server(self, timeout: int = 60):
        """Wait for server to be ready"""
        logger.info(f"⏳ Waiting for server to be ready ({timeout}s timeout)...")
        start = time.time()
        attempts = 0
        
        while time.time() - start < timeout:
            try:
                async with self.session.get(f"{self.base_url}/health", timeout=aiohttp.ClientTimeout(total=2)) as resp:
                    if resp.status in (200, 401):
                        logger.info("✅ Server is ready")
                        return
            except Exception:
                pass
            
            attempts += 1
            if attempts % 10 == 0:
                logger.debug(f"Still waiting... ({int(time.time() - start)}s elapsed)")
            
            await asyncio.sleep(0.5)
        
        raise TimeoutError(f"Server did not start within {timeout}s")
    
    def _get_dashboard_token(self) -> str:
        """Get or create dashboard token"""
        # For now, use default token from config or None for no auth
        from securecomm.config import DASHBOARD_TOKEN
        return DASHBOARD_TOKEN or ""
    
    def _record_test(self, name: str, passed: bool, message: str = "", details: Dict = None):
        """Record test result"""
        test_result = {
            "name": name,
            "passed": passed,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": message,
            "details": details or {}
        }
        self.results["tests"].append(test_result)
        
        if passed:
            self.results["passed"] += 1
            status = "✅ PASS"
        else:
            self.results["failed"] += 1
            status = "❌ FAIL"
        
        self.results["total"] += 1
        logger.info(f"{status} - {name}: {message}")
    
    async def test_dashboard_home(self):
        """Test dashboard home page"""
        try:
            async with self.session.get(f"{self.base_url}/") as resp:
                if resp.status == 200:
                    text = await resp.text()
                    has_ui = "SecureComm" in text and "<html" in text.lower()
                    self._record_test(
                        "Dashboard Home",
                        has_ui,
                        f"Status {resp.status}, {len(text)} bytes"
                    )
                    return has_ui
        except Exception as e:
            self._record_test("Dashboard Home", False, str(e))
            return False
    
    async def test_api_endpoints(self):
        """Test all API endpoints"""
        logger.info("🔍 Testing API endpoints...")
        
        endpoints = [
            # Core endpoints
            ("GET", "/api/stats", None, "stats"),
            ("GET", "/api/state", None, "state"),
            ("GET", "/api/agents", None, "agents"),
            ("GET", "/api/commands", None, "commands"),
            
            # Agent detail endpoints
            ("GET", "/api/agents/test_agent", None, "agent_detail"),
            
            # Audit endpoints
            ("GET", "/api/audit/logs", None, "audit_logs"),
            ("GET", "/api/audit/events", None, "audit_events"),
            ("GET", "/api/audit/search", None, "audit_search"),
            
            # PKI endpoints
            ("GET", "/api/certificates/list", None, "certificates_list"),
            ("GET", "/api/certificates", None, "certificates"),
            ("GET", "/api/certificates/operator/admin", None, "certificate_detail_operator"),
            ("GET", "/api/certificates/agent/test_agent", None, "certificate_detail_agent"),
            ("GET", "/api/certificates/ca/ca_root", None, "certificate_detail_ca"),
            
            # Config endpoints
            ("GET", "/api/config/commands", None, "config_commands"),
            
            # Payload builder endpoints
            ("GET", "/api/payload/templates", None, "payload_templates"),
            ("GET", "/api/payload/templates/exec", None, "payload_template_exec"),
            ("GET", "/api/payload/templates/basic_recon", None, "payload_template_basic_recon"),
            ("POST", "/api/payload/build", {"commands": [{"type": "exec", "payload": "whoami"}]}, "payload_build"),
            
            # File management endpoints
            ("GET", "/api/files/list?agent_id=test_agent", None, "files_list"),
            ("GET", "/api/files/browse?agent_id=test_agent", None, "files_browse"),
            ("POST", "/api/files/upload", {"agent_id": "test_agent", "file": "test.txt", "content": "test content"}, "files_upload"),
            ("GET", "/api/files/download?agent_id=test_agent&path=test.txt", None, "files_download"),
            
            # Command endpoints
            ("POST", "/api/command", {"agent_id": "test_agent", "type": "exec", "payload": "test"}, "command_submit"),
            ("POST", "/api/command/batch", {"agents": ["test_agent"], "command_type": "exec", "command_data": "test"}, "command_batch"),
            
            # Health and metrics endpoints
            ("GET", "/api/health/detailed", None, "health_detailed"),
            ("GET", "/api/metrics", None, "metrics_all"),
            ("GET", "/api/metrics/operation?operation=certificate_validation", None, "metrics_operation"),
            ("GET", "/api/metrics/errors", None, "metrics_errors"),
            
            # WebSocket endpoint (test connection)
            ("WS", "/ws", None, "websocket_connection"),
        ]
        
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        
        for method, endpoint, payload, test_name in endpoints:
            try:
                url = f"{self.base_url}{endpoint}"
                if method == "GET":
                    async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        passed = resp.status in (200, 401)  # 401 if auth required
                        self._record_test(
                            f"API {endpoint}",
                            passed,
                            f"Status {resp.status}"
                        )
                elif method == "POST":
                    async with self.session.post(url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        passed = resp.status in (200, 400, 401)
                        self._record_test(
                            f"API {endpoint}",
                            passed,
                            f"Status {resp.status}"
                        )
                elif method == "WS":
                    # Test WebSocket connection
                    try:
                        ws_url = self.base_url.replace("http://", "ws://") + endpoint
                        async with self.session.ws_connect(ws_url, timeout=aiohttp.ClientTimeout(total=5)) as ws:
                            await ws.send_json({"type": "ping", "timestamp": datetime.now(timezone.utc).isoformat()})
                            msg = await ws.receive(timeout=3)
                            ws_works = msg.type == aiohttp.WSMsgType.TEXT
                            
                            self._record_test(
                                f"API {endpoint}",
                                ws_works,
                                f"WebSocket: {'Connected' if ws_works else 'Failed'}"
                            )
                    except Exception as ws_e:
                        self._record_test(f"API {endpoint}", False, f"WebSocket error: {ws_e}")
            except Exception as e:
                self._record_test(f"API {endpoint}", False, str(e))
    
    async def test_command_submission(self):
        """Test command submission"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            
            # First, ensure we have an agent registered
            db = OperationalDatabase(OPERATIONAL_DB_PATH)
            
            # Register test agent if not exists
            agent_id = "test_agent_autodrive_001"
            agents = db.list_agents()
            agent_exists = any(a.agent_id == agent_id for a in agents)
            
            if not agent_exists:
                agent = AgentRecord(
                    agent_id=agent_id,
                    ip_address="127.0.0.1",
                    status="active",
                    connected_at=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc),
                    certificate_fingerprint="test_fingerprint",
                    certificate_subject="CN=test_agent",
                )
                db.register_agent(agent)
                logger.info(f"📌 Created test agent: {agent_id}")
            
            # Submit command
            payload = {
                "agent_id": agent_id,
                "command_type": "exec",
                "payload": "whoami"
            }
            
            url = f"{self.base_url}/api/command"
            async with self.session.post(url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                passed = resp.status in (200, 201)
                response_data = await resp.json() if resp.status < 400 else {}
                
                self._record_test(
                    "Command Submission",
                    passed,
                    f"Status {resp.status}",
                    response_data
                )
                return passed
        except Exception as e:
            self._record_test("Command Submission", False, str(e))
            return False
    
    async def test_batch_command(self):
        """Test batch command execution"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            db = OperationalDatabase(OPERATIONAL_DB_PATH)
            
            # Get or create agents
            agents = db.list_agents()
            agent_ids = [a.agent_id for a in agents[:2]]
            
            if len(agent_ids) < 2:
                for i in range(2 - len(agent_ids)):
                    agent_id = f"test_agent_batch_{i}"
                    agent = AgentRecord(
                        agent_id=agent_id,
                        ip_address="127.0.0.1",
                        status="active",
                        connected_at=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc),
                        certificate_fingerprint="test_fingerprint",
                        certificate_subject="CN=test_agent",
                    )
                    db.register_agent(agent)
                    agent_ids.append(agent_id)
            
            payload = {
                "agents": agent_ids,
                "command_type": "exec",
                "payload": "hostname"
            }
            
            url = f"{self.base_url}/api/command/batch"
            async with self.session.post(url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                passed = resp.status in (200, 201)
                response_data = await resp.json() if resp.status < 400 else {}
                
                self._record_test(
                    "Batch Command Execution",
                    passed,
                    f"Status {resp.status}, {len(agent_ids)} agents",
                    response_data
                )
                return passed
        except Exception as e:
            self._record_test("Batch Command Execution", False, str(e))
            return False
    
    async def test_audit_logging(self):
        """Test audit logging"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            url = f"{self.base_url}/api/audit/logs"
            
            async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    logs = data.get("logs", [])
                    
                    # Check if audit logs contain security events
                    has_command_logs = any("dashboard_command" in str(log) for log in logs)
                    
                    self._record_test(
                        "Audit Logging",
                        len(logs) > 0,
                        f"Found {len(logs)} audit logs",
                        {"has_command_logs": has_command_logs}
                    )
                    return True
        except Exception as e:
            self._record_test("Audit Logging", False, str(e))
            return False
    
    async def test_pki_validation(self):
        """Test PKI certificate validation"""
        try:
            pki_path = Path(PKI_PATH)
            
            # Check operator certificate exists
            operator_cert_path = pki_path / "operators" / "admin.crt"
            ca_cert_path = pki_path / "ca" / "ca_root.crt"
            
            has_operator_cert = operator_cert_path.exists()
            has_ca_cert = ca_cert_path.exists()
            
            if has_operator_cert and has_ca_cert:
                # Load and validate operator certificate
                with open(operator_cert_path, "rb") as f:
                    operator_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                
                with open(ca_cert_path, "rb") as f:
                    ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                
                # Check certificate properties
                now = datetime.now(timezone.utc)
                is_valid = operator_cert.not_valid_before.replace(tzinfo=timezone.utc) <= now <= operator_cert.not_valid_after.replace(tzinfo=timezone.utc)
                issuer_matches = operator_cert.issuer == ca_cert.subject
                
                # Extract CN
                cn_attrs = operator_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                has_cn = len(cn_attrs) > 0
                
                passed = is_valid and issuer_matches and has_cn
                
                self._record_test(
                    "PKI Validation",
                    passed,
                    f"Valid: {is_valid}, Issuer OK: {issuer_matches}, CN: {has_cn}",
                    {
                        "operator_cn": cn_attrs[0].value if has_cn else None,
                        "valid_from": operator_cert.not_valid_before.replace(tzinfo=timezone.utc).isoformat(),
                        "valid_until": operator_cert.not_valid_after.replace(tzinfo=timezone.utc).isoformat(),
                    }
                )
                return passed
            else:
                self._record_test("PKI Validation", False, "Missing certificate files")
                return False
        except Exception as e:
            self._record_test("PKI Validation", False, str(e))
            return False
    
    async def test_payload_builder_endpoints(self):
        """Test payload builder API endpoints"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            
            # Check if templates endpoint exists
            url = f"{self.base_url}/api/payload/templates"
            async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                has_templates = resp.status == 200
                templates_data = await resp.json() if resp.status == 200 else {}
                
                self._record_test(
                    "Payload Templates API",
                    has_templates,
                    f"Status {resp.status}",
                    templates_data
                )
            
            # Check payload build endpoint
            url = f"{self.base_url}/api/payload/build"
            build_payload = {
                "commands": [
                    {"type": "exec", "payload": "whoami"}
                ]
            }
            async with self.session.post(url, json=build_payload, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                has_build = resp.status in (200, 201, 400)  # Accept 400 if validation needed
                self._record_test(
                    "Payload Build API",
                    has_build,
                    f"Status {resp.status}"
                )
            
            return has_templates or has_build
        except Exception as e:
            logger.warning(f"Payload builder endpoints test: {e}")
            self._record_test("Payload Builder APIs", False, str(e))
            return False
    
    async def test_file_manager_endpoints(self):
        """Test file manager API endpoints"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            
            # Check files list endpoint
            url = f"{self.base_url}/api/files/list"
            async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                has_files_list = resp.status in (200, 404)  # 404 if no agent selected
                
                self._record_test(
                    "File Manager List API",
                    has_files_list,
                    f"Status {resp.status}"
                )
            
            return has_files_list
        except Exception as e:
            logger.warning(f"File manager endpoints test: {e}")
            self._record_test("File Manager APIs", False, str(e))
            return False
    
    async def test_certificate_viewer_endpoints(self):
        """Test certificate viewer API endpoints"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            
            # Check certificates list endpoint
            url = f"{self.base_url}/api/certificates/list"
            async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                has_certs = resp.status == 200
                certs_data = await resp.json() if resp.status == 200 else {}
                
                self._record_test(
                    "Certificate Viewer API",
                    has_certs,
                    f"Status {resp.status}",
                    {"certificate_count": len(certs_data.get("certificates", []))}
                )
            
            return has_certs
        except Exception as e:
            logger.warning(f"Certificate viewer endpoints test: {e}")
            self._record_test("Certificate Viewer APIs", False, str(e))
            return False
    
    async def test_websocket_connection(self):
        """Test WebSocket connection"""
        try:
            ws_url = self.base_url.replace("http://", "ws://") + "/ws"
            
            try:
                async with self.session.ws_connect(ws_url, timeout=aiohttp.ClientTimeout(total=5)) as ws:
                    # Send ping
                    await ws.send_json({"type": "ping"})
                    
                    # Receive pong
                    msg = await ws.receive(timeout=2)
                    
                    self._record_test(
                        "WebSocket Connection",
                        True,
                        "Connected and received message"
                    )
                    return True
            except asyncio.TimeoutError:
                self._record_test("WebSocket Connection", False, "Timeout")
                return False
        except Exception as e:
            logger.warning(f"WebSocket test: {e}")
            self._record_test("WebSocket Connection", False, str(e))
            return False
    
    async def test_features_alignment(self):
        """Check frontend/backend feature alignment"""
        features_to_check = {
            "payload_builder": False,
            "file_manager": False,
            "certificate_viewer": False,
            "batch_commands": False,
            "command_templates": False,
            "audit_logging": False,
            "pki_validation": False,
            "websocket_updates": False,
        }
        
        # Test each feature
        payload_builder_ok = await self.test_payload_builder_endpoints()
        file_manager_ok = await self.test_file_manager_endpoints()
        cert_viewer_ok = await self.test_certificate_viewer_endpoints()
        batch_ok = await self.test_batch_command()
        pki_ok = await self.test_pki_validation()
        audit_ok = await self.test_audit_logging()
        ws_ok = await self.test_websocket_connection()
        
        features_to_check = {
            "payload_builder": payload_builder_ok,
            "file_manager": file_manager_ok,
            "certificate_viewer": cert_viewer_ok,
            "batch_commands": batch_ok,
            "pki_validation": pki_ok,
            "audit_logging": audit_ok,
            "websocket_updates": ws_ok,
        }
        
        self.results["features"] = features_to_check
        
        return all(features_to_check.values())
    
    async def run_all_tests(self):
        """Run all tests"""
        await self.setup()
        
        logger.info("\n" + "="*80)
        logger.info("🧪 RUNNING COMPREHENSIVE AUTODRIVE TEST SUITE")
        logger.info("="*80 + "\n")
        
        try:
            # Basic UI tests
            await self.test_dashboard_home()
            
            # API endpoint tests
            await self.test_api_endpoints()
            
            # Feature tests
            await self.test_command_submission()
            await self.test_batch_command()
            await self.test_audit_logging()
            await self.test_pki_validation()
            
            # Advanced feature tests
            await self.test_payload_builder_endpoints()
            await self.test_file_manager_endpoints()
            await self.test_certificate_viewer_endpoints()
            await self.test_websocket_connection()
            
            # Alignment check
            await self.test_features_alignment()
            
        finally:
            await self.cleanup()
        
        return self.results
    
    async def cleanup(self):
        """Cleanup test environment"""
        logger.info("\n🧹 Cleaning up...")
        
        if self.session:
            await self.session.close()
        
        if self.server_process:
            self.server_process.terminate()
            try:
                self.server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.server_process.kill()
            logger.info("✅ Server stopped")
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "="*80)
        print("📊 TEST SUMMARY")
        print("="*80)
        print(f"Total Tests: {self.results['total']}")
        print(f"✅ Passed: {self.results['passed']}")
        print(f"❌ Failed: {self.results['failed']}")
        print(f"Success Rate: {(self.results['passed'] / max(self.results['total'], 1) * 100):.1f}%")
        
        print("\n📋 FEATURE ALIGNMENT:")
        for feature, status in self.results['features'].items():
            symbol = "✅" if status else "❌"
            print(f"  {symbol} {feature}")
        
        print("\n" + "="*80)
        
        # Write results to JSON
        results_file = Path(__file__).parent / "autodrive_results.json"
        with open(results_file, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"\n💾 Results saved to: {results_file}")
    
    def get_summary(self) -> Dict[str, Any]:
        """Get test summary as dict"""
        return {
            "total": self.results["total"],
            "passed": self.results["passed"],
            "failed": self.results["failed"],
            "success_rate": self.results["passed"] / max(self.results["total"], 1),
            "features": self.results["features"],
            "timestamp": self.results["timestamp"]
        }


async def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="SecureComm Autodrive Test Suite")
    parser.add_argument("--host", default="127.0.0.1", help="Dashboard host")
    parser.add_argument("--port", type=int, default=8080, help="Dashboard port")
    parser.add_argument("--skip-server-start", action="store_true", help="Skip server startup (test external instance)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    runner = AutodriveTestRunner(
        host=args.host,
        port=args.port,
        skip_server_start=args.skip_server_start
    )
    
    results = await runner.run_all_tests()
    runner.print_summary()
    
    # Exit with appropriate code
    sys.exit(0 if results["failed"] == 0 else 1)


if __name__ == "__main__":
    asyncio.run(main())
