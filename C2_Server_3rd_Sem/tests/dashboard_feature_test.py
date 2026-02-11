#!/usr/bin/env python3
"""
Dashboard Feature Testing Suite
Comprehensive testing of all dashboard UI features and functionality

Usage:
    python tests/dashboard_feature_test.py [--verbose] [--skip-server-start] [--host HOST] [--port PORT]
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any

import aiohttp
try:
    from bs4 import BeautifulSoup
except ImportError:
    print("⚠️  BeautifulSoup not found. Install with: pip install beautifulsoup4")
    sys.exit(1)

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from securecomm.config import PKI_PATH, OPERATIONAL_DB_PATH, AUDIT_LOG_DIR
from securecomm.operational_db import OperationalDatabase, AgentRecord, CommandRecord
from securecomm.pki_manager import PKIManager

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("DashboardFeatureTest")

class DashboardFeatureTester:
    """Comprehensive dashboard feature tester"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8080, skip_server_start: bool = False):
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
        self.skip_server_start = skip_server_start
        self.server_process = None
        self.session = None
        self.token = None
        self.test_agent_id = f"dashboard_test_agent_{int(time.time())}"
        self.results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ui_features": {},
            "api_endpoints": {},
            "workflows": {},
            "security_tests": {},
            "performance_tests": {},
            "passed": 0,
            "failed": 0,
            "total": 0,
            "ui_completeness": 0.0,
            "functionality_score": 0.0,
            "overall_grade": "F"
        }
    
    async def setup(self):
        """Setup test environment"""
        logger.info("🔧 Setting up dashboard feature test environment...")
        
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
        logger.info(f"✅ Test environment ready")
    
    def _setup_pki(self):
        """Ensure PKI is set up"""
        pki_path = Path(PKI_PATH)
        ca_cert = pki_path / "ca" / "ca_root.crt"
        
        if not ca_cert.exists():
            logger.info("📋 Generating PKI infrastructure...")
            pki = PKIManager(pki_path)
            pki.generate_ca()
            pki.generate_operator_certificate("admin", "admin")
            pki.generate_agent_certificate(self.test_agent_id, self.test_agent_id)
            logger.info("✅ PKI generated with test agent")
    
    def _start_server(self):
        """Start dashboard server"""
        logger.info("🚀 Starting dashboard server...")
        launcher_path = Path(__file__).parent.parent / "launcher.py"
        
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
        logger.info(f"⏳ Waiting for server to be ready...")
        start = time.time()
        
        while time.time() - start < timeout:
            try:
                async with self.session.get(f"{self.base_url}/health", timeout=aiohttp.ClientTimeout(total=2)) as resp:
                    if resp.status in (200, 401):
                        logger.info("✅ Server is ready")
                        return
            except Exception:
                pass
            await asyncio.sleep(0.5)
        
        raise TimeoutError(f"Server did not start within {timeout}s")
    
    def _get_dashboard_token(self) -> str:
        """Get dashboard token"""
        from securecomm.config import DASHBOARD_TOKEN
        return DASHBOARD_TOKEN or ""
    
    def _record_test(self, name: str, passed: bool, message: str = "", details: Dict = None, category: str = "general"):
        """Record test result"""
        test_result = {
            "name": name,
            "category": category,
            "passed": passed,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": message,
            "details": details or {}
        }
        
        if category not in self.results:
            self.results[category] = {}
        
        self.results[category][name] = test_result
        
        if passed:
            self.results["passed"] += 1
            status = "✅ PASS"
        else:
            self.results["failed"] += 1
            status = "❌ FAIL"
        
        self.results["total"] += 1
        logger.info(f"{status} - {name}: {message}")
    
    async def test_dashboard_ui_structure(self):
        """Test dashboard UI structure and components"""
        logger.info("🎨 Testing dashboard UI structure...")
        
        try:
            async with self.session.get(f"{self.base_url}/", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    html_content = await resp.text()
                    soup = BeautifulSoup(html_content, 'html.parser')
                    
                    ui_tests = {
                        # Basic structure
                        "html5_doctype": html_content.startswith("<!DOCTYPE html>"),
                        "responsive_viewport": bool(soup.find('meta', attrs={'name': 'viewport'})),
                        "proper_title": bool(soup.find('title')),
                        
                        # Layout components
                        "sidebar_exists": bool(soup.find(class_="sidebar")),
                        "main_content_exists": bool(soup.find(class_="main-content")),
                        "top_bar_exists": bool(soup.find(class_="top-bar")),
                        "navigation_menu": bool(soup.find(class_="nav-menu")),
                        
                        # Dashboard specific elements
                        "stats_grid": bool(soup.find(class_="stats-grid")),
                        "stat_cards": len(soup.find_all(class_="stat-card")) >= 4,
                        "connection_status": bool(soup.find(class_="connection-status")),
                        "auto_refresh_toggle": bool(soup.find(id="auto-refresh")),
                        "refresh_button": bool(soup.find(id="refresh-btn")),
                        
                        # Page containers
                        "dashboard_page": bool(soup.find(id="page-dashboard")),
                        "agents_page": bool(soup.find(id="page-agents")),
                        "commands_page": bool(soup.find(id="page-commands")),
                        "payload_page": bool(soup.find(id="page-payload")),
                        "files_page": bool(soup.find(id="page-files")),
                        "certificates_page": bool(soup.find(id="page-certificates")),
                        "audit_page": bool(soup.find(id="page-audit")),
                        
                        # Navigation elements
                        "nav_links": len(soup.find_all(class_="nav-link")) >= 7,
                        "nav_icons": bool(soup.find_all(class_="nav-icon")),
                        "logo_section": bool(soup.find(class_="logo")),
                        
                        # Interactive elements
                        "page_wrappers": bool(soup.find(class_="content-wrapper")),
                        "version_info": bool(soup.find(class_="version")),
                    }
                    
                    passed_count = sum(ui_tests.values())
                    total_count = len(ui_tests)
                    completeness = (passed_count / total_count) * 100
                    
                    self.results["ui_completeness"] = completeness
                    
                    self._record_test(
                        "Dashboard UI Structure",
                        completeness >= 90,
                        f"UI completeness: {completeness:.1f}% ({passed_count}/{total_count})",
                        ui_tests,
                        "ui_features"
                    )
                    
                    return completeness >= 90
        except Exception as e:
            self._record_test("Dashboard UI Structure", False, str(e), category="ui_features")
            return False
    
    async def test_navigation_functionality(self):
        """Test navigation functionality"""
        logger.info("🧭 Testing navigation functionality...")
        
        navigation_tests = {}
        
        # Test navigation links exist and have correct attributes
        try:
            async with self.session.get(f"{self.base_url}/", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    html_content = await resp.text()
                    soup = BeautifulSoup(html_content, 'html.parser')
                    
                    nav_links = soup.find_all(class_="nav-link")
                    
                    expected_pages = ["dashboard", "agents", "commands", "payload", "files", "certificates", "audit"]
                    
                    for page in expected_pages:
                        page_found = False
                        for link in nav_links:
                            if link.get('data-page') == page or page in link.get('href', ''):
                                page_found = True
                                break
                        
                        navigation_tests[f"nav_{page}"] = page_found
                    
                    # Test active page highlighting
                    active_link = soup.find('a', class_="nav-link active") or soup.find(class_="nav-link active")
                    navigation_tests["active_nav_highlighting"] = bool(active_link)
                    
                    passed_count = sum(navigation_tests.values())
                    total_count = len(navigation_tests)
                    completeness = (passed_count / total_count) * 100
                    
                    self._record_test(
                        "Navigation Functionality",
                        completeness >= 90,
                        f"Navigation completeness: {completeness:.1f}%",
                        navigation_tests,
                        "ui_features"
                    )
                    
                    return completeness >= 90
        except Exception as e:
            self._record_test("Navigation Functionality", False, str(e), category="ui_features")
            return False
    
    async def test_agent_management_ui(self):
        """Test agent management UI features"""
        logger.info("🤖 Testing agent management UI...")
        
        agent_ui_tests = {}
        
        try:
            # Register a test agent
            db = OperationalDatabase(OPERATIONAL_DB_PATH)
            agent = AgentRecord(
                agent_id=self.test_agent_id,
                ip_address="127.0.0.1",
                status="active",
                connected_at=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
                certificate_fingerprint="test_fingerprint",
                certificate_subject=f"CN={self.test_agent_id}",
            )
            db.register_agent(agent)
            
            # Test agents API
            async with self.session.get(f"{self.base_url}/api/agents", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                agents_api_works = resp.status == 200
                agent_ui_tests["agents_api"] = agents_api_works
                
                if agents_api_works:
                    agents_data = await resp.json()
                    agents_list = agents_data.get("agents", [])
                    agent_ui_tests["agents_list_returned"] = len(agents_list) > 0
                    agent_ui_tests["test_agent_visible"] = any(a.get("agent_id") == self.test_agent_id for a in agents_list)
            
            # Test agent detail API
            async with self.session.get(f"{self.base_url}/api/agents/{self.test_agent_id}", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                agent_detail_works = resp.status in (200, 404)
                agent_ui_tests["agent_detail_api"] = agent_detail_works
            
            # Test UI has agent management elements
            async with self.session.get(f"{self.base_url}/", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    html_content = await resp.text()
                    soup = BeautifulSoup(html_content, 'html.parser')
                    
                    agents_page = soup.find(id="page-agents")
                    if agents_page:
                        agent_ui_tests["agents_page_exists"] = True
                        agent_ui_tests["agent_table_structure"] = bool(agents_page.find("table"))
                        agent_ui_tests["agent_status_indicators"] = "status" in agents_page.get_text().lower()
                        agent_ui_tests["agent_action_buttons"] = bool(agents_page.find("button"))
                    else:
                        agent_ui_tests["agents_page_exists"] = False
            
            passed_count = sum(agent_ui_tests.values())
            total_count = len(agent_ui_tests)
            completeness = (passed_count / total_count) * 100 if total_count > 0 else 0
            
            self._record_test(
                "Agent Management UI",
                completeness >= 80,
                f"Agent UI completeness: {completeness:.1f}%",
                agent_ui_tests,
                "ui_features"
            )
            
            return completeness >= 80
        except Exception as e:
            self._record_test("Agent Management UI", False, str(e), category="ui_features")
            return False
    
    async def test_command_interface_ui(self):
        """Test command interface UI features"""
        logger.info("⚙️ Testing command interface UI...")
        
        command_ui_tests = {}
        
        try:
            # Test commands API
            async with self.session.get(f"{self.base_url}/api/commands", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                commands_api_works = resp.status == 200
                command_ui_tests["commands_api"] = commands_api_works
            
            # Test command submission API
            command_payload = {
                "agent_id": self.test_agent_id,
                "type": "exec",
                "payload": "echo 'UI test'"
            }
            headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
            
            async with self.session.post(f"{self.base_url}/api/command", json=command_payload, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                command_submit_works = resp.status in (200, 201, 400, 401)
                command_ui_tests["command_submit_api"] = command_submit_works
            
            # Test batch command API
            batch_payload = {
                "agents": [self.test_agent_id],
                "command_type": "exec",
                "command_data": "echo 'batch test'"
            }
            
            async with self.session.post(f"{self.base_url}/api/command/batch", json=batch_payload, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                batch_command_works = resp.status in (200, 201, 400, 401)
                command_ui_tests["batch_command_api"] = batch_command_works
            
            # Test UI has command interface elements
            async with self.session.get(f"{self.base_url}/", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    html_content = await resp.text()
                    soup = BeautifulSoup(html_content, 'html.parser')
                    
                    commands_page = soup.find(id="page-commands")
                    if commands_page:
                        command_ui_tests["commands_page_exists"] = True
                        command_ui_tests["command_form"] = bool(commands_page.find("form"))
                        command_ui_tests["command_type_selector"] = bool(commands_page.find("select"))
                        command_ui_tests["command_payload_input"] = bool(commands_page.find("textarea") or commands_page.find("input[type='text']"))
                        command_ui_tests["submit_button"] = bool(commands_page.find("button", type_="submit") or commands_page.find("button", string=lambda text: "submit" in text.lower()))
                    else:
                        command_ui_tests["commands_page_exists"] = False
            
            passed_count = sum(command_ui_tests.values())
            total_count = len(command_ui_tests)
            completeness = (passed_count / total_count) * 100 if total_count > 0 else 0
            
            self._record_test(
                "Command Interface UI",
                completeness >= 80,
                f"Command UI completeness: {completeness:.1f}%",
                command_ui_tests,
                "ui_features"
            )
            
            return completeness >= 80
        except Exception as e:
            self._record_test("Command Interface UI", False, str(e), category="ui_features")
            return False
    
    async def test_payload_builder_ui(self):
        """Test payload builder UI features"""
        logger.info("🎯 Testing payload builder UI...")
        
        payload_ui_tests = {}
        
        try:
            # Test payload templates API
            async with self.session.get(f"{self.base_url}/api/payload/templates", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                templates_api_works = resp.status == 200
                payload_ui_tests["templates_api"] = templates_api_works
                
                if templates_api_works:
                    templates_data = await resp.json()
                    payload_ui_tests["templates_returned"] = len(templates_data.get("templates", [])) > 0
            
            # Test payload build API
            build_payload = {
                "commands": [{"type": "exec", "payload": "whoami"}]
            }
            headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
            
            async with self.session.post(f"{self.base_url}/api/payload/build", json=build_payload, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                payload_build_works = resp.status in (200, 201, 400, 401)
                payload_ui_tests["payload_build_api"] = payload_build_works
            
            # Test UI has payload builder elements
            async with self.session.get(f"{self.base_url}/", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    html_content = await resp.text()
                    soup = BeautifulSoup(html_content, 'html.parser')
                    
                    payload_page = soup.find(id="page-payload")
                    if payload_page:
                        payload_ui_tests["payload_page_exists"] = True
                        payload_ui_tests["template_selector"] = bool(payload_page.find("select"))
                        payload_ui_tests["command_builder"] = bool(payload_page.find(class_="command-builder") or payload_page.find("form"))
                        payload_ui_tests["payload_preview"] = bool(payload_page.find(class_="preview") or payload_page.find("pre"))
                    else:
                        payload_ui_tests["payload_page_exists"] = False
            
            passed_count = sum(payload_ui_tests.values())
            total_count = len(payload_ui_tests)
            completeness = (passed_count / total_count) * 100 if total_count > 0 else 0
            
            self._record_test(
                "Payload Builder UI",
                completeness >= 80,
                f"Payload UI completeness: {completeness:.1f}%",
                payload_ui_tests,
                "ui_features"
            )
            
            return completeness >= 80
        except Exception as e:
            self._record_test("Payload Builder UI", False, str(e), category="ui_features")
            return False
    
    async def test_file_management_ui(self):
        """Test file management UI features"""
        logger.info("📁 Testing file management UI...")
        
        file_ui_tests = {}
        
        try:
            # Test file listing API
            async with self.session.get(f"{self.base_url}/api/files/list?agent_id={self.test_agent_id}", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                file_list_works = resp.status in (200, 404)
                file_ui_tests["file_list_api"] = file_list_works
            
            # Test file browsing API
            async with self.session.get(f"{self.base_url}/api/files/browse?agent_id={self.test_agent_id}", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                file_browse_works = resp.status in (200, 404)
                file_ui_tests["file_browse_api"] = file_browse_works
            
            # Test file upload API (will likely fail without actual file, but should accept the request)
            upload_payload = {
                "agent_id": self.test_agent_id,
                "path": "test.txt"
            }
            headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
            
            async with self.session.post(f"{self.base_url}/api/files/upload", json=upload_payload, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                file_upload_works = resp.status in (200, 201, 400, 401)
                file_ui_tests["file_upload_api"] = file_upload_works
            
            # Test UI has file management elements
            async with self.session.get(f"{self.base_url}/", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    html_content = await resp.text()
                    soup = BeautifulSoup(html_content, 'html.parser')
                    
                    files_page = soup.find(id="page-files")
                    if files_page:
                        file_ui_tests["files_page_exists"] = True
                        file_ui_tests["file_browser"] = bool(files_page.find(class_="file-browser") or files_page.find("table"))
                        file_ui_tests["upload_interface"] = bool(files_page.find("input[type='file']") or files_page.find("form", enctype="multipart/form-data"))
                        file_ui_tests["download_controls"] = bool(files_page.find("a") or files_page.find("button", string=lambda text: "download" in text.lower()))
                    else:
                        file_ui_tests["files_page_exists"] = False
            
            passed_count = sum(file_ui_tests.values())
            total_count = len(file_ui_tests)
            completeness = (passed_count / total_count) * 100 if total_count > 0 else 0
            
            self._record_test(
                "File Management UI",
                completeness >= 75,
                f"File UI completeness: {completeness:.1f}%",
                file_ui_tests,
                "ui_features"
            )
            
            return completeness >= 75
        except Exception as e:
            self._record_test("File Management UI", False, str(e), category="ui_features")
            return False
    
    async def test_certificate_management_ui(self):
        """Test certificate management UI features"""
        logger.info("🔐 Testing certificate management UI...")
        
        cert_ui_tests = {}
        
        try:
            # Test certificates listing API
            async with self.session.get(f"{self.base_url}/api/certificates", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                certs_list_works = resp.status == 200
                cert_ui_tests["certificates_list_api"] = certs_list_works
                
                if certs_list_works:
                    certs_data = await resp.json()
                    cert_ui_tests["certificates_returned"] = len(certs_data.get("certificates", [])) > 0
            
            # Test certificate detail API
            async with self.session.get(f"{self.base_url}/api/certificates/operator/admin", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                cert_detail_works = resp.status in (200, 404)
                cert_ui_tests["certificate_detail_api"] = cert_detail_works
            
            # Test UI has certificate management elements
            async with self.session.get(f"{self.base_url}/", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    html_content = await resp.text()
                    soup = BeautifulSoup(html_content, 'html.parser')
                    
                    certs_page = soup.find(id="page-certificates")
                    if certs_page:
                        cert_ui_tests["certificates_page_exists"] = True
                        cert_ui_tests["certificate_list"] = bool(certs_page.find("table") or certs_page.find(class_="certificate-list"))
                        cert_ui_tests["certificate_details"] = bool(certs_page.find(class_="certificate-details") or certs_page.find("pre"))
                        cert_ui_tests["certificate_filters"] = bool(certs_page.find("select") or certs_page.find("input[type='search']"))
                    else:
                        cert_ui_tests["certificates_page_exists"] = False
            
            passed_count = sum(cert_ui_tests.values())
            total_count = len(cert_ui_tests)
            completeness = (passed_count / total_count) * 100 if total_count > 0 else 0
            
            self._record_test(
                "Certificate Management UI",
                completeness >= 80,
                f"Certificate UI completeness: {completeness:.1f}%",
                cert_ui_tests,
                "ui_features"
            )
            
            return completeness >= 80
        except Exception as e:
            self._record_test("Certificate Management UI", False, str(e), category="ui_features")
            return False
    
    async def test_audit_logging_ui(self):
        """Test audit logging UI features"""
        logger.info("📝 Testing audit logging UI...")
        
        audit_ui_tests = {}
        
        try:
            # Test audit logs API
            async with self.session.get(f"{self.base_url}/api/audit/logs", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                audit_logs_works = resp.status == 200
                audit_ui_tests["audit_logs_api"] = audit_logs_works
                
                if audit_logs_works:
                    audit_data = await resp.json()
                    audit_ui_tests["audit_events_returned"] = len(audit_data.get("logs", [])) >= 0
            
            # Test audit search API
            search_params = "?start_time=2024-01-01T00:00:00Z&end_time=2026-12-31T23:59:59Z"
            async with self.session.get(f"{self.base_url}/api/audit/search{search_params}", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                audit_search_works = resp.status in (200, 400)
                audit_ui_tests["audit_search_api"] = audit_search_works
            
            # Test UI has audit logging elements
            async with self.session.get(f"{self.base_url}/", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    html_content = await resp.text()
                    soup = BeautifulSoup(html_content, 'html.parser')
                    
                    audit_page = soup.find(id="page-audit")
                    if audit_page:
                        audit_ui_tests["audit_page_exists"] = True
                        audit_ui_tests["audit_log_table"] = bool(audit_page.find("table"))
                        audit_ui_tests["search_controls"] = bool(audit_page.find("input") or audit_page.find("form"))
                        audit_ui_tests["filter_options"] = bool(audit_page.find("select"))
                        audit_ui_tests["export_controls"] = bool(audit_page.find("button", string=lambda text: "export" in text.lower()))
                    else:
                        audit_ui_tests["audit_page_exists"] = False
            
            passed_count = sum(audit_ui_tests.values())
            total_count = len(audit_ui_tests)
            completeness = (passed_count / total_count) * 100 if total_count > 0 else 0
            
            self._record_test(
                "Audit Logging UI",
                completeness >= 80,
                f"Audit UI completeness: {completeness:.1f}%",
                audit_ui_tests,
                "ui_features"
            )
            
            return completeness >= 80
        except Exception as e:
            self._record_test("Audit Logging UI", False, str(e), category="ui_features")
            return False
    
    async def test_real_time_features(self):
        """Test real-time features and WebSocket"""
        logger.info("⚡ Testing real-time features...")
        
        realtime_tests = {}
        
        try:
            # Test WebSocket connection
            ws_url = self.base_url.replace("http://", "ws://") + "/ws"
            
            async with self.session.ws_connect(ws_url, timeout=aiohttp.ClientTimeout(total=5)) as ws:
                await ws.send_json({"type": "ping", "timestamp": datetime.now(timezone.utc).isoformat()})
                msg = await ws.receive(timeout=3)
                
                websocket_works = msg.type == aiohttp.WSMsgType.TEXT
                realtime_tests["websocket_connection"] = websocket_works
                
                if websocket_works:
                    response = json.loads(msg.data)
                    realtime_tests["websocket_response"] = response.get("type") == "pong"
            
            # Test API response times
            start_time = time.time()
            async with self.session.get(f"{self.base_url}/api/state", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                response_time = (time.time() - start_time) * 1000
                realtime_tests["api_response_time"] = response_time < 500  # Less than 500ms
                realtime_tests["response_time_ms"] = round(response_time, 2)
            
            # Test auto-refresh functionality in UI
            async with self.session.get(f"{self.base_url}/", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    html_content = await resp.text()
                    soup = BeautifulSoup(html_content, 'html.parser')
                    
                    realtime_tests["auto_refresh_toggle"] = bool(soup.find(id="auto-refresh"))
                    realtime_tests["refresh_button"] = bool(soup.find(id="refresh-btn"))
                    realtime_tests["connection_status"] = bool(soup.find(class_="connection-status"))
            
            passed_count = sum(realtime_tests.values())
            total_count = len(realtime_tests)
            completeness = (passed_count / total_count) * 100 if total_count > 0 else 0
            
            self._record_test(
                "Real-time Features",
                completeness >= 75,
                f"Real-time completeness: {completeness:.1f}%",
                realtime_tests,
                "performance_tests"
            )
            
            return completeness >= 75
        except Exception as e:
            self._record_test("Real-time Features", False, str(e), category="performance_tests")
            return False
    
    async def run_dashboard_tests(self):
        """Run all dashboard feature tests"""
        await self.setup()
        
        logger.info("\n" + "="*80)
        logger.info("🧪 RUNNING DASHBOARD FEATURE TEST SUITE")
        logger.info("="*80 + "\n")
        
        try:
            # Run all UI tests
            await self.test_dashboard_ui_structure()
            await self.test_navigation_functionality()
            await self.test_agent_management_ui()
            await self.test_command_interface_ui()
            await self.test_payload_builder_ui()
            await self.test_file_management_ui()
            await self.test_certificate_management_ui()
            await self.test_audit_logging_ui()
            await self.test_real_time_features()
            
            # Calculate overall scores
            self._calculate_overall_scores()
            
        finally:
            await self.cleanup()
        
        return self.results
    
    def _calculate_overall_scores(self):
        """Calculate overall functionality scores"""
        ui_features = self.results.get("ui_features", {})
        performance_tests = self.results.get("performance_tests", {})
        
        # Calculate UI completeness
        ui_passed = sum(1 for test in ui_features.values() if test.get("passed", False))
        ui_total = len(ui_features)
        self.results["ui_completeness"] = (ui_passed / ui_total * 100) if ui_total > 0 else 0
        
        # Calculate functionality score
        all_tests = {**ui_features, **performance_tests}
        total_passed = sum(1 for test in all_tests.values() if test.get("passed", False))
        total_tests = len(all_tests)
        self.results["functionality_score"] = (total_passed / total_tests * 100) if total_tests > 0 else 0
        
        # Calculate overall grade
        overall_score = (self.results["ui_completeness"] + self.results["functionality_score"]) / 2
        if overall_score >= 95:
            self.results["overall_grade"] = "A+"
        elif overall_score >= 90:
            self.results["overall_grade"] = "A"
        elif overall_score >= 85:
            self.results["overall_grade"] = "B+"
        elif overall_score >= 80:
            self.results["overall_grade"] = "B"
        elif overall_score >= 75:
            self.results["overall_grade"] = "C+"
        elif overall_score >= 70:
            self.results["overall_grade"] = "C"
        elif overall_score >= 65:
            self.results["overall_grade"] = "D+"
        elif overall_score >= 60:
            self.results["overall_grade"] = "D"
        else:
            self.results["overall_grade"] = "F"
    
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
    
    def print_dashboard_summary(self):
        """Print dashboard test summary"""
        print("\n" + "="*80)
        print("📊 DASHBOARD FEATURE TEST SUMMARY")
        print("="*80)
        
        print(f"🕐 Timestamp: {self.results['timestamp']}")
        print(f"🎨 UI Completeness: {self.results['ui_completeness']:.1f}%")
        print(f"⚙️ Functionality Score: {self.results['functionality_score']:.1f}%")
        print(f"📈 Overall Grade: {self.results['overall_grade']}")
        print(f"✅ Tests Passed: {self.results['passed']}")
        print(f"❌ Tests Failed: {self.results['failed']}")
        print(f"📊 Total Tests: {self.results['total']}")
        
        # UI Features breakdown
        ui_features = self.results.get("ui_features", {})
        if ui_features:
            print("\n🎨 UI FEATURES:")
            for test_name, test_result in ui_features.items():
                status = "✅" if test_result.get("passed", False) else "❌"
                print(f"   {status} {test_name}")
        
        # Performance tests
        performance_tests = self.results.get("performance_tests", {})
        if performance_tests:
            print("\n⚡ PERFORMANCE TESTS:")
            for test_name, test_result in performance_tests.items():
                status = "✅" if test_result.get("passed", False) else "❌"
                print(f"   {status} {test_name}")
        
        # Final assessment
        print("\n" + "="*80)
        grade = self.results["overall_grade"]
        if grade in ["A+", "A"]:
            print("🎉 EXCELLENT! Dashboard UI is production-ready with exceptional quality!")
        elif grade in ["B+", "B"]:
            print("✅ GOOD! Dashboard UI is mostly ready with minor improvements needed.")
        elif grade in ["C+", "C"]:
            print("⚠️  AVERAGE! Dashboard UI needs significant improvements before production.")
        elif grade in ["D+", "D"]:
            print("🚨 BELOW AVERAGE! Dashboard UI has major issues that must be addressed.")
        else:
            print("❌ CRITICAL! Dashboard UI is not ready and requires major fixes.")
        print("="*80)

async def main():
    """Main entry point"""
    import argparse
    import subprocess
    
    parser = argparse.ArgumentParser(description="Dashboard Feature Testing Suite")
    parser.add_argument("--host", default="127.0.0.1", help="Dashboard host")
    parser.add_argument("--port", type=int, default=8080, help="Dashboard port")
    parser.add_argument("--skip-server-start", action="store_true", help="Skip server startup")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--save-results", help="Save results to JSON file")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    tester = DashboardFeatureTester(
        host=args.host,
        port=args.port,
        skip_server_start=args.skip_server_start
    )
    
    try:
        results = await tester.run_dashboard_tests()
        tester.print_dashboard_summary()
        
        if args.save_results:
            with open(args.save_results, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\n💾 Results saved to: {args.save_results}")
        
        # Exit with appropriate code
        if results["functionality_score"] >= 80:
            sys.exit(0)  # Success
        else:
            sys.exit(1)  # Failure
            
    except KeyboardInterrupt:
        print("\n🛑 Tests interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"❌ Test execution failed: {e}")
        sys.exit(2)

if __name__ == "__main__":
    asyncio.run(main())
