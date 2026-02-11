#!/usr/bin/env python3
"""
Dashboard Payload Builder Test
Tests the full payload builder workflow:
  - Template listing and detail retrieval
  - Payload encryption and build via the API
  - Windows payload template integration
  - Dashboard HTML elements for payload builder

Usage:
    pytest tests/test_dashboard_payload.py -v
"""

import asyncio
import json
import sys
import os
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from aiohttp.test_utils import TestClient, TestServer
from securecomm.dashboard_server import create_app, PAYLOAD_TEMPLATES, PAYLOADS_DIR


# ==================== TEMPLATE TESTS ====================

class TestPayloadTemplates:
    """Test payload template listing and retrieval"""

    def test_01_templates_exist(self):
        """Verify PAYLOAD_TEMPLATES has expected entries"""
        assert len(PAYLOAD_TEMPLATES) >= 5, f"Expected ≥5 templates, got {len(PAYLOAD_TEMPLATES)}"
        required = ["basic_recon", "persistence_setup", "credential_harvest",
                     "network_pivot", "data_exfiltration"]
        for name in required:
            assert name in PAYLOAD_TEMPLATES, f"Missing template: {name}"
        print("✅ All required templates present")

    def test_02_windows_recon_template(self):
        """Verify the Windows reconnaissance template exists and is correct"""
        assert "windows_recon" in PAYLOAD_TEMPLATES, "Missing windows_recon template"
        tpl = PAYLOAD_TEMPLATES["windows_recon"]
        assert tpl["name"] == "Windows Reconnaissance"
        assert "windows" in tpl["description"].lower()
        assert tpl.get("platform") == "windows"
        assert len(tpl["commands"]) >= 6, "Windows recon should have ≥6 commands"
        # Verify Windows-specific commands
        payloads = [c["payload"] for c in tpl["commands"]]
        assert any("systeminfo" in p for p in payloads), "Missing systeminfo command"
        assert any("ipconfig" in p for p in payloads), "Missing ipconfig command"
        assert any("tasklist" in p for p in payloads), "Missing tasklist command"
        print("✅ Windows recon template validated")

    def test_03_template_structure(self):
        """Verify every template has the required fields"""
        for name, tpl in PAYLOAD_TEMPLATES.items():
            assert "name" in tpl, f"Template '{name}' missing 'name'"
            assert "description" in tpl, f"Template '{name}' missing 'description'"
            assert "commands" in tpl, f"Template '{name}' missing 'commands'"
            assert isinstance(tpl["commands"], list), f"Template '{name}' commands is not a list"
            for cmd in tpl["commands"]:
                assert "type" in cmd, f"Template '{name}' command missing 'type'"
                assert "payload" in cmd, f"Template '{name}' command missing 'payload'"
        print("✅ All template structures valid")


# ==================== API ENDPOINT TESTS ====================

class TestPayloadAPI:
    """Test the payload builder API endpoints"""

    def test_04_templates_endpoint(self):
        """GET /api/payload/templates returns template list"""
        app = create_app()

        async def run():
            async with TestServer(app) as server:
                async with TestClient(server) as client:
                    resp = await client.get('/api/payload/templates')
                    assert resp.status == 200
                    data = await resp.json()
                    assert "templates" in data
                    templates = data["templates"]
                    assert len(templates) >= 5
                    # Templates is a dict keyed by template name
                    for name, tpl in templates.items():
                        assert "name" in tpl
                        assert "description" in tpl
                    print("✅ Templates endpoint returns valid data")

        asyncio.run(run())

    def test_05_template_detail_endpoint(self):
        """GET /api/payload/templates/{name} returns specific template"""
        app = create_app()

        async def run():
            async with TestServer(app) as server:
                async with TestClient(server) as client:
                    resp = await client.get('/api/payload/templates/basic_recon')
                    assert resp.status == 200
                    data = await resp.json()
                    assert "template" in data
                    assert data["template"]["name"] == "Basic Reconnaissance"
                    print("✅ Template detail endpoint works")

        asyncio.run(run())

    def test_06_template_not_found(self):
        """GET /api/payload/templates/{invalid} returns 404"""
        app = create_app()

        async def run():
            async with TestServer(app) as server:
                async with TestClient(server) as client:
                    resp = await client.get('/api/payload/templates/nonexistent')
                    assert resp.status == 404
                    print("✅ Invalid template returns 404")

        asyncio.run(run())

    def test_07_payload_build_validation(self):
        """POST /api/payload/build validates required fields"""
        app = create_app()

        async def run():
            async with TestServer(app) as server:
                async with TestClient(server) as client:
                    # Missing required fields
                    resp = await client.post(
                        '/api/payload/build',
                        json={"agent_id": "test"}
                    )
                    assert resp.status == 400
                    data = await resp.json()
                    assert "error" in data
                    print("✅ Payload build validation works")

        asyncio.run(run())

    def test_08_payload_build_invalid_agent(self):
        """POST /api/payload/build with invalid agent returns 404"""
        app = create_app()

        async def run():
            async with TestServer(app) as server:
                async with TestClient(server) as client:
                    resp = await client.post(
                        '/api/payload/build',
                        json={
                            "agent_id": "nonexistent-agent",
                            "command_type": "exec",
                            "command_data": "whoami"
                        }
                    )
                    assert resp.status == 404
                    data = await resp.json()
                    assert data["error"] == "agent_not_found"
                    print("✅ Invalid agent returns 404")

        asyncio.run(run())

    def test_13_payload_saving_to_disk(self):
        """POST /api/payload/build saves payload to disk and returns file path"""
        
        # Ensure payloads dir exists and is clean for test (optional, server handles it)
        if PAYLOADS_DIR.exists():
            shutil.rmtree(PAYLOADS_DIR)
        PAYLOADS_DIR.mkdir()

        # We need to mock the agent check and encryption since we don't have a real DB/PKI here
        # But dashboard_server.py imports 'operational_db' and 'PKI_PATH'.
        # Since we are running the real app via create_app(), we are hitting the real logic.
        # The logic fails if agent doesn't exist in DB.
        # So we need to mock operational_db.get_agent and PKI file existence.
        
        # Using unittest.mock to patch securecomm.dashboard_server modules
        from unittest.mock import patch, MagicMock
        
        # Mock objects
        mock_agent = MagicMock()
        mock_agent.agent_id = "test-agent"
        
        mock_cert_path = MagicMock()
        mock_cert_path.exists.return_value = True
        
        # We need a real certificate for encryption to work.
        # Let's generate a temporary self-signed certificate for the test.
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import datetime
        
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        # Build a self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"test-agent"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        ).sign(private_key, hashes.SHA256())
        
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        
        # Create a mock open function that returns the Certificate PEM content
        from unittest.mock import mock_open
        m_open = mock_open(read_data=cert_pem)
        
        # Patching context

        # We patch the Class, so when it is instantiated in create_app, it returns our mock_db_instance
        with patch('securecomm.dashboard_server.OperationalDatabase') as MockDBClass, \
             patch('securecomm.dashboard_server.PKI_PATH') as mock_pki_path, \
             patch('builtins.open', m_open):
            
            # Setup mock DB instance
            mock_db_instance = MockDBClass.return_value
            mock_db_instance.get_agent.return_value = mock_agent

            # Setup mock path return
            mock_pki_path.__truediv__.return_value.__truediv__.return_value.__truediv__.return_value = mock_cert_path

            app = create_app()

            async def run():
                async with TestServer(app) as server:
                    async with TestClient(server) as client:
                        resp = await client.post(
                            '/api/payload/build',
                            json={
                                "agent_id": "test-agent",
                                "command_type": "exec",
                                "command_data": "whoami"
                            }
                        )
                        assert resp.status == 200
                        data = await resp.json()
                        assert data["success"] is True
                        assert "metadata" in data
                        assert "file_path" in data["metadata"]
                        
                        file_path = Path(data["metadata"]["file_path"])
                        assert file_path.exists()
                        assert file_path.parent == PAYLOADS_DIR
                        assert file_path.name.startswith("payload_test-agent_")
                        assert file_path.suffix == ".json"
                        
                        print(f"✅ Payload saved to {file_path}")

            asyncio.run(run())


# ==================== DASHBOARD UI TESTS ====================

class TestPayloadBuilderUI:
    """Test dashboard HTML contains payload builder elements"""

    def test_09_payload_page_exists(self):
        """Dashboard HTML has the payload builder page"""
        app = create_app()

        async def run():
            async with TestServer(app) as server:
                async with TestClient(server) as client:
                    resp = await client.get('/')
                    assert resp.status == 200
                    html = await resp.text()
                    assert 'id="page-payload"' in html, "Missing payload page"
                    assert "Payload Builder" in html
                    assert "Open Payload Builder" in html
                    assert "RSA-4096" in html or "AES-256-GCM" in html
                    print("✅ Payload builder page exists in HTML")

        asyncio.run(run())

    def test_10_payload_builder_js(self):
        """app.js has payload builder methods"""
        app = create_app()

        async def run():
            async with TestServer(app) as server:
                async with TestClient(server) as client:
                    resp = await client.get('/static/app.js')
                    assert resp.status == 200
                    js = await resp.text()
                    assert "openPayloadBuilder" in js, "Missing openPayloadBuilder method"
                    assert "buildPayload" in js, "Missing buildPayload method"
                    assert "loadPayloadTemplates" in js, "Missing loadPayloadTemplates method"
                    assert "applyTemplate" in js, "Missing applyTemplate method"
                    assert "deployPayload" in js, "Missing deployPayload method"
                    assert "copyPayload" in js, "Missing copyPayload method"
                    print("✅ All payload builder JS methods present")

        asyncio.run(run())

    def test_11_quick_actions_payload_button(self):
        """Dashboard has quick action button for Payload Builder"""
        app = create_app()

        async def run():
            async with TestServer(app) as server:
                async with TestClient(server) as client:
                    resp = await client.get('/')
                    assert resp.status == 200
                    html = await resp.text()
                    assert 'id="btn-payload-builder"' in html
                    print("✅ Payload Builder quick action button present")

        asyncio.run(run())

    def test_12_windows_template_in_api(self):
        """Windows recon template is accessible via the API"""
        app = create_app()

        async def run():
            async with TestServer(app) as server:
                async with TestClient(server) as client:
                    resp = await client.get('/api/payload/templates/windows_recon')
                    assert resp.status == 200
                    data = await resp.json()
                    tpl = data["template"]
                    assert tpl["name"] == "Windows Reconnaissance"
                    assert tpl["platform"] == "windows"
                    assert len(tpl["commands"]) >= 6
                    print("✅ Windows recon template accessible via API")

        asyncio.run(run())
