"""
Operational database for SecureComm academic workflows.
Stores agent registrations, command records, and responses.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class AgentRecord:
    agent_id: str
    ip_address: str
    status: str
    connected_at: datetime
    last_seen: datetime
    certificate_fingerprint: str
    certificate_subject: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "agent_id": self.agent_id,
            "ip_address": self.ip_address,
            "status": self.status,
            "connected_at": self.connected_at.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "certificate_fingerprint": self.certificate_fingerprint,
            "certificate_subject": self.certificate_subject,
        }

    @classmethod
    def from_dict(cls, payload: Dict[str, object]) -> "AgentRecord":
        return cls(
            agent_id=str(payload["agent_id"]),
            ip_address=str(payload["ip_address"]),
            status=str(payload["status"]),
            connected_at=datetime.fromisoformat(str(payload["connected_at"])),
            last_seen=datetime.fromisoformat(str(payload["last_seen"])),
            certificate_fingerprint=str(payload["certificate_fingerprint"]),
            certificate_subject=str(payload["certificate_subject"]),
        )


@dataclass
class CommandRecord:
    task_id: str
    operator_id: str
    agent_id: str
    command_type: str
    payload: str
    nonce: str
    timestamp: int
    signature: str
    status: str = "pending"
    created_at: datetime = field(default_factory=utc_now)
    response: Optional[Dict[str, object]] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "task_id": self.task_id,
            "operator_id": self.operator_id,
            "agent_id": self.agent_id,
            "command_type": self.command_type,
            "payload": self.payload,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "signature": self.signature,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "response": self.response,
        }

    @classmethod
    def from_dict(cls, payload: Dict[str, object]) -> "CommandRecord":
        created_at = datetime.fromisoformat(str(payload["created_at"]))
        return cls(
            task_id=str(payload["task_id"]),
            operator_id=str(payload["operator_id"]),
            agent_id=str(payload["agent_id"]),
            command_type=str(payload["command_type"]),
            payload=str(payload["payload"]),
            nonce=str(payload["nonce"]),
            timestamp=int(payload["timestamp"]),
            signature=str(payload["signature"]),
            status=str(payload.get("status", "pending")),
            created_at=created_at,
            response=payload.get("response"),
        )


class OperationalDatabase:
    """Lightweight operational database with optional JSON persistence."""

    def __init__(self, storage_path: Optional[str] = None) -> None:
        self._lock = Lock()
        self._agents: Dict[str, AgentRecord] = {}
        self._commands: Dict[str, CommandRecord] = {}
        self._storage_path = Path(storage_path) if storage_path else None
        self._logger = logging.getLogger(__name__)
        if self._storage_path:
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)
            self._load()

    def register_agent(self, record: AgentRecord) -> None:
        with self._lock:
            self._agents[record.agent_id] = record
            self._persist()

    def update_agent_status(self, agent_id: str, status: str, last_seen: Optional[datetime] = None) -> None:
        with self._lock:
            record = self._agents.get(agent_id)
            if not record:
                self._logger.warning("Agent not found for status update: %s", agent_id)
                return
            record.status = status
            record.last_seen = last_seen or utc_now()
            self._persist()

    def list_agents(self) -> List[AgentRecord]:
        with self._lock:
            return list(self._agents.values())

    def list_commands(self) -> List[CommandRecord]:
        with self._lock:
            return list(self._commands.values())

    def get_agent(self, agent_id: str) -> Optional[AgentRecord]:
        with self._lock:
            return self._agents.get(agent_id)

    def record_command(self, record: CommandRecord) -> None:
        with self._lock:
            self._commands[record.task_id] = record
            self._persist()

    def record_response(self, task_id: str, response: Dict[str, object], status: str) -> None:
        with self._lock:
            record = self._commands.get(task_id)
            if not record:
                self._logger.warning("Command record not found for response: %s", task_id)
                return
            record.response = response
            record.status = status
            self._persist()

    def get_command(self, task_id: str) -> Optional[CommandRecord]:
        with self._lock:
            return self._commands.get(task_id)

    def reload(self) -> None:
        if not self._storage_path:
            return
        with self._lock:
            self._load()

    def _persist(self) -> None:
        if not self._storage_path:
            return
        data = {
            "agents": [record.to_dict() for record in self._agents.values()],
            "commands": [record.to_dict() for record in self._commands.values()],
        }
        payload = json.dumps(data, indent=2)
        temp_path = self._storage_path.with_suffix(self._storage_path.suffix + ".tmp")
        temp_path.write_text(payload)
        temp_path.replace(self._storage_path)

    def _load(self) -> None:
        if not self._storage_path or not self._storage_path.exists():
            return
        try:
            payload = json.loads(self._storage_path.read_text())
        except json.JSONDecodeError as exc:
            self._logger.warning("Operational DB JSON decode failed: %s", exc)
            return
        agents = payload.get("agents", [])
        commands = payload.get("commands", [])
        self._agents = {record["agent_id"]: AgentRecord.from_dict(record) for record in agents}
        self._commands = {record["task_id"]: CommandRecord.from_dict(record) for record in commands}
