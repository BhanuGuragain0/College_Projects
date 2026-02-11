"""
Audit logging for SecureComm
"""

import json
import logging
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Any


class AuditLogger:
    """
    Tamper-proof audit logging
    
    Features:
    - Command logging
    - Response logging
    - Security event logging
    - JSON format for easy parsing
    """
    
    def __init__(self, log_dir: str = "data/logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger = logging.getLogger(__name__)
        self._setup_logger()
    
    def _setup_logger(self):
        """Setup file logger"""
        log_file = self.log_dir / f"audit_{datetime.now().strftime('%Y%m%d')}.log"
        
        handler = logging.FileHandler(log_file)
        handler.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": %(message)s}'
        )
        handler.setFormatter(formatter)
        
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def log_command(
        self,
        agent_id: str,
        cmd_type: str,
        payload: str,
        task_id: Optional[str] = None,
        operator_id: Optional[str] = None,
    ):
        """Log command execution"""
        log_entry = {
            "type": "command",
            "agent_id": agent_id,
            "command_type": cmd_type,
            "command_hash": hashlib.sha256(payload.encode()).hexdigest(),
            "timestamp": datetime.utcnow().isoformat()
        }
        if task_id:
            log_entry["task_id"] = task_id
        if operator_id:
            log_entry["operator_id"] = operator_id
        self.logger.info(json.dumps(log_entry))

    def log_command_result(
        self,
        task_id: str,
        agent_id: str,
        status: str,
        result: Any,
        operator_id: Optional[str] = None,
    ):
        """Log command execution results"""
        result_json = json.dumps(result, sort_keys=True, default=str)
        log_entry = {
            "type": "command_result",
            "task_id": task_id,
            "agent_id": agent_id,
            "status": status,
            "result_hash": hashlib.sha256(result_json.encode()).hexdigest(),
            "result_preview": result_json[:200],
            "timestamp": datetime.utcnow().isoformat(),
        }
        if operator_id:
            log_entry["operator_id"] = operator_id
        self.logger.info(json.dumps(log_entry))
    
    def log_connection(self, agent_id: str, event: str, details: dict):
        """Log connection events"""
        log_entry = {
            "type": "connection",
            "agent_id": agent_id,
            "event": event,
            "details": details,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.logger.info(json.dumps(log_entry))
    
    def log_security_event(self, event_type: str, details: dict):
        """Log security events (MITM, replay, etc)"""
        log_entry = {
            "type": "security",
            "event_type": event_type,
            "details": details,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.logger.warning(json.dumps(log_entry))