"""
Audit logging for SecureComm
"""

import json
import logging
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Any, List


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
            "timestamp": datetime.now(timezone.utc).isoformat()
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
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        self.logger.info(json.dumps(log_entry))
    
    def log_security_event(self, event_type: str, details: dict):
        """Log security events (MITM, replay, etc)"""
        log_entry = {
            "type": "security",
            "event_type": event_type,
            "details": details,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        self.logger.warning(json.dumps(log_entry))
    
    def search_logs(
        self,
        query: str = "",
        agent_id: str = "",
        event_type: str = "",
        start_date: str = "",
        end_date: str = "",
        limit: int = 100
    ) -> Dict[str, Any]:
        """
        Search audit logs with advanced filtering
        
        Args:
            query: Search query string
            agent_id: Filter by agent ID
            event_type: Filter by event type
            start_date: Start date filter (ISO format)
            end_date: End date filter (ISO format)
            limit: Maximum number of results
            
        Returns:
            Dictionary with search results and metadata
        """
        try:
            search_results = {
                "query": query,
                "filters": {
                    "agent_id": agent_id,
                    "event_type": event_type,
                    "start_date": start_date,
                    "end_date": end_date,
                    "limit": limit
                },
                "results": [],
                "total_matches": 0,
                "execution_time_ms": 0,
                "search_performed_at": datetime.now(timezone.utc).isoformat()
            }
            
            start_time = datetime.now().timestamp()
            
            # Get all log files
            log_files = list(self.log_dir.glob("audit_*.log"))
            log_files.sort(reverse=True)  # Most recent first
            
            all_entries = []
            
            # Parse all log entries
            for log_file in log_files:
                try:
                    with open(log_file, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if line and line.startswith('{'):
                                try:
                                    entry = json.loads(line)
                                    
                                    # Add search fields
                                    entry['search_text'] = self._create_search_text(entry)
                                    entry['search_keywords'] = self._extract_search_keywords(entry)
                                    
                                    # Apply filters
                                    if self._matches_filters(entry, query, agent_id, event_type, start_date, end_date):
                                        all_entries.append(entry)
                                        
                                except json.JSONDecodeError:
                                    continue
                except Exception as e:
                    logging.error(f"Error reading log file {log_file}: {e}")
                    continue
            
            # Sort by timestamp (most recent first)
            all_entries.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            
            # Apply limit
            search_results["results"] = all_entries[:limit]
            search_results["total_matches"] = len(all_entries)
            search_results["execution_time_ms"] = int((datetime.now().timestamp() - start_time) * 1000)
            
            return search_results
            
        except Exception as e:
            logging.error(f"Search failed: {e}")
            return {
                "error": "search_failed",
                "detail": str(e),
                "query": query,
                "filters": {
                    "agent_id": agent_id,
                    "event_type": event_type,
                    "start_date": start_date,
                    "end_date": end_date
                }
            }
    
    def _create_search_text(self, entry: Dict) -> str:
        """Create searchable text from audit entry"""
        search_fields = []
        
        # Basic fields
        for field in ['agent_id', 'type', 'event_type', 'command_type', 'status']:
            if field in entry and entry[field]:
                search_fields.append(str(entry[field]).lower())
        
        # Nested fields
        if 'details' in entry and isinstance(entry['details'], dict):
            for key, value in entry['details'].items():
                search_fields.append(f"{key}:{value}".lower())
        
        if 'result' in entry and isinstance(entry['result'], dict):
            for key, value in entry['result'].items():
                search_fields.append(f"{key}:{value}".lower())
        
        return " ".join(search_fields)
    
    def _extract_search_keywords(self, entry: Dict) -> List[str]:
        """Extract keywords for searching"""
        keywords = []
        
        # Event types
        if entry.get('type') in ['command', 'connection', 'security', 'command_result']:
            keywords.append(entry['type'])
        
        # Security events
        security_events = ['mitm_detected', 'replay_detected', 'unauthorized_access', 'certificate_mismatch']
        if entry.get('event_type') in security_events:
            keywords.append(entry['event_type'])
            keywords.append('security')
        
        # Command types
        command_types = ['exec', 'shell', 'upload', 'download', 'persist', 'recon']
        if entry.get('command_type') in command_types:
            keywords.append(entry['command_type'])
        
        # Status keywords
        status_keywords = ['success', 'failed', 'error', 'timeout', 'denied']
        if entry.get('status') in status_keywords:
            keywords.append(entry['status'])
        
        return keywords
    
    def _matches_filters(
        self, 
        entry: Dict, 
        query: str, 
        agent_id: str, 
        event_type: str, 
        start_date: str, 
        end_date: str
    ) -> bool:
        """Check if entry matches all search filters"""
        
        # Query filter
        if query:
            query_lower = query.lower()
            search_text = entry.get('search_text', '').lower()
            if query_lower not in search_text:
                return False
        
        # Agent ID filter
        if agent_id:
            if entry.get('agent_id', '').lower() != agent_id.lower():
                return False
        
        # Event type filter
        if event_type:
            if entry.get('type', '').lower() != event_type.lower():
                return False
        
        # Start date filter
        if start_date:
            try:
                entry_time = datetime.fromisoformat(entry.get('timestamp', '').replace('Z', '+00:00'))
                filter_time = datetime.fromisoformat(start_date)
                if entry_time < filter_time:
                    return False
            except ValueError:
                pass  # Invalid date format, ignore filter
        
        # End date filter
        if end_date:
            try:
                entry_time = datetime.fromisoformat(entry.get('timestamp', '').replace('Z', '+00:00'))
                filter_time = datetime.fromisoformat(end_date)
                if entry_time > filter_time:
                    return False
            except ValueError:
                pass  # Invalid date format, ignore filter
        
        return True
    
    def get_log_statistics(self) -> Dict[str, Any]:
        """Get comprehensive audit log statistics"""
        try:
            stats = {
                "total_entries": 0,
                "event_types": {},
                "agent_activity": {},
                "security_events": 0,
                "command_results": {},
                "date_range": {"earliest": None, "latest": None},
                "generated_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Get all log files
            log_files = list(self.log_dir.glob("audit_*.log"))
            
            for log_file in log_files:
                try:
                    with open(log_file, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if line and line.startswith('{'):
                                try:
                                    entry = json.loads(line)
                                    stats["total_entries"] += 1
                                    
                                    # Count event types
                                    event_type = entry.get('type', 'unknown')
                                    stats["event_types"][event_type] = stats["event_types"].get(event_type, 0) + 1
                                    
                                    # Count agent activity
                                    if 'agent_id' in entry:
                                        agent = entry['agent_id']
                                        stats["agent_activity"][agent] = stats["agent_activity"].get(agent, 0) + 1
                                    
                                    # Count security events
                                    if entry.get('type') == 'security':
                                        stats["security_events"] += 1
                                    
                                    # Count command results
                                    if entry.get('type') == 'command_result':
                                        status = entry.get('status', 'unknown')
                                        stats["command_results"][status] = stats["command_results"].get(status, 0) + 1
                                    
                                    # Track date range
                                    if 'timestamp' in entry:
                                        entry_time = datetime.fromisoformat(entry['timestamp'].replace('Z', '+00:00'))
                                        if stats["date_range"]["earliest"] is None or entry_time < stats["date_range"]["earliest"]:
                                            stats["date_range"]["earliest"] = entry_time
                                        if stats["date_range"]["latest"] is None or entry_time > stats["date_range"]["latest"]:
                                            stats["date_range"]["latest"] = entry_time
                                            
                                except json.JSONDecodeError:
                                    continue
                except Exception as e:
                    logging.error(f"Error processing log file {log_file}: {e}")
                    continue
            
            return stats
            
        except Exception as e:
            logging.error(f"Failed to generate statistics: {e}")
            return {"error": "statistics_failed", "detail": str(e)}