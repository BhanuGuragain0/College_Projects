"""
SecureComm Structured Logging Context
Provides operation context tracking for distributed tracing

Author: SecureComm Team
Version: 1.0.0
"""

from __future__ import annotations

import json
import logging
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from threading import local
from typing import Any, Dict, Optional

# Thread-local context stack
_context_stack = local()


class OperationContext:
    """Tracks operation context for structured logging"""

    def __init__(
        self,
        operation_type: str,
        operation_id: Optional[str] = None,
        **metadata
    ):
        self.operation_id = operation_id or str(uuid.uuid4())
        self.operation_type = operation_type
        self.metadata = metadata
        self.start_time = datetime.now(timezone.utc)
        self.events: list[Dict[str, Any]] = []

    def add_event(self, event_type: str, **details):
        """Record an event within this operation"""
        self.events.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": event_type,
            **details
        })

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging"""
        elapsed = (datetime.now(timezone.utc) - self.start_time).total_seconds() * 1000
        return {
            "op_id": self.operation_id,
            "op_type": self.operation_type,
            "started_at": self.start_time.isoformat(),
            "elapsed_ms": elapsed,
            "metadata": self.metadata,
            "events": self.events,
        }


class ContextManager:
    """Manages operation context stack"""

    @staticmethod
    def get_stack() -> list[OperationContext]:
        """Get current context stack"""
        if not hasattr(_context_stack, "stack"):
            _context_stack.stack = []
        return _context_stack.stack

    @staticmethod
    def current() -> Optional[OperationContext]:
        """Get current (innermost) context"""
        stack = ContextManager.get_stack()
        return stack[-1] if stack else None

    @staticmethod
    def push(context: OperationContext):
        """Push context onto stack"""
        ContextManager.get_stack().append(context)

    @staticmethod
    def pop() -> Optional[OperationContext]:
        """Pop context from stack"""
        stack = ContextManager.get_stack()
        return stack.pop() if stack else None

    @staticmethod
    @contextmanager
    def operation(operation_type: str, operation_id: Optional[str] = None, **metadata):
        """
        Context manager for tracking operations
        
        Usage:
            with ContextManager.operation("batch_command", agent_count=5) as ctx:
                # operation code
                ctx.add_event("command_sent", agent_id="agent_001")
        """
        context = OperationContext(operation_type, operation_id, **metadata)
        ContextManager.push(context)
        try:
            yield context
        finally:
            ContextManager.pop()


class StructuredFormatter(logging.Formatter):
    """Logging formatter that adds operation context to records"""

    def format(self, record: logging.LogRecord) -> str:
        """Format record with context"""
        ctx = ContextManager.current()
        
        # Add context fields to record
        if ctx:
            record.op_id = ctx.operation_id
            record.op_type = ctx.operation_type
        else:
            record.op_id = "no-context"
            record.op_type = "unknown"
        
        return super().format(record)


def setup_structured_logging(logger_name: str = None) -> logging.Logger:
    """
    Setup structured logging with context support
    
    Args:
        logger_name: Logger name (default: root)
    
    Returns:
        Configured logger
    """
    logger = logging.getLogger(logger_name)
    
    # Create formatter with context fields
    formatter = StructuredFormatter(
        fmt=json.dumps({
            "timestamp": "%(asctime)s",
            "level": "%(levelname)s",
            "logger": "%(name)s",
            "op_id": "%(op_id)s",
            "op_type": "%(op_type)s",
            "message": "%(message)s",
        })
    )
    
    # Add console handler
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    return logger


def get_context_dict() -> Dict[str, Any]:
    """Get current context as dictionary for logging"""
    ctx = ContextManager.current()
    if ctx:
        return {
            "op_id": ctx.operation_id,
            "op_type": ctx.operation_type,
            **ctx.metadata
        }
    return {}

