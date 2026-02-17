"""
SecureComm Health Check Module
Provides system and component health checks for production monitoring

Author: SecureComm Team
Version: 1.0.0
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .pki_manager import PKIManager
    from .operational_db import OperationalDatabase
    from .security import SecurityModule
    from .session import SessionManager

logger = logging.getLogger(__name__)


@dataclass
class ComponentHealth:
    """Health status of a component"""
    name: str
    status: str  # "healthy", "degraded", "unhealthy"
    message: str = ""
    last_checked: Optional[datetime] = None
    details: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "message": self.message,
            "last_checked": self.last_checked.isoformat() if self.last_checked else None,
            "details": self.details or {},
        }


class HealthChecker:
    """Checks system and component health"""

    def __init__(
        self,
        pki_manager: Optional[PKIManager] = None,
        operational_db: Optional[OperationalDatabase] = None,
        security: Optional[SecurityModule] = None,
        session_manager: Optional[SessionManager] = None,
    ):
        self.pki_manager = pki_manager
        self.operational_db = operational_db
        self.security = security
        self.session_manager = session_manager
        self.last_check = None

    async def check_pki_health(self) -> ComponentHealth:
        """Check PKI manager health"""
        try:
            if not self.pki_manager:
                return ComponentHealth(
                    "pki",
                    "degraded",
                    "PKI manager not initialized",
                    datetime.now(timezone.utc),
                )
            
            # Try to load CA certificate
            ca_cert = self.pki_manager.load_ca_certificate()
            
            # Check CA expiry
            now = datetime.now(timezone.utc)
            expires_at = ca_cert.not_valid_after.replace(tzinfo=timezone.utc)
            days_until_expiry = (expires_at - now).days
            
            if days_until_expiry < 0:
                return ComponentHealth(
                    "pki",
                    "unhealthy",
                    f"CA certificate expired {abs(days_until_expiry)} days ago",
                    datetime.now(timezone.utc),
                    {"days_until_expiry": days_until_expiry},
                )
            elif days_until_expiry < 30:
                return ComponentHealth(
                    "pki",
                    "degraded",
                    f"CA certificate expiring in {days_until_expiry} days",
                    datetime.now(timezone.utc),
                    {"days_until_expiry": days_until_expiry},
                )
            
            return ComponentHealth(
                "pki",
                "healthy",
                "PKI operational",
                datetime.now(timezone.utc),
                {"days_until_ca_expiry": days_until_expiry},
            )
        
        except Exception as e:
            logger.error(f"PKI health check failed: {e}")
            return ComponentHealth(
                "pki",
                "unhealthy",
                f"Health check error: {str(e)}",
                datetime.now(timezone.utc),
            )

    async def check_database_health(self) -> ComponentHealth:
        """Check operational database health"""
        try:
            if not self.operational_db:
                return ComponentHealth(
                    "database",
                    "degraded",
                    "Database not initialized",
                    datetime.now(timezone.utc),
                )
            
            # Try to read agents
            agents = self.operational_db.list_agents()
            
            return ComponentHealth(
                "database",
                "healthy",
                "Database operational",
                datetime.now(timezone.utc),
                {"agent_count": len(agents)},
            )
        
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return ComponentHealth(
                "database",
                "unhealthy",
                f"Health check error: {str(e)}",
                datetime.now(timezone.utc),
            )

    async def check_session_health(self) -> ComponentHealth:
        """Check session manager health"""
        try:
            if not self.session_manager:
                return ComponentHealth(
                    "sessions",
                    "degraded",
                    "Session manager not initialized",
                    datetime.now(timezone.utc),
                )
            
            # Get active sessions count
            active_sessions = self.session_manager.get_total_sessions()
            
            return ComponentHealth(
                "sessions",
                "healthy",
                "Session manager operational",
                datetime.now(timezone.utc),
                {"active_sessions": active_sessions},
            )
        
        except Exception as e:
            logger.error(f"Session health check failed: {e}")
            return ComponentHealth(
                "sessions",
                "unhealthy",
                f"Health check error: {str(e)}",
                datetime.now(timezone.utc),
            )

    async def check_security_health(self) -> ComponentHealth:
        """Check security module health"""
        try:
            if not self.security:
                return ComponentHealth(
                    "security",
                    "degraded",
                    "Security module not initialized",
                    datetime.now(timezone.utc),
                )
            
            # Security module is always healthy if initialized
            return ComponentHealth(
                "security",
                "healthy",
                "Security module operational",
                datetime.now(timezone.utc),
            )
        
        except Exception as e:
            logger.error(f"Security health check failed: {e}")
            return ComponentHealth(
                "security",
                "unhealthy",
                f"Health check error: {str(e)}",
                datetime.now(timezone.utc),
            )

    async def check_all_components(self) -> Dict[str, ComponentHealth]:
        """Check health of all components"""
        results = {}
        
        # Run checks concurrently
        checks = [
            ("pki", self.check_pki_health()),
            ("database", self.check_database_health()),
            ("sessions", self.check_session_health()),
            ("security", self.check_security_health()),
        ]
        
        for name, check_coro in checks:
            try:
                results[name] = await check_coro
            except Exception as e:
                logger.error(f"Failed to check {name}: {e}")
                results[name] = ComponentHealth(
                    name,
                    "unhealthy",
                    f"Check error: {str(e)}",
                    datetime.now(timezone.utc),
                )
        
        return results

    async def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health"""
        components = await self.check_all_components()
        self.last_check = datetime.now(timezone.utc)
        
        # Determine overall status
        statuses = [c.status for c in components.values()]
        if "unhealthy" in statuses:
            overall_status = "unhealthy"
        elif "degraded" in statuses:
            overall_status = "degraded"
        else:
            overall_status = "healthy"
        
        return {
            "status": overall_status,
            "timestamp": self.last_check.isoformat(),
            "components": {name: comp.to_dict() for name, comp in components.items()},
        }

    async def is_ready(self) -> bool:
        """Check if system is ready for operation"""
        components = await self.check_all_components()
        
        # System is ready if no unhealthy components
        return all(c.status != "unhealthy" for c in components.values())

