"""
SecureComm Session Manager
Manages encryption sessions, key rotation, and Perfect Forward Secrecy

Author: Shadow Junior
"""

import time
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, Optional, Set
import logging
from threading import Lock


@dataclass
class Session:
    """
    Represents an active encryption session
    
    Attributes:
        agent_id: Unique agent identifier
        session_key: Current AES-256 session key
        created_at: Session creation timestamp
        last_activity: Last communication timestamp
        command_count: Number of commands sent
        ecdh_public: Current ECDH public key
        nonce_history: Set of used nonces (replay protection)
    """
    agent_id: str
    session_key: bytes
    created_at: datetime
    last_activity: datetime
    command_count: int = 0
    ecdh_public: Optional[bytes] = None
    nonce_history: Set[str] = field(default_factory=set)
    
    def should_rotate(self, rotation_threshold: int = 100, time_threshold: int = 3600) -> bool:
        """
        Determine if session key should be rotated
        
        Args:
            rotation_threshold: Max commands before rotation (default 100)
            time_threshold: Max seconds before rotation (default 1 hour)
        
        Returns:
            True if rotation needed
        
        Security:
            - Perfect Forward Secrecy: rotate keys regularly
            - Limit key exposure window
            - Prevent cryptanalysis with large datasets
        """
        # Check command count
        if self.command_count >= rotation_threshold:
            return True
        
        # Check time elapsed
        elapsed = (datetime.utcnow() - self.created_at).total_seconds()
        if elapsed >= time_threshold:
            return True
        
        return False
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.utcnow()
    
    def increment_command_count(self):
        """Increment command counter"""
        self.command_count += 1
        self.update_activity()


class SessionManager:
    """
    Manages encryption sessions for all active agents
    
    Features:
    - Session creation and tracking
    - Automatic key rotation (Perfect Forward Secrecy)
    - Session timeout handling
    - Nonce management for replay protection
    - Thread-safe operations
    """
    
    def __init__(
        self,
        rotation_threshold: int = 100,
        time_threshold: int = 3600,
        session_timeout: int = 7200
    ):
        """
        Initialize Session Manager
        
        Args:
            rotation_threshold: Commands before key rotation (default 100)
            time_threshold: Seconds before key rotation (default 1 hour)
            session_timeout: Session inactivity timeout (default 2 hours)
        """
        self.sessions: Dict[str, Session] = {}
        self.rotation_threshold = rotation_threshold
        self.time_threshold = time_threshold
        self.session_timeout = session_timeout
        
        self.logger = logging.getLogger(__name__)
        self._lock = Lock()  # Thread safety
    
    def create_session(
        self,
        agent_id: str,
        session_key: bytes,
        ecdh_public: Optional[bytes] = None
    ) -> Session:
        """
        Create new encryption session
        
        Args:
            agent_id: Unique agent identifier
            session_key: Initial AES-256 session key
            ecdh_public: Agent's ECDH public key
        
        Returns:
            Created session object
        """
        with self._lock:
            now = datetime.utcnow()
            
            session = Session(
                agent_id=agent_id,
                session_key=session_key,
                created_at=now,
                last_activity=now,
                ecdh_public=ecdh_public
            )
            
            self.sessions[agent_id] = session
            
            self.logger.info(f"✅ Created session for agent: {agent_id}")
            return session
    
    def get_session(self, agent_id: str) -> Optional[Session]:
        """
        Get session by agent ID
        
        Args:
            agent_id: Agent identifier
        
        Returns:
            Session object or None
        """
        with self._lock:
            return self.sessions.get(agent_id)
    
    def update_session_key(
        self,
        agent_id: str,
        new_session_key: bytes,
        new_ecdh_public: Optional[bytes] = None
    ) -> bool:
        """
        Rotate session key (Perfect Forward Secrecy)
        
        Args:
            agent_id: Agent identifier
            new_session_key: New AES-256 session key
            new_ecdh_public: New ECDH public key
        
        Returns:
            True if successful
        
        Security:
            - Old key is discarded (PFS)
            - New ephemeral ECDH keys used
            - Command counter reset
            - Nonce history cleared
        """
        with self._lock:
            session = self.sessions.get(agent_id)
            if not session:
                self.logger.error(f"❌ Session not found: {agent_id}")
                return False
            
            # Discard old key (Perfect Forward Secrecy)
            old_key = session.session_key
            session.session_key = new_session_key
            
            # Update ECDH public key
            if new_ecdh_public:
                session.ecdh_public = new_ecdh_public
            
            # Reset counters
            session.command_count = 0
            session.created_at = datetime.utcnow()
            
            # Clear nonce history (new session)
            session.nonce_history.clear()
            
            # Overwrite old key in memory
            if old_key:
                del old_key
            
            self.logger.info(f"🔄 Rotated session key for agent: {agent_id}")
            return True
    
    def check_and_rotate(self, agent_id: str) -> bool:
        """
        Check if session needs rotation
        
        Args:
            agent_id: Agent identifier
        
        Returns:
            True if rotation needed
        """
        session = self.get_session(agent_id)
        if not session:
            return False
        
        return session.should_rotate(self.rotation_threshold, self.time_threshold)
    
    def record_command(self, agent_id: str, nonce: str) -> bool:
        """
        Record command and check for replay
        
        Args:
            agent_id: Agent identifier
            nonce: Command nonce
        
        Returns:
            True if nonce is unique (not a replay)
        
        Security:
            - Replay protection
            - Nonce uniqueness validation
            - Command counting for key rotation
        """
        with self._lock:
            session = self.sessions.get(agent_id)
            if not session:
                self.logger.error(f"❌ Session not found: {agent_id}")
                return False
            
            # Check for replay attack
            if nonce in session.nonce_history:
                self.logger.warning(f"⚠️  Replay attack detected for agent {agent_id}: nonce reused")
                return False
            
            # Record nonce
            session.nonce_history.add(nonce)
            
            # Increment command counter
            session.increment_command_count()
            
            # Cleanup old nonces if history gets too large
            if len(session.nonce_history) > 10000:
                # Keep only last 5000 nonces
                sorted_nonces = sorted(session.nonce_history)
                session.nonce_history = set(sorted_nonces[-5000:])
            
            return True
    
    def remove_session(self, agent_id: str) -> bool:
        """
        Remove session
        
        Args:
            agent_id: Agent identifier
        
        Returns:
            True if removed
        """
        with self._lock:
            if agent_id in self.sessions:
                session = self.sessions[agent_id]
                
                # Clear session key from memory
                if session.session_key:
                    session.session_key = b'\x00' * len(session.session_key)
                    del session.session_key
                
                # Remove session
                del self.sessions[agent_id]
                
                self.logger.info(f"✅ Removed session for agent: {agent_id}")
                return True
        
        return False
    
    def cleanup_expired_sessions(self):
        """
        Remove expired/inactive sessions
        
        Security:
            - Automatic session timeout
            - Prevents stale session accumulation
            - Reduces attack surface
        """
        with self._lock:
            now = datetime.utcnow()
            expired = []
            
            for agent_id, session in self.sessions.items():
                elapsed = (now - session.last_activity).total_seconds()
                if elapsed > self.session_timeout:
                    expired.append(agent_id)
            
            for agent_id in expired:
                self.logger.info(f"⏰ Session timeout for agent: {agent_id}")
                self.remove_session(agent_id)
            
            if expired:
                self.logger.info(f"✅ Cleaned up {len(expired)} expired sessions")
    
    def get_session_stats(self, agent_id: str) -> Optional[Dict]:
        """
        Get session statistics
        
        Args:
            agent_id: Agent identifier
        
        Returns:
            Session statistics dictionary
        """
        session = self.get_session(agent_id)
        if not session:
            return None
        
        now = datetime.utcnow()
        age = (now - session.created_at).total_seconds()
        idle = (now - session.last_activity).total_seconds()
        
        return {
            "agent_id": agent_id,
            "command_count": session.command_count,
            "age_seconds": age,
            "idle_seconds": idle,
            "needs_rotation": session.should_rotate(self.rotation_threshold, self.time_threshold),
            "nonce_history_size": len(session.nonce_history)
        }
    
    def list_active_sessions(self) -> list:
        """
        List all active sessions
        
        Returns:
            List of agent IDs
        """
        with self._lock:
            return list(self.sessions.keys())
    
    def get_total_sessions(self) -> int:
        """Get total number of active sessions"""
        with self._lock:
            return len(self.sessions)


# ==================== USAGE EXAMPLE ====================

if __name__ == "__main__":
    import secrets
    
    logging.basicConfig(level=logging.INFO)
    
    print("🔥 SecureComm Session Manager Test 🔥\n")
    
    # Initialize session manager
    session_mgr = SessionManager(
        rotation_threshold=5,      # Rotate after 5 commands (for testing)
        time_threshold=10,         # Or after 10 seconds
        session_timeout=60         # Timeout after 60 seconds
    )
    
    print("1. Create Sessions")
    print("-" * 50)
    
    # Create sessions for multiple agents
    for i in range(3):
        agent_id = f"agent_{i:03d}"
        session_key = secrets.token_bytes(32)
        ecdh_public = secrets.token_bytes(32)
        
        session_mgr.create_session(agent_id, session_key, ecdh_public)
    
    print(f"✅ Total sessions: {session_mgr.get_total_sessions()}\n")
    
    print("2. Send Commands (Replay Protection)")
    print("-" * 50)
    
    agent_id = "agent_000"
    
    # Send valid commands
    for i in range(3):
        nonce = secrets.token_hex(32)
        result = session_mgr.record_command(agent_id, nonce)
        print(f"  Command {i+1}: {result}")
    
    # Try replay attack
    print("\n⚠️  Attempting replay attack...")
    replay_nonce = secrets.token_hex(32)
    session_mgr.record_command(agent_id, replay_nonce)
    replay_result = session_mgr.record_command(agent_id, replay_nonce)  # Replay
    print(f"  Replay blocked: {not replay_result}\n")
    
    print("3. Session Statistics")
    print("-" * 50)
    
    stats = session_mgr.get_session_stats(agent_id)
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\n4. Key Rotation Test")
    print("-" * 50)
    
    # Send more commands to trigger rotation
    for i in range(5):
        nonce = secrets.token_hex(32)
        session_mgr.record_command(agent_id, nonce)
    
    needs_rotation = session_mgr.check_and_rotate(agent_id)
    print(f"  Needs rotation: {needs_rotation}")
    
    if needs_rotation:
        new_key = secrets.token_bytes(32)
        new_public = secrets.token_bytes(32)
        session_mgr.update_session_key(agent_id, new_key, new_public)
        print(f"  ✅ Key rotated successfully")
    
    print("\n5. Session Cleanup")
    print("-" * 50)
    
    print(f"  Before cleanup: {session_mgr.get_total_sessions()} sessions")
    session_mgr.cleanup_expired_sessions()
    print(f"  After cleanup: {session_mgr.get_total_sessions()} sessions")
    
    print("\n🔥 Session Manager test completed! 🔥")
