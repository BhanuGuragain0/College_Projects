"""
Stealth Manager
Handles anti-debugging and situational awareness
"""

import sys
import platform
import time
import random
import logging
import ctypes
from typing import Optional

class StealthManager:
    """
    Manages stealth and evasion techniques.
    Features:
    - Anti-debugging checks
    - Sandbox detection (basic)
    - Execution jitter
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def check_environment(self) -> bool:
        """
        Perform environment checks (anti-debug, etc.)
        Returns True if safe to proceed, False if threat detected.
        """
        if self._is_being_debugged():
            self.logger.warning("🚫 Debugger detected! Initiating evasive maneuvers.")
            return False
        
        return True

    def random_sleep(self, min_seconds: int = 1, max_seconds: int = 5):
        """Sleep for a random interval"""
        sleep_time = random.uniform(min_seconds, max_seconds)
        time.sleep(sleep_time)
        self.logger.debug(f"Slept for {sleep_time:.2f}s")

    def _is_being_debugged(self) -> bool:
        """Check for debugger presence"""
        try:
            if platform.system() == "Windows":
                return self._check_windows_debug()
            elif platform.system() == "Linux":
                return self._check_linux_debug()
        except Exception as e:
            self.logger.error(f"Error checking debug status: {e}")
        return False

    def _check_windows_debug(self) -> bool:
        """Windows specific debugger checks"""
        try:
            return ctypes.windll.kernel32.IsDebuggerPresent() != 0
        except (AttributeError, OSError) as e:
            self.logger.debug(f"Windows debugger check failed: {e}")
            return False

    def _check_linux_debug(self) -> bool:
        """Linux specific debugger checks"""
        try:
            with open("/proc/self/status", "r") as f:
                content = f.read()
                # Check TracerPid
                for line in content.splitlines():
                    if line.startswith("TracerPid:"):
                        pid = int(line.split()[1])
                        if pid > 0:
                            return True
            return False
        except (FileNotFoundError, ValueError, OSError) as e:
            self.logger.debug(f"Linux debugger check failed: {e}")
            return False
