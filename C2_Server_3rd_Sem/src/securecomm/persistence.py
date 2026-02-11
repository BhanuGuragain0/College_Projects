"""
Persistence Manager
Handles persistence mechanisms for Windows and Linux
"""

import os
import platform
import logging
import subprocess
import shutil
from typing import Optional

from .config import PERSISTENCE_ALLOWED

class PersistenceManager:
    """
    Manages persistence on the host system.
    Supports:
    - Windows: Registry (HKCU Run)
    - Linux: Cron, Systemd (User)
    """

    def __init__(self, allow_persistence: Optional[bool] = None):
        self.logger = logging.getLogger(__name__)
        self._allowed = PERSISTENCE_ALLOWED if allow_persistence is None else allow_persistence

    @property
    def is_allowed(self) -> bool:
        return self._allowed

    def install_persistence(self) -> bool:
        """
        Install persistence on the current system.
        Returns True if successful.
        """
        if not self._allowed:
            self.logger.warning("Persistence blocked by policy (set SECURECOMM_ENABLE_PERSISTENCE=true for authorized labs)")
            return False
        system = platform.system()
        try:
            if system == "Windows":
                return self._install_windows()
            elif system == "Linux":
                return self._install_linux()
            else:
                self.logger.warning(f"Persistence not supported on {system}")
                return False
        except Exception as e:
            self.logger.error(f"Failed to install persistence: {e}")
            return False

    def _install_windows(self) -> bool:
        """Install Windows persistence via Registry"""
        try:
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            app_name = "SecureCommAgent"
            exe_path = os.path.abspath(__file__) # Note: In real usage, this should be the executable path

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, exe_path)
            
            self.logger.info("✅ Windows persistence installed via Registry")
            return True
        except ImportError:
            self.logger.error("winreg module not found (not on Windows?)")
            return False
        except Exception as e:
            self.logger.error(f"Windows persistence failed: {e}")
            return False

    def _install_linux(self) -> bool:
        """Install Linux persistence via Cron and/or Systemd"""
        success = False
        
        # Method 1: Cron
        try:
            script_path = os.path.abspath(__file__) # Needs to be fixed to point to actual entry point in integration
            cron_entry = f"@reboot {script_path}\n"
            
            # Check if crontab exists
            current_cron = subprocess.run("crontab -l", shell=True, capture_output=True, text=True).stdout
            
            if script_path not in current_cron:
                # Add to cron
                cmd = f'(crontab -l 2>/dev/null; echo "{cron_entry}") | crontab -'
                subprocess.run(cmd, shell=True, check=True)
                self.logger.info("✅ Linux persistence installed via Cron")
                success = True
            else:
                self.logger.info("Persistence already exists in Cron")
                success = True
                
        except Exception as e:
            self.logger.warning(f"Cron persistence failed: {e}")

        # Method 2: Systemd (User) - Optional enhancement
        # (Could look into ~/.config/systemd/user/)
        
        return success

    def remove_persistence(self) -> bool:
        """Remove persistence"""
        if not self._allowed:
            self.logger.warning("Persistence removal blocked by policy")
            return False
        system = platform.system()
        try:
            if system == "Windows":
                return self._remove_windows()
            if system == "Linux":
                return self._remove_linux()
            self.logger.warning("Persistence removal not supported on %s", system)
            return False
        except Exception as e:
            self.logger.error("Failed to remove persistence: %s", e)
            return False

    def _remove_windows(self) -> bool:
        """Remove Windows persistence via Registry"""
        try:
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            app_name = "SecureCommAgent"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                try:
                    winreg.DeleteValue(key, app_name)
                except FileNotFoundError:
                    self.logger.info("Windows persistence entry not found")
                    return True
            self.logger.info("✅ Windows persistence removed")
            return True
        except ImportError:
            self.logger.error("winreg module not found (not on Windows?)")
            return False
        except Exception as e:
            self.logger.error(f"Windows persistence removal failed: {e}")
            return False

    def _remove_linux(self) -> bool:
        """Remove Linux persistence via Cron"""
        try:
            script_path = os.path.abspath(__file__)
            current_cron = subprocess.run("crontab -l", shell=True, capture_output=True, text=True).stdout
            if script_path not in current_cron:
                self.logger.info("Linux persistence entry not found")
                return True
            filtered = "\n".join(
                line for line in current_cron.splitlines() if script_path not in line
            )
            if filtered:
                subprocess.run("crontab -", shell=True, input=f"{filtered}\n", text=True, check=True)
            else:
                subprocess.run("crontab -", shell=True, input="", text=True, check=True)
            self.logger.info("✅ Linux persistence removed from Cron")
            return True
        except Exception as e:
            self.logger.warning(f"Cron persistence removal failed: {e}")
            return False
