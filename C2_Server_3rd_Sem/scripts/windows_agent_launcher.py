#!/usr/bin/env python3
"""
Windows Agent Launcher for SecureComm C2
Quick start script for Windows VM deployment
"""
import os
import sys
import argparse
import subprocess

def generate_windows_agent():
    """Generate Windows executable using PyInstaller"""
    print("[+] Generating Windows agent executable...")
    
    # Check if pyinstaller is installed
    try:
        import PyInstaller
    except ImportError:
        print("[*] Installing PyInstaller...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)
    
    # Build command
    cmd = [
        "pyinstaller",
        "--onefile",
        "--name", "securecomm_agent",
        "--clean",
        "--noconfirm",
        "launcher.py"
    ]
    
    print(f"[+] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0:
        print("[+] Agent executable generated successfully!")
        print("[+] Location: dist/securecomm_agent.exe")
        return True
    else:
        print(f"[-] Error: {result.stderr}")
        return False

def create_agent_config(agent_id, server_ip, port=8443):
    """Create agent configuration file"""
    config = f"""{{
    "agent_id": "{agent_id}",
    "server": "{server_ip}",
    "port": {port},
    "beacon_interval": 60,
    "jitter": 0.3,
    "timeout": 300,
    "max_retries": 3,
    "platform": "windows"
}}"""
    
    config_path = f"payloads/agent_config_{agent_id}.json"
    with open(config_path, 'w') as f:
        f.write(config)
    
    print(f"[+] Configuration saved to: {config_path}")
    return config_path

def main():
    parser = argparse.ArgumentParser(description="Windows Agent Generator")
    parser.add_argument("--generate", action="store_true", help="Generate Windows executable")
    parser.add_argument("--config", action="store_true", help="Create agent configuration")
    parser.add_argument("--agent-id", default="agent_windows_01", help="Agent ID")
    parser.add_argument("--server", default="192.168.1.100", help="C2 Server IP")
    parser.add_argument("--port", type=int, default=8443, help="C2 Server port")
    
    args = parser.parse_args()
    
    if args.generate:
        generate_windows_agent()
    
    if args.config:
        create_agent_config(args.agent_id, args.server, args.port)
    
    if not args.generate and not args.config:
        print("Usage:")
        print("  python windows_agent_launcher.py --generate        # Build executable")
        print("  python windows_agent_launcher.py --config --server 192.168.1.100  # Create config")
        print("  python windows_agent_launcher.py --generate --config --server 192.168.1.100")

if __name__ == "__main__":
    main()
