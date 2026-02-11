#!/usr/bin/env python3
"""
SecureComm - Unified Launcher
One-click deployment for all SecureComm components

Author: Shadow Junior (Bhanu Guragain)
"""

import argparse
import sys
import os
import logging
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from securecomm.pki_manager import PKIManager
from securecomm.crypto_engine import CryptoEngine
from securecomm.operator import OperatorConsole
from securecomm.agent import SecureAgent
from securecomm.config import (
    DASHBOARD_HOST,
    DASHBOARD_PORT,
    DASHBOARD_REFRESH_SECONDS,
    DASHBOARD_TOKEN,
)
from securecomm.dashboard_server import run_dashboard

# ASCII Art Banner
BANNER = """
██████╗ ███████╗ ██████╗██╗   ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ███╗███╗   ███╗
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ████║████╗ ████║
███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ██║     ██║   ██║██╔████╔██║██╔████╔██║
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╔╝██║██║╚██╔╝██║
███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚═╝ ██║██║ ╚═╝ ██║
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚═╝
                                                                                    v1.0
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║  🔐 Military-Grade Encrypted C2 Framework for Red Team Operations                     ║
║  👤 Author: Shadow Junior (Bhanu Guragain) | ST6051CEM Practical Cryptography         ║
╚═══════════════════════════════════════════════════════════════════════════════════════╝
"""

def setup_logging(verbose: bool = False):
    """Configure logging"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def init_pki(args):
    """Initialize PKI infrastructure"""
    print(BANNER)
    print("🔐 Initializing PKI Infrastructure...\n")
    
    pki = PKIManager(args.pki_path)
    
    # Generate Root CA
    print("📜 Generating Root CA...")
    ca_cert, ca_key = pki.generate_root_ca(
        common_name=args.ca_name,
        validity_days=3650
    )
    
    print(f"\n✅ PKI initialized at: {args.pki_path}")
    print(f"   CA Certificate: {args.pki_path}/ca/ca_root.crt")
    print(f"   CA Private Key: {args.pki_path}/ca/ca_root.key")

def issue_cert(args):
    """Issue a certificate"""
    print(BANNER)
    print(f"📜 Issuing certificate for: {args.common_name}\n")
    
    pki = PKIManager(args.pki_path)
    cert, key = pki.issue_certificate(
        common_name=args.common_name,
        cert_type=args.type,
        validity_days=args.validity
    )
    
    print(f"\n✅ Certificate issued successfully!")

def start_operator(args):
    """Start operator console"""
    print(BANNER)
    print("🎮 Starting Operator Console...\n")
    
    console = OperatorConsole(
        cert_path=args.cert,
        key_path=args.key,
        ca_cert_path=args.ca_cert,
        host=args.host,
        port=args.port,
    )
    
    try:
        console.cmdloop()
    except KeyboardInterrupt:
        print("\n🛑 Operator console stopped")

def start_agent(args):
    """Start agent"""
    print(BANNER)
    print(f"🤖 Starting Agent: {args.agent_id}\n")
    print(f"   Server: {args.server}:{args.port}")

    agent_cert_path = args.agent_cert or f"data/pki/agents/{args.agent_id}.crt"
    agent_key_path = args.agent_key or f"data/pki/agents/{args.agent_id}.key"
    if not Path(agent_cert_path).exists() or not Path(agent_key_path).exists():
        print("❌ Agent certificate or key not found.")
        print(f"   Expected cert: {agent_cert_path}")
        print(f"   Expected key:  {agent_key_path}")
        return
    
    agent = SecureAgent(
        agent_id=args.agent_id,
        ca_cert_path=args.ca_cert,
        agent_cert_path=agent_cert_path,
        agent_key_path=agent_key_path,
        server_host=args.server,
        server_port=args.port
    )
    
    try:
        agent.run()
    except KeyboardInterrupt:
        print("\n🛑 Agent stopped")
        agent.stop()

def run_tests(args):
    """Run test suite"""
    print(BANNER)
    print("🧪 Running SecureComm Test Suite...\n")
    
    import subprocess
    cmd = ["python", "-m", "pytest", "tests/", "-v"]
    
    if args.coverage:
        cmd.extend(["--cov=src/securecomm", "--cov-report=html"])
    
    subprocess.run(cmd)


def start_dashboard(args):
    """Start dashboard server"""
    print(BANNER)
    print("📊 Starting SecureComm Dashboard...\n")
    print(f"   Host: {args.host}")
    print(f"   Port: {args.port}")
    print(f"   Refresh: {args.refresh}s")
    if args.token:
        print("   Auth: Token required")
    else:
        print("   Auth: Disabled (set SECURECOMM_DASHBOARD_TOKEN to enable)")

    run_dashboard(
        host=args.host,
        port=args.port,
        refresh_seconds=args.refresh,
        token=args.token,
    )

def show_status(args):
    """Show system status"""
    print(BANNER)
    print("📊 SecureComm System Status\n")
    print("=" * 60)
    
    # Check PKI
    pki_path = Path(args.pki_path)
    ca_exists = (pki_path / "ca" / "ca_root.crt").exists()
    print(f"PKI Initialized:    {'✅ Yes' if ca_exists else '❌ No'}")
    
    if ca_exists:
        pki = PKIManager(args.pki_path)
        certs = pki.list_certificates()
        print(f"Issued Certificates: {len(certs)}")
        
        for cert in certs:
            status = "🟢 Active" if not cert.get('revoked') else "🔴 Revoked"
            print(f"  - {cert['common_name']} ({cert['type']}) {status}")
    
    print("=" * 60)
    
    # Check components
    components = [
        ("pki_manager.py", "PKI Manager"),
        ("crypto_engine.py", "Crypto Engine"),
        ("network.py", "Network Manager"),
        ("operator.py", "Operator Console"),
        ("agent.py", "Agent"),
        ("session.py", "Session Manager"),
        ("security.py", "Security Module"),
        ("persistence.py", "Persistence Manager"),
        ("stealth.py", "Stealth Manager"),
        ("audit.py", "Audit Logger"),
        ("config.py", "Configuration"),
    ]
    
    print("\n📦 Components:")
    src_path = Path("src/securecomm")
    for filename, name in components:
        exists = (src_path / filename).exists()
        print(f"  {'✅' if exists else '❌'} {name}")
    
    print("\n🔐 Cryptographic Features:")
    features = [
        ("ECDH X25519 Key Exchange", True),
        ("AES-256-GCM Encryption", True),
        ("Ed25519 Digital Signatures", True),
        ("HKDF Key Derivation", True),
        ("X.509 Certificates", True),
        ("Perfect Forward Secrecy", True),
        ("MITM Prevention", True),
        ("Replay Attack Prevention", True),
        ("Rate Limiting", True),
    ]
    for name, implemented in features:
        print(f"  {'✅' if implemented else '❌'} {name}")

def main():
    parser = argparse.ArgumentParser(
        description="SecureComm - Red Team Encrypted C2 Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Initialize PKI
  python launcher.py init-pki --ca-name "SecureComm CA"
  
  # Issue operator certificate
  python launcher.py issue-cert --common-name admin --type operator
  
  # Start operator console
  python launcher.py operator --cert data/pki/operators/admin.crt --key data/pki/operators/admin.key
  
  # Start agent
  python launcher.py agent --agent-id AGT001 --server 192.168.1.100
  
  # Run tests
  python launcher.py test --coverage
  
  # Show status
  python launcher.py status
"""
    )
    
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # init-pki command
    pki_parser = subparsers.add_parser('init-pki', help='Initialize PKI infrastructure')
    pki_parser.add_argument('--pki-path', default='data/pki', help='PKI data path')
    pki_parser.add_argument('--ca-name', default='SecureComm Root CA', help='CA common name')
    pki_parser.set_defaults(func=init_pki)
    
    # issue-cert command
    cert_parser = subparsers.add_parser('issue-cert', help='Issue a certificate')
    cert_parser.add_argument('--pki-path', default='data/pki', help='PKI data path')
    cert_parser.add_argument('--common-name', required=True, help='Certificate common name')
    cert_parser.add_argument('--type', choices=['operator', 'agent'], default='operator', help='Certificate type')
    cert_parser.add_argument('--validity', type=int, default=365, help='Validity in days')
    cert_parser.set_defaults(func=issue_cert)
    
    # operator command
    op_parser = subparsers.add_parser('operator', help='Start operator console')
    op_parser.add_argument('--cert', required=True, help='Operator certificate')
    op_parser.add_argument('--key', required=True, help='Operator private key')
    op_parser.add_argument('--ca-cert', default='data/pki/ca/ca_root.crt', help='CA certificate')
    op_parser.add_argument('--host', default='0.0.0.0', help='Listen host')
    op_parser.add_argument('--port', type=int, default=8443, help='Listen port')
    op_parser.set_defaults(func=start_operator)
    
    # agent command
    agent_parser = subparsers.add_parser('agent', help='Start agent')
    agent_parser.add_argument('--agent-id', required=True, help='Agent identifier')
    agent_parser.add_argument('--server', required=True, help='Operator server address')
    agent_parser.add_argument('--port', type=int, default=8443, help='Server port')
    agent_parser.add_argument('--ca-cert', default='data/pki/ca/ca_root.crt', help='CA certificate')
    agent_parser.add_argument('--agent-cert', help='Agent certificate (defaults to data/pki/agents/<agent_id>.crt)')
    agent_parser.add_argument('--agent-key', help='Agent private key (defaults to data/pki/agents/<agent_id>.key)')
    agent_parser.set_defaults(func=start_agent)
    
    # test command
    test_parser = subparsers.add_parser('test', help='Run test suite')
    test_parser.add_argument('--coverage', action='store_true', help='Generate coverage report')
    test_parser.set_defaults(func=run_tests)
    
    # status command
    status_parser = subparsers.add_parser('status', help='Show system status')
    status_parser.add_argument('--pki-path', default='data/pki', help='PKI data path')
    status_parser.set_defaults(func=show_status)

    # dashboard command
    dashboard_parser = subparsers.add_parser('dashboard', help='Start dashboard server')
    dashboard_parser.add_argument('--host', default=DASHBOARD_HOST, help='Dashboard host')
    dashboard_parser.add_argument('--port', type=int, default=DASHBOARD_PORT, help='Dashboard port')
    dashboard_parser.add_argument(
        '--refresh',
        type=int,
        default=DASHBOARD_REFRESH_SECONDS,
        help='Dashboard refresh interval (seconds)'
    )
    dashboard_parser.add_argument(
        '--token',
        default=DASHBOARD_TOKEN,
        help='Dashboard API token (overrides SECURECOMM_DASHBOARD_TOKEN)'
    )
    dashboard_parser.set_defaults(func=start_dashboard)
    
    args = parser.parse_args()
    
    if args.command is None:
        print(BANNER)
        parser.print_help()
        return
    
    setup_logging(args.verbose)
    args.func(args)

if __name__ == "__main__":
    main()
