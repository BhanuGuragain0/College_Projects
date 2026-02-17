#!/usr/bin/env python3
"""
SecureComm PKI Setup Script
Generates Root CA and initial operator/agent certificates

Usage:
    python scripts/generate_ca.py [--password CA_PASSWORD]

Author: Shadow Junior
"""

import argparse
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.securecomm.pki_manager import PKIManager


def main():
    parser = argparse.ArgumentParser(
        description='Generate SecureComm PKI infrastructure'
    )
    parser.add_argument(
        '--password',
        help='Password to encrypt CA private key',
        default=None
    )
    parser.add_argument(
        '--pki-path',
        help='Path to PKI directory',
        default='data/pki'
    )
    parser.add_argument(
        '--operator',
        help='Operator common name',
        default='admin'
    )
    parser.add_argument(
        '--agent',
        help='Agent common name',
        default='agent001'
    )
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("🔥 SecureComm PKI Setup 🔥")
    print("=" * 70)
    print()
    
    # Initialize PKI Manager
    pki = PKIManager(pki_path=args.pki_path)
    
    # Generate Root CA
    print("1. Generating Root CA...")
    print("-" * 50)
    
    password = args.password.encode() if args.password else None
    ca_cert, ca_key = pki.generate_root_ca(
        common_name="SecureComm Root CA",
        validity_days=3650,
        password=password
    )
    print()
    
    # Issue Operator Certificate
    print("2. Issuing Operator Certificate...")
    print("-" * 50)
    
    op_cert, op_key = pki.issue_certificate(
        common_name=args.operator,
        cert_type="operator",
        validity_days=365,
        ca_password=password
    )
    print()
    
    # Issue Agent Certificate
    print("3. Issuing Agent Certificate...")
    print("-" * 50)
    
    agent_cert, agent_key = pki.issue_certificate(
        common_name=args.agent,
        cert_type="agent",
        validity_days=365,
        ca_password=password
    )
    print()
    
    # Print summary
    print("=" * 70)
    print("✅ PKI Setup Complete!")
    print("=" * 70)
    print()
    print("Generated Files:")
    print(f"  CA Certificate: {args.pki_path}/ca/ca_root.crt")
    print(f"  CA Private Key: {args.pki_path}/ca/ca_root.key")
    print(f"  Operator Cert:  {args.pki_path}/operators/{args.operator}.crt")
    print(f"  Operator Key:   {args.pki_path}/operators/{args.operator}.key")
    print(f"  Agent Cert:     {args.pki_path}/agents/{args.agent}.crt")
    print(f"  Agent Key:      {args.pki_path}/agents/{args.agent}.key")
    print()
    print("Next Steps:")
    print("  1. Start operator: python -m src.securecomm.operator")
    print("  2. Start agent: python -m src.securecomm.agent")
    print("  3. Start dashboard: python -m src.securecomm.dashboard_server")
    print()


if __name__ == "__main__":
    main()
