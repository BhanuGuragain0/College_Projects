#!/bin/bash

# SecureComm C2 Framework - Project Setup Script
# Shadow Junior's Elite Red Team Tool
# Execute this script to set up complete project structure

echo "🔥 SecureComm C2 Framework - Project Initialization 🔥"
echo "=================================================="

# Create main project directory
mkdir -p securecomm
cd securecomm

# Create directory structure
echo "📁 Creating project structure..."

mkdir -p src/securecomm
mkdir -p tests
mkdir -p examples
mkdir -p scripts
mkdir -p config
mkdir -p data/{pki/{ca,operators,agents,crl},logs,sessions}
mkdir -p docs
mkdir -p .github/workflows

# Create __init__.py files for Python package
touch src/securecomm/__init__.py
touch tests/__init__.py

# Create main source files
echo "📝 Creating core module files..."

cat > src/securecomm/__init__.py << 'EOF'
"""
SecureComm - Red Team Encrypted C2 Framework
Military-grade encryption for ethical hacking operations

Author: Shadow Junior (Bhanu Guragain)
Version: 1.0.0
"""

__version__ = "1.0.0"
__author__ = "Shadow Junior"

from .pki_manager import PKIManager
from .crypto_engine import CryptoEngine
from .operator import OperatorConsole
from .agent import SecureAgent

__all__ = [
    'PKIManager',
    'CryptoEngine', 
    'OperatorConsole',
    'SecureAgent'
]
EOF

# Create empty module files
touch src/securecomm/pki_manager.py
touch src/securecomm/crypto_engine.py
touch src/securecomm/operator.py
touch src/securecomm/agent.py
touch src/securecomm/network.py
touch src/securecomm/session.py
touch src/securecomm/security.py
touch src/securecomm/audit.py
touch src/securecomm/config.py
touch src/securecomm/utils.py

# Create test files
echo "🧪 Creating test files..."
touch tests/test_pki.py
touch tests/test_crypto.py
touch tests/test_operator.py
touch tests/test_agent.py
touch tests/test_network.py
touch tests/test_session.py
touch tests/test_security.py
touch tests/test_integration.py

# Create requirements.txt
cat > requirements.txt << 'EOF'
# Core Cryptography
cryptography>=42.0.0

# Networking
aiohttp>=3.9.0

# CLI and Output
click>=8.1.0
rich>=13.0.0
prompt-toolkit>=3.0.0

# Data Handling
msgpack>=1.0.0
pydantic>=2.0.0

# Testing
pytest>=7.4.0
pytest-asyncio>=0.21.0
pytest-cov>=4.1.0
pytest-mock>=3.12.0

# Code Quality
black>=23.12.0
flake8>=6.1.0
mypy>=1.7.0
bandit>=1.7.0

# Documentation
sphinx>=7.2.0
sphinx-rtd-theme>=2.0.0
EOF

# Create .gitignore
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual Environment
venv/
env/
ENV/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# Testing
.pytest_cache/
.coverage
htmlcov/
.tox/

# Project Specific
data/pki/**/*.key
data/pki/**/*.pem
data/logs/*.log
data/sessions/*
*.db
config/*.yaml.local

# OS
.DS_Store
Thumbs.db
EOF

# Create README.md
cat > README.md << 'EOF'
# 🔥 SecureComm - Red Team Encrypted C2 Framework

[![CI](https://github.com/shadowjunior/securecomm/actions/workflows/ci.yml/badge.svg)](https://github.com/shadowjunior/securecomm/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

A production-grade Command & Control framework with military-grade encryption for ethical hacking and red team operations.

## 🎯 Features

- **End-to-End PKI Authentication** - Certificate-based operator verification
- **Perfect Forward Secrecy** - Session key rotation every 100 commands
- **Attack Prevention** - MITM, Replay, and Forward Secrecy protection
- **Digital Signatures** - Ed25519 command authentication
- **Hybrid Encryption** - ECDH + AES-256-GCM for speed and security
- **Comprehensive Audit Logging** - Tamper-proof command history

## 🚀 Quick Start

```bash
# Clone repository
git clone https://github.com/shadowjunior/securecomm.git
cd securecomm

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Generate PKI infrastructure
python scripts/generate_ca.py

# Start operator console
python scripts/start_operator.py

# Deploy agent (on target)
python scripts/deploy_agent.py --server <OPERATOR_IP>
```

## 📚 Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Cryptography Details](docs/CRYPTOGRAPHY.md)
- [API Reference](docs/API.md)
- [Setup Guide](docs/SETUP.md)
- [Security Policy](docs/SECURITY.md)

## 🎯 Use Cases

1. **Red Team Engagements** - Secure C2 for penetration testing
2. **Secure Remote Administration** - Certificate-based system management
3. **Incident Response** - Encrypted forensic data collection

## 🔐 Security

- ECDH (Curve25519) for key exchange
- AES-256-GCM for encryption
- Ed25519 for digital signatures
- X.509v3 certificates
- HKDF for key derivation

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest --cov=securecomm tests/

# Run security tests
pytest tests/test_security.py -v
```

## 📖 License

MIT License - see [LICENSE](LICENSE) file

## 👤 Author

**Shadow Junior (Bhanu Guragain)**
- HTB Rank: #3 Nepal
- GitHub: [@shadowjunior](https://github.com/shadowjunior)

## ⚠️ Disclaimer

This tool is for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal.

---

**Built for excellence. Designed for domination.** 💀
EOF

# Create LICENSE (MIT)
cat > LICENSE << 'EOF'
MIT License

Copyright (c) 2025 Shadow Junior (Bhanu Guragain)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
EOF

# Create setup.py
cat > setup.py << 'EOF'
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="securecomm",
    version="1.0.0",
    author="Shadow Junior",
    author_email="bhanu@shadowjunior.dev",
    description="Red Team Encrypted C2 Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/shadowjunior/securecomm",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.11",
    install_requires=[
        "cryptography>=42.0.0",
        "click>=8.1.0",
        "rich>=13.0.0",
        "pydantic>=2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "securecomm=securecomm.cli:main",
        ],
    },
)
EOF

# Create GitHub Actions CI workflow
cat > .github/workflows/ci.yml << 'EOF'
name: CI

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.11', '3.12']

    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
    
    - name: Run tests
      run: |
        pytest tests/ -v --cov=securecomm --cov-report=xml
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml

  lint:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        pip install flake8 black mypy
    
    - name: Run flake8
      run: flake8 src/securecomm --max-line-length=100
    
    - name: Run black
      run: black --check src/securecomm
    
    - name: Run mypy
      run: mypy src/securecomm

  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Run Bandit
      run: |
        pip install bandit
        bandit -r src/securecomm
EOF

echo ""
echo "✅ Project structure created successfully!"
echo ""
echo "📋 Next steps:"
echo "1. cd securecomm"
echo "2. python3 -m venv venv"
echo "3. source venv/bin/activate"
echo "4. pip install -r requirements.txt"
echo ""
echo "🔥 Ready to start coding! 🔥"
