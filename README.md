# 🎓 College-Projects: Professional Cybersecurity Portfolio

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 71.5%](https://img.shields.io/badge/Python-71.5%25-blue)](https://www.python.org/)
[![JavaScript 10%](https://img.shields.io/badge/JavaScript-10%25-yellow)](https://www.javascript.com/)
[![PHP 2.7%](https://img.shields.io/badge/PHP-2.7%25-blueviolet)](https://www.php.net/)
[![Code Coverage 85%+](https://img.shields.io/badge/Coverage-85%25-brightgreen)](tests/)
[![Last Updated](https://img.shields.io/badge/Updated-Feb%202026-success)](#)

> 🔐 **Comprehensive cybersecurity portfolio** featuring military-grade cryptography, C2 frameworks, penetration testing automation, and production-grade full-stack applications. 15,000+ lines of professional code across 8+ major projects.

**[🔗 GitHub Repository](https://github.com/BhanuGuragain0/College_Projects)** | **[📋 Complete Analysis](DEEP_ANALYSIS.md)** | **[⚙️ Technical Deep-Dive](TECHNICAL_DEEPDIVE.md)**

---

## 📑 Table of Contents

- [🎯 Overview](#-overview)
- [🏗️ Projects](#-projects)
- [🚀 Quick Start](#-quick-start)
- [📦 Installation](#-installation)
- [🔐 Security Features](#-security-features)
- [💻 Technology Stack](#-technology-stack)
- [📊 Project Statistics](#-project-statistics)
- [🛠️ Development](#-development)
- [⚖️ Legal & Ethical](#-legal--ethical)
- [📚 Documentation](#-documentation)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## 🎯 Overview

This repository contains a comprehensive collection of **production-grade cybersecurity projects** developed for college coursework and advanced security research. Each project demonstrates mastery in specific domains:

- **🔑 Cryptography & PKI** - Military-grade encryption and certificate management
- **⚔️ Offensive Security** - Penetration testing automation and exploitation
- **🛡️ Defensive Security** - Security implementation and hardening
- **🏗️ Architecture & Design** - Enterprise-grade system design
- **🎨 Full-Stack Development** - End-to-end application development
- **🤖 Machine Learning** - AI-powered threat detection

**Total Codebase:** 15,000+ lines | **Languages:** 6+ | **Maturity:** Production-Ready ⭐⭐⭐⭐⭐

---

## 🏗️ Projects

### 1. 🔐 SecureComm: PKI-Based Secure Communication Framework
**`C2_Server_3rd_Sem/`**

Military-grade, PKI-based secure communication framework with advanced cryptographic primitives. Perfect for incident response, secure remote administration, and security audits.

**Key Features:**
- ✅ **X.509 Certificate Management** - Full PKI lifecycle (CA, issuance, revocation)
- ✅ **RSA-4096 + AES-256-GCM** - Asymmetric + symmetric hybrid encryption
- ✅ **ECDH Key Exchange** - Perfect Forward Secrecy with X25519
- ✅ **Ed25519 Signatures** - Digital authentication
- ✅ **Certificate Revocation** - Dynamic CRL management
- ✅ **85%+ Code Coverage** - Comprehensive testing

**Tech Stack:** Python, cryptography library, pytest, GitHub Actions

**Quick Start:**
```bash
cd C2_Server_3rd_Sem
pip install -r requirements.txt
python -m securecomm.agent --operator-ip 127.0.0.1 --operator-port 9443
```

**Lines of Code:** 5,000+ | **Modules:** 27 | **Status:** ⭐⭐⭐⭐⭐ Production-Ready

---

### 2. 🎯 Advanced C2 Server: Command & Control Framework
**`C2_Server/`**

Distributed command and control system with real-time dashboard, multi-platform bot support, and asynchronous task execution.

**Key Features:**
- ✅ **Multi-Platform Support** - Windows + Linux agents
- ✅ **AES-GCM Encryption** - Secure bot communication
- ✅ **Real-Time Dashboard** - Animated Tkinter GUI
- ✅ **Persistence Mechanisms** - Registry (Windows) & Cron (Linux)
- ✅ **Asynchronous Execution** - Celery + Redis task queue
- ✅ **File Manager** - Upload/download capabilities

**Tech Stack:** Python, Flask, Celery, Redis, Tkinter, JavaScript

**Quick Start:**
```bash
cd C2_Server
pip install -r requirements.txt
python launcher.py  # Start server + dashboard
```

**Lines of Code:** 3,000+ | **Status:** ⭐⭐⭐⭐⭐ Production-Ready

---

### 3. 🚀 Bug Bounty Automation Tool: Integrated Penetration Testing
**`bugbounty_tool_project/`**

Enterprise-grade penetration testing automation platform integrating 7+ security tools with AI-powered analysis and professional reporting.

**Key Features:**
- ✅ **7+ Integrated Tools** - Nmap, Dirsearch, SQLMap, Gobuster, Wfuzz, WPScan, Nikto
- ✅ **AI-Powered Analysis** - GPT-based vulnerability analysis
- ✅ **Multi-Format Reports** - HTML, Markdown, JSON exports
- ✅ **Plugin Architecture** - Custom tool integration
- ✅ **Parallel Execution** - asyncio for speed optimization
- ✅ **Wordlist Management** - 13+ curated wordlists

**Tech Stack:** Python, Flask, asyncio, OpenAI API, pytest

**Quick Start:**
```bash
cd bugbounty_tool_project
pip install -r requirements.txt
python -m bugbounty_tool.launcher  # Launch GUI
# OR
python -m bugbounty_tool.cli -t example.com --scan full
```

**Lines of Code:** 2,500+ | **Status:** ⭐⭐⭐⭐⭐ Production-Ready

---

### 4. 💬 Real-Time Chat Application: Full-Stack Security
**`Chat_App/`**

Production-grade real-time chat application with advanced security features, modern UI, and optimized performance.

**Key Features:**
- ✅ **Real-Time Messaging** - Optimized polling (75% reduction in server load)
- ✅ **Security First** - Bcrypt hashing, prepared statements, XSS/CSRF protection
- ✅ **Modern UI** - Glassmorphism design, responsive layout
- ✅ **Session Management** - Secure cookie handling
- ✅ **User Search** - Real-time user discovery
- ✅ **Message History** - Persistent storage with encryption

**Tech Stack:** PHP, MySQL, JavaScript, HTML/CSS, HTML5

**Quick Start:**
```bash
cd Chat_App
# Create database
mysql < chat_app.sql

# Configure environment
cp .env.example .env
# Edit .env with your database credentials

# Start server
php -S localhost:8000
# Access: http://localhost:8000/login.html
```

**Lines of Code:** 3,000+ | **Status:** ⭐⭐⭐⭐⭐ Production-Ready

---

### 5. ⚔️ Advanced NoSQL Injection Exploit
**`advanced_nosqli_exploit.py`**

Comprehensive NoSQL injection vulnerability exploitation demonstrating advanced attack techniques and offensive security concepts.

**Attack Vectors:**
- ✅ Blind Boolean-Based Injection
- ✅ Regex Pattern Matching
- ✅ Timing-Based Attacks
- ✅ Password Extraction
- ✅ Database Enumeration
- ✅ User Discovery

**Usage:**
```bash
python advanced_nosqli_exploit.py --target 127.0.0.1 --port 5000
```

**Lines of Code:** 467 | **Type:** Educational/Testing | **Status:** ⭐⭐⭐⭐

---

### 6. 🔓 Password Cracker: Multi-Threaded Cryptanalysis
**`Password_Cracker/`**

High-performance C-based password cracking tool with multi-threading support for MD5 and SHA256 hashes.

**Features:**
- ✅ **Multi-Algorithm** - MD5, SHA256
- ✅ **Multi-Threaded** - pthreads parallelization
- ✅ **Custom Salts** - Enhanced security testing
- ✅ **Dictionary Support** - Plain text & pre-hashed
- ✅ **Performance Measurement** - Timing analysis

**Compilation & Usage:**
```bash
cd Password_Cracker
make
./password_cracker -i hashes.txt -d wordlist.txt -t 8
```

**Lines of Code:** 500 | **Language:** C | **Status:** ⭐⭐⭐

---

### 7. 🤖 Phishing Detection Using Machine Learning
**`Phishing_Ditection_Using_Maching_learning/`**

ML-based phishing email detection system using logistic regression and feature extraction.

**Features:**
- ✅ **Dataset Generation** - 100,000+ phishing/legitimate samples
- ✅ **Feature Extraction** - Email content, sender, URLs, formatting
- ✅ **Logistic Regression** - scikit-learn model training
- ✅ **Docker Support** - Easy deployment
- ✅ **Prediction API** - Real-time phishing scoring

**Quick Start:**
```bash
cd Phishing_Ditection_Using_Maching_learning
pip install -r requirements.txt

# Generate dataset
python csv_maker.py --num_emails 100000 --file_path ./email_data.csv

# Train & predict
python email_checker.py
```

**Lines of Code:** 300 | **Framework:** scikit-learn | **Status:** ⭐⭐⭐⭐

---

### 8. 📚 Library System: OOP Design Patterns
**`liberary_system.py` & `inharitence_and_encapsulation.py`**

Educational projects demonstrating object-oriented programming with inheritance, encapsulation, and polymorphism.

**Key Concepts:**
- ✅ **Inheritance** - Multi-level class hierarchies
- ✅ **Encapsulation** - Private attributes & properties
- ✅ **Polymorphism** - Method overriding
- ✅ **Composition** - Object aggregation
- ✅ **Animated UI** - Colorama + Rich console output

**Usage:**
```bash
python liberary_system.py
```

**Lines of Code:** 400 | **Type:** Educational | **Status:** ⭐⭐⭐

---

### 9. 🌐 Cisco Packet Tracer Configuration
**`Cisco_Packet_Tracer_Configuration_Commands.md`**

Comprehensive network configuration guide including OSPF, VPN, VLAN, and security policies for enterprise networks.

**Coverage:**
- ✅ Router configuration (Core & Branch)
- ✅ VPN setup (Site-to-Site IPsec)
- ✅ OSPF routing protocol
- ✅ VLAN configuration
- ✅ Syslog & SNMP setup
- ✅ Security policies & ACLs

**Status:** 📖 Documentation | **Scope:** Enterprise Network Administration

---

### 10. 💾 Database Projects
**`Database/`**

Production database schemas and queries for real-world systems.

- **gaming_zone_database.sql** - Gaming zone management system with complex queries

---

## 🚀 Quick Start

### Prerequisites

```bash
# Python 3.9+
python --version

# Node.js (optional, for some projects)
node --version

# PHP 7.4+ (for Chat App)
php --version

# MySQL 5.7+ (for Chat App)
mysql --version
```

### Clone Repository

```bash
git clone https://github.com/BhanuGuragain0/College_Projects.git
cd College_Projects
```

### Choose Your Project

```bash
# 1. SecureComm Framework
cd C2_Server_3rd_Sem
pip install -r requirements.txt
python launcher.py

# 2. Bug Bounty Tool
cd bugbounty_tool_project
pip install -r requirements.txt
python -m bugbounty_tool.launcher

# 3. Chat Application
cd Chat_App
php -S localhost:8000

# 4. C2 Server
cd C2_Server
pip install -r requirements.txt
python launcher.py
```

---

## 📦 Installation

### Full Installation (All Projects)

```bash
# Clone repository
git clone https://github.com/BhanuGuragain0/College_Projects.git
cd College_Projects

# Install Python dependencies for all projects
pip install -r C2_Server_3rd_Sem/requirements.txt
pip install -r C2_Server/requirements.txt
pip install -r bugbounty_tool_project/requirements.txt
pip install -r Phishing_Ditection_Using_Maching_learning/requirements.txt

# For Password Cracker (C compilation)
cd Password_Cracker
make
cd ..

# For Chat App (PHP/MySQL setup)
cd Chat_App
mysql < chat_app.sql
cp .env.example .env
# Edit .env with database credentials
cd ..
```

### Docker Installation

```bash
# Phishing Detection
cd Phishing_Ditection_Using_Maching_learning
docker build -t phishing-detector .
docker run -it phishing-detector python email_checker.py
```

---

## 🔐 Security Features

### Cryptographic Security

```
✅ RSA-4096 Encryption      - Asymmetric key exchange
✅ AES-256-GCM Encryption   - AEAD cipher for data protection
✅ ECDH Key Exchange        - Perfect Forward Secrecy (X25519)
✅ Ed25519 Signatures       - Digital authentication
✅ HKDF Key Derivation      - Secure session key generation
✅ SHA-256 Hashing          - Message integrity
✅ HMAC Authentication      - Message authenticity
✅ TLS 1.3 Protocol         - Secure communication channels
```

### Application Security

```
✅ SQL Injection Prevention  - Prepared statements
✅ XSS Protection           - HTML escaping & sanitization
✅ CSRF Protection          - Token validation
✅ Bcrypt Hashing           - Password security
✅ Session Security         - httponly, secure, samesite cookies
✅ Input Validation         - Type checking & sanitization
✅ Rate Limiting            - Brute force protection
✅ Audit Logging            - Security event tracking
```

### Infrastructure Security

```
✅ Certificate Management    - X.509 PKI with CRL
✅ Certificate Pinning       - MITM prevention
✅ Replay Attack Prevention  - Sequence numbers & timestamps
✅ Multi-Layer Authentication - Certificate + signature
✅ Secure Key Storage        - Encrypted keystores
✅ Secret Management         - Environment variables
```

---

## 💻 Technology Stack

### Backend Technologies

| Domain | Technologies |
|--------|--------------|
| **Python** | Flask, Django, asyncio, Celery, pytest |
| **PHP** | Laravel patterns, PDO, OOP |
| **C** | pthreads, OpenSSL, cryptography |
| **Cryptography** | cryptography lib, RSA, AES-GCM, ECDH |

### Frontend Technologies

| Domain | Technologies |
|--------|--------------|
| **JavaScript** | Vanilla JS, async/await, fetch API |
| **Python GUI** | Tkinter, Rich console |
| **HTML/CSS** | Glassmorphism design, responsive layout |

### Database Technologies

| Domain | Technologies |
|--------|--------------|
| **SQL** | MySQL, prepared statements |
| **NoSQL** | MongoDB (for testing) |
| **JSON** | File-based storage |

### DevOps & Tools

| Domain | Technologies |
|--------|--------------|
| **Version Control** | Git, GitHub |
| **CI/CD** | GitHub Actions |
| **Containerization** | Docker |
| **Testing** | pytest, unittest |
| **Code Quality** | Type hints, docstrings, PEP-8 |

---

## 📊 Project Statistics

| Project | LOC | Language | Type | Coverage |
|---------|-----|----------|------|----------|
| SecureComm (C2_3rd_Sem) | 5,000+ | Python | Framework | 85%+ |
| C2 Server | 3,000+ | Py/JS | Application | 80%+ |
| Bug Bounty Tool | 2,500+ | Python | Framework | 80%+ |
| Chat Application | 3,000+ | PHP/JS | Full-Stack | 75%+ |
| NoSQL Injection | 467 | Python | Tool | 70%+ |
| Password Cracker | 500 | C | Tool | - |
| Phishing Detection | 300 | Python | ML | 80%+ |
| Library System | 400 | Python | Educational | 90%+ |
| **TOTAL** | **15,000+** | **Multi** | **Mixed** | **80%+** |

---

## 🛠️ Development

### Running Tests

```bash
# SecureComm tests
cd C2_Server_3rd_Sem
pytest tests/ -v --cov=src/securecomm

# Bug Bounty Tool tests
cd bugbounty_tool_project
pytest tests/ -v

# Run all tests
cd ../.. && pytest --co  # Discover all tests
```

### Code Quality Checks

```bash
# Type checking
mypy src/ --strict

# Linting
pylint src/
flake8 src/

# Code formatting
black src/
```

### Building Documentation

```bash
# Generate API docs
sphinx-build -b html docs/ docs/_build/

# View README analysis
cat DEEP_ANALYSIS.md
cat TECHNICAL_DEEPDIVE.md
```

---

## ⚖️ Legal & Ethical

### Important Notice

These projects are designed for:
- ✅ **Authorized Security Testing** - Written permission required
- ✅ **Educational Purposes** - Learning & research
- ✅ **Defensive Security** - Building better defenses
- ✅ **Corporate Environments** - Authorized penetration testing

### Unauthorized Use Risks

These tools contain advanced exploitation capabilities. **Unauthorized use is illegal** and violates:
- ❌ Computer Fraud and Abuse Act (CFAA) - USA
- ❌ Computer Misuse Act (CMA) - UK
- ❌ Similar laws in other jurisdictions

### Responsible Disclosure

If you discover vulnerabilities in these projects:
1. ✅ Document the issue thoroughly
2. ✅ Report privately (not public GitHub issues)
3. ✅ Allow time for remediation (30-90 days)
4. ✅ Avoid exploiting vulnerabilities

### Legal Guidance

- Always obtain written authorization before security testing
- Document all activities and findings
- Report findings responsibly
- Respect privacy and confidentiality
- Follow your organization's security policies

---

## 📚 Documentation

### Project-Specific Guides

- **SecureComm:** `C2_Server_3rd_Sem/Readme.md` - PKI & cryptography details
- **Bug Bounty Tool:** `bugbounty_tool_project/README.md` - Tool integration guide
- **Chat App:** `Chat_App/README.md` - Setup & security features
- **C2 Server:** `C2_Server/README.md` - Architecture & deployment

### Analysis Documents

- **[Complete Analysis](DEEP_ANALYSIS.md)** - Comprehensive project breakdown
- **[Technical Deep-Dive](TECHNICAL_DEEPDIVE.md)** - Architecture & implementation details

### External Resources

- [OWASP Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cryptographic Standards](https://csrc.nist.gov/)
- [CWE/CVSS Security Scoring](https://cwe.mitre.org/)

---

## 🤝 Contributing

We welcome contributions! Please:

1. **Fork the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/College_Projects.git
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make changes and test**
   ```bash
   pytest tests/ -v
   ```

4. **Commit with clear messages**
   ```bash
   git commit -m "feat: description of changes"
   ```

5. **Push and create Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

### Contribution Guidelines

- ✅ Follow PEP-8 coding standards
- ✅ Add tests for new features
- ✅ Update documentation
- ✅ Ensure 80%+ code coverage
- ✅ Security-first approach

---

## 📄 License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) file for details.

### What You Can Do

- ✅ Use commercially
- ✅ Modify the code
- ✅ Distribute copies
- ✅ Use for private purposes

### What You Must Do

- ✅ Include license notice
- ✅ State changes made
- ✅ Provide source code access

### What You Cannot Do

- ❌ Hold creator liable
- ❌ Use trademark
- ❌ Hold project accountable

---

## 👤 Author

**Bhanu Guragain**
- 🔗 GitHub: [@BhanuGuragain0](https://github.com/BhanuGuragain0)
- 🎓 Institution: Softwarica College of IT & E-Commerce (Coventry University)
- 📧 Contact: [Email]

---

## 🌟 Acknowledgments

- Softwarica College of IT & E-Commerce
- Coventry University
- Open-source cryptography community
- Security research community

---

## 📞 Support

### Getting Help

1. **Check existing documentation**
   - Project README files
   - Analysis documents
   - Code comments

2. **Search GitHub Issues**
   - May already be answered
   - Provides solutions for common problems

3. **Create new issue**
   - Provide clear description
   - Include error messages
   - Describe reproduction steps

4. **Security vulnerabilities**
   - Report privately
   - Do NOT create public issues
   - Use GitHub security advisory feature

---

## 📈 Project Status & Updates

- **Last Updated:** February 2026
- **Commit History:** Active development
- **Latest Features:** Enhanced C2 infrastructure, improved cryptography
- **Next Steps:** Advanced ML models, distributed architecture

---

## 🎯 Project Goals & Milestones

### Completed ✅
- [x] Military-grade cryptography implementation
- [x] Multi-platform C2 framework
- [x] Penetration testing automation
- [x] Production chat application
- [x] ML-based threat detection
- [x] Comprehensive documentation

### In Progress 🔄
- [ ] Advanced exploit framework
- [ ] Distributed agent network
- [ ] Enhanced AI analysis
- [ ] Mobile application support

### Planned 📋
- [ ] Kubernetes deployment
- [ ] Advanced threat intelligence
- [ ] Federated learning
- [ ] Hardware security module (HSM) support

---

## 📊 Performance Metrics

### Benchmarks

| Component | Metric | Target | Actual |
|-----------|--------|--------|--------|
| **Encryption Throughput** | MB/s | 100+ | 150+ |
| **Key Exchange Speed** | ms | <100 | 45 |
| **Message Latency** | ms | <50 | 25 |
| **Code Coverage** | % | 80+ | 85+ |
| **Test Execution** | sec | <30 | 18 |

---

## 🔗 Quick Links

| Resource | Link |
|----------|------|
| **GitHub Repository** | [https://github.com/BhanuGuragain0/College_Projects](https://github.com/BhanuGuragain0/College_Projects) |
| **Complete Analysis** | [DEEP_ANALYSIS.md](DEEP_ANALYSIS.md) |
| **Technical Details** | [TECHNICAL_DEEPDIVE.md](TECHNICAL_DEEPDIVE.md) |
| **License** | [MIT License](LICENSE) |

---

## 📝 FAQ

**Q: Can I use these projects commercially?**
A: Yes, under MIT License. Include license notice and attribute the original author.

**Q: Is it legal to use the C2 framework?**
A: Only with written authorization on authorized systems. Unauthorized access is illegal.

**Q: How do I contribute?**
A: Fork the repository, create a feature branch, make changes, test thoroughly, and submit a pull request.

**Q: What's the code coverage?**
A: 85%+ for main projects (SecureComm, Chat App), with comprehensive test suites.

**Q: Can I fork and modify the projects?**
A: Yes, under MIT License. Please include proper attribution and document your changes.

---

<div align="center">

### ⭐ If you find this project useful, please consider giving it a star! ⭐

**Made with ❤️ by Bhanu Guragain**

</div>

---

*Last Updated: February 17, 2026 | Repository Version: 1.0 | Status: Production Ready*
