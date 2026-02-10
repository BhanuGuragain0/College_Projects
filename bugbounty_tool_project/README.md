# # ✨ Bug Bounty Automation Tool By Shadow@Bhanu ✨

## 🔒 Overview
**Bug Bounty Automation Tool** designed for elite hackers and security researchers. This tool integrates **Kali Linux's** most powerful scanning tools (like Nmap, Dirsearch, SQLMap, Nikto, Gobuster, Wfuzz, and Wpscan), With AI-driven analysis, and custom reporting to help you **hunt vulnerabilities faster and smarter**.

## ⚙️ Features
- **🔮 Full-Stack Automation**: Runs **nmap, dirsearch, sqlmap, nikto, gobuster, wfuzz, wpscan**, and more.
- **🤖 AI-Powered Analysis**: Uses OpenAI's **GPT** to analyze output and suggest next moves.
- **🛠️ Custom Wordlists**: Optimize brute-force attacks with **tailored wordlists**.
- **💡 Intelligent Reporting**: Generates reports in **HTML, Markdown, and JSON**.
- **⚡ High-Speed Execution**: Utilizes **asyncio** for parallel execution.
- **🛡️ Modular Plugin System**: Extend and customize functionality with ease.


## 📝 Directory Structure
```
📂 bugbounty_tool_project            <-- Repository root
├── 📜 setup.py                      <-- our setup script
├── 📜 README.md                     <-- Project documentation
├── 📜 requirements.txt               <-- Dependencies list
├── 📜 Dockerfile                     <-- Docker containerization file
├── 📜 icon.png                       <-- GUI icon file
├── 📂 config                         <-- Configuration files
│   ├── 📜 config.yaml                <-- Tool configuration file
│   ├── 📜 schema.yaml                <-- Validation schema for configuration
├── 📂 bugbounty_tool                 <-- Your package directory
│   ├── 📜 __init__.py                <-- Marks bugbounty_tool as a package
│   ├── 📜 cli.py                     <-- CLI interface for running scans
│   ├── 📜 launcher.py                 <-- GUI launcher with enhanced features
│   ├── 📜 gui.py                      <-- GUI interface using Tkinter
│   ├── 📂 core                        <-- Core framework and processing logic
│   │   ├── 📜 __init__.py
│   │   ├── 📜 tool_runner.py          <-- Handles execution of scanning tools
│   │   ├── 📜 target_processor.py     <-- Validates and processes target inputs
│   │   ├── 📜 report_generator.py     <-- Generates HTML, Markdown, JSON reports
│   │   ├── 📜 ai_analyzer.py          <-- AI-based analysis of scan outputs
│   │   ├── 📜 utils.py                <-- Utility functions (logging, validation)
│   │   ├── 📜 plugin_manager.py       <-- Handles dynamic plugin loading
│   │   ├── 📜 rate_limiter.py         <-- Rate limiting for API/tool execution
│   │   ├── 📜 wordlist_manager.py     <-- Manages wordlists for brute-forcing
│   │   ├── 📂 plugins                 <-- Contains all scanning tool plugins
│   │   │   ├── 📜 __init__.py
│   │   │   ├── 📜 base_plugin.py      <-- Base class for all plugins
│   │   │   ├── 📜 dirsearch_plugin.py <-- Plugin for Dirsearch tool
│   │   │   ├── 📜 gobuster_plugin.py  <-- Plugin for Gobuster tool
│   │   │   ├── 📜 nmap_plugin.py      <-- Plugin for Nmap tool
│   │   │   ├── 📜 sqlmap_plugin.py    <-- Plugin for SQLMap tool
│   │   │   ├── 📜 wfuzz_plugin.py     <-- Plugin for Wfuzz tool
│   │   │   ├── 📜 wpscan_plugin.py    <-- Plugin for WPScan tool
├── 📂 templates                      <-- Report templates
│   ├── 📜 report.html                <-- HTML report template
│   ├── 📜 report.md                  <-- Markdown report template
├── 📂 tests                          <-- Unit tests
│   ├── 📜 __init__.py
│   ├── 📜 test_ai_analyzer.py         <-- Unit tests for AI module
│   ├── 📜 test_tool_runner.py         <-- Unit tests for scanning execution
├── 📂 .github                         <-- GitHub CI/CD workflow
│   ├── 📂 workflows
│   │   ├── 📜 ci.yml                  <-- Automated tests & deployment
└── 📂 wordlists                       <-- Wordlists for brute-forcing
    ├── 📜 admin-panels.txt
    ├── 📜 big.txt
    ├── 📜 bug-bounty-program-subdomains-trickest-inventory.txt
    ├── 📜 burp-parameter-names.txt
    ├── 📜 combined_subdomains.txt
    ├── 📜 common.txt
    ├── 📜 directory-list-1.0.txt
    ├── 📜 directory-list-2.3-big.txt
    ├── 📜 directory-list-lowercase-2.3-big.txt
    ├── 📜 directory-list-lowercase-2.3-medium.txt
    ├── 📜 directory-list-lowercase-2.3-small.txt
    ├── 📜 dirsearch.txt
    ├── 📜 subdomains-top1million-110000.txt
    └── 📜 subdomains.txt
```


## 👤 Installation
```bash
cd bugbounty_tool_project

# Install dependencies
$ pip install -e . --break-system-packages

# Verify installation
$ python3 -c "import bugbounty_tool; print('Package found!')"
# Should return: "Package found!"
```

## ⚛️ Usage
```bash
# Display help menu
$ bugbounty --help

# Launch the tool
$ python3 -m bugbounty_tool.launcher
# OR
$ cd bugbounty_tool_project/bugbounty_tool/ 
$ python3 launcher.py
```



## 🌐 GitHub
Want to contribute? Fork the repo and submit a PR!
- **Repository**: [GitHub](https://github.com/BhanuGuragain0/bugbounty_tool_project)

## 🤠 Stay Anonymous. Stay Elite. Happy Hacking! 💀


