# Advanced C2 Server Tool

**Author:** Shadow@Bhanu

---

## Overview

Welcome to the **Advanced C2 Server Tool** – a cutting-edge, distributed command and control system built for ethical hackers and cybersecurity enthusiasts. This tool is engineered to securely manage a network of bots with robust encryption, real-time monitoring, and a sleek, hacker-inspired interface. Whether you’re testing your defenses or learning advanced cybersecurity techniques, this tool delivers high-level security and performance.

---

## Features

- **Secure Communication:**  
  - Uses **AES-GCM** encryption with a 32-byte shared key for secure data transmission.
  - Implements **ECDH** key exchange to protect against MITM and replay attacks.

- **Multi-Platform Bot Support:**  
  - Compatible with both Windows and Linux.
  - Incorporates persistence mechanisms and anti-debugging techniques to remain covert.

- **Asynchronous Task Execution:**  
  - Leverages **Celery** and **Redis** to process commands asynchronously.

- **Hacker-Style Dashboard:**  
  - A dynamic GUI built with **Tkinter** featuring an animated gradient background.
  - Real-time log monitoring, sortable tables, search, and export functionalities.
  - Customizable themes and settings for a truly immersive experience.

- **Authentication and Security:**  
  - Protected endpoints using **Flask-Login**.
  - Designed with modular security to resist common attacks (DoS, MITM, replay).

- **Extensible and Modular:**  
  - A scalable architecture that supports future enhancements such as MFA, plugin systems, and advanced analytics.

---

## Setup

### Prerequisites

- **Python 3.x** – Ensure you have Python 3 installed.
- **Redis Server** – Required for asynchronous task processing with Celery.
- **VirtualBox** (optional) – For deploying bot payloads in a controlled environment.
- **Git** – To clone the repository.

### Quick Start

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/BhanuGuragain0/c2-server.git
   cd c2-server
   pip install -r requirements.txt
   python3 launcher.py
   ```
   
   
   
 # Project Structure 

```bash
 
📂 c2-server                          <-- Repository root
├── 📜 README.md                      <-- Project documentation
├── 📜 requirements.txt                <-- Dependencies list
├── 📜 .env                            <-- Environment configuration file
├── 📜 icon.png                        <-- GUI icon file
├── 📜 launcher.py                     <-- GUI launcher with enhanced features
├── 📜 c2_server.db                    <-- SQLite database file for bot management
│
├── 📂 bot                             <-- Bot client code
│   ├── 📜 __init__.py                 <-- Marks bot directory as a package
│   ├── 📜 bot.py                      <-- Main bot script (connects to C2 server)
│   ├── 📜 encryption.py               <-- Cryptographic functions for secure communication
│   ├── 📜 persistence.py              <-- Implements bot persistence on target machines
│   ├── 📜 stealth.py                  <-- Anti-debugging and stealth techniques
│
├── 📂 dashboard                       <-- Web dashboard for monitoring bots
│   ├── 📜 app.js                      <-- JavaScript for web-based control panel
│   ├── 📜 __init__.py                 <-- Initializes dashboard as a package
│   ├── 📂 components                  <-- React components for UI
│   ├── 📂 styles                      <-- Stylesheets for UI
│   │   ├── 📜 main.css                 <-- Main CSS file for styling the dashboard
│
├── 📂 payload_generator               <-- Payload (bot) generation scripts
│   ├── 📜 __init__.py                 <-- Initializes payload generator package
│   ├── 📜 generator.py                <-- Generates executable bot payload using PyInstaller
│   ├── 📜 obfuscation.py              <-- Obfuscates bot code using PyArmor
│
├── 📂 scripts                         <-- Deployment and setup scripts
│   ├── 📜 deploy.sh                   <-- Deploys the C2 server
│   ├── 📜 setup.sh                    <-- Installs dependencies and configures the environment
│
└── 📂 server                          <-- Backend server code
    ├── 📜 __init__.py                 <-- Initializes server package
    ├── 📜 app.py                      <-- Flask application (main API)
    ├── 📜 auth.py                     <-- User authentication and access control
    ├── 📜 bot_manager.py              <-- Handles bot registrations and management
    ├── 📜 config.py                   <-- Central configuration for the C2 server
    ├── 📜 encryption.py               <-- Server-side encryption functions
    ├── 📜 file_manager.py             <-- Handles file uploads and downloads
    ├── 📜 gui.py                      <-- Tkinter-based GUI for real-time monitoring
    ├── 📜 logging.py                  <-- Custom logging configuration
    ├── 📜 models.py                   <-- Database models and schema definitions
    ├── 📜 plugins_loader.py           <-- Plugin-based architecture for extending functionality
    ├── 📜 socket_app.py               <-- Real-time communication using WebSockets
    ├── 📜 task_manager.py             <-- Manages and schedules tasks asynchronously
    ├── 📜 tasks.py                    <-- Defines Celery tasks for remote command execution
    └── 📂 templates                   <-- Web dashboard HTML templates
        ├── 📜 dashboard.html          <-- Main dashboard page
        └── 📜 login.html              <-- Login page for authentication

```
