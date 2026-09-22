# Sentinel Core - Installation & Setup Guide

> **Authorized use only.** Lab / defender inventory for assets you own or have
> written permission to assess. Not a chaos or attack toolkit.

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip package manager
- Git (optional, for cloning)

### Installation Steps

1. **Clone or navigate to the project**
   ```bash
   cd sentinel_core
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your API keys
   nano .env
   ```

4. **Initialize database and start**
   ```bash
   python app.py
   ```

5. **Access the application**
   - Open browser: `http://localhost:5000` (or the port printed by `app.py`, often `5001`)
   - Username: `admin`
   - Password: set `SHADOWSEYE_ADMIN_PASSWORD` before first boot, **or** read the
     one-time generated password printed to the console (no committed default)
   - **IMPORTANT**: Change the admin password immediately after first login

## 🔑 Required API Keys

### NVIDIA NIM (AI Integration)
- Get free API key: https://build.nvidia.com/
- Supports 13 cybersecurity AI personas

### Shodan (Infrastructure Intelligence)
- Free tier: https://www.shodan.io/
- 100 queries/month free

### VirusTotal (Malware Analysis)
- Free tier: https://www.virustotal.com/
- 4 requests/minute, 500/day

### Hunter.io (Email Discovery)
- Free tier: https://hunter.io/
- 25 searches/month

## 🛠️ Kali/Parrot Tools Integration

The following tools are supported (install as needed):
- **Reconnaissance**: nmap, amass, subfinder, theHarvester, dnsrecon
- **Web Analysis**: httpx, nuclei, nikto, gobuster, dirb, wfuzz, whatweb, wafw00f
- **Vulnerability**: sqlmap, metasploit
- **Password**: hydra, john, hashcat
- **Network**: masscan, rustscan, naabu
- **Fuzzing**: ffuf, feroxbuster

Install on Kali/Parrot:
```bash
sudo apt update
sudo apt install -y nmap amass subfinder theharvester dnsrecon \
    httpx nuclei nikto gobuster dirb wfuzz whatweb wafw00f \
    sqlmap metasploit-framework hydra john hashcat \
    masscan rustscan naabu ffuf feroxbuster
```

## 🔒 Security Best Practices

1. **Set `SHADOWSEYE_ADMIN_PASSWORD` (or capture the generated one) and change it after first login**
2. **Use strong SECRET_KEY in production**
3. **Enable HTTPS in production**
4. **Restrict network access**
5. **Regular security updates**
6. **Review audit logs frequently**

## 📁 Project Structure

```
sentinel_core/
├── app.py                 # Main Flask application
├── models/                # Database models
├── modules/               # OSINT modules
│   ├── dns_module.py
│   ├── whois_module.py
│   ├── ssl_module.py
│   ├── crtsh_module.py
│   ├── shodan_module.py
│   ├── virustotal_module.py
│   ├── wayback_module.py
│   └── hunter_module.py
├── integrations/          # AI and external services
│   └── kimi_ai.py
├── engine/                # Automation engine
│   ├── script_engine.py
│   └── task_queue.py
├── templates/             # HTML templates
├── static/                # CSS, JS, images
├── db/                    # SQLite database
├── logs/                  # Application logs
└── config/                # Configuration files
```

## 🎯 Features Overview

### OSINT Modules (8)
- DNS Enumeration & Subdomain Discovery
- WHOIS Lookup
- SSL/TLS Certificate Analysis
- Certificate Transparency Search
- Shodan Infrastructure Search
- VirusTotal Malware Analysis
- Wayback Machine Archives
- Hunter.io Email Discovery

### AI Integration
- 13 Cybersecurity Expert Personas
- Case Analysis & Recommendations
- Report Generation
- MITRE ATT&CK Mapping

### Automation
- Playbook Engine
- Custom Tool Creator
- Task Queue System
- Scheduled Scans

### Kali/Parrot Tools (30+)
- Full integration with security tools
- Command whitelist for safety
- Live terminal with AI assistance

### Case Management
- Entity Relationship Graphs
- Findings Tracking
- Collaborative Notes
- Audit Logging

## 🐛 Troubleshooting

### Module import errors
```bash
pip install -r requirements.txt --upgrade
```

### Database errors
```bash
rm db/sentinel.db
python -c "from app import app, db; app.app_context().push(); db.create_all()"
```

### Permission errors
```bash
chmod -R 755 logs/ db/
```

## 📞 Support

For issues and feature requests, please check documentation or contact support.

---
**⚠️ WARNING**: This tool is for authorized security testing only. Always obtain proper authorization before scanning systems you do not own.
