# 🛡️ Sentinel Core - Elite Cybersecurity Intelligence Platform

**Complete, Production-Ready OSINT & Security Assessment Platform with Kimi AI Integration**

![Status](https://img.shields.io/badge/status-production--ready-success)
![Python](https://img.shields.io/badge/python-3.8+-blue)
![Flask](https://img.shields.io/badge/flask-3.0+-green)
![AI](https://img.shields.io/badge/AI-Kimi_Moonshot_NVIDIA-purple)

---

## 🎯 Overview

Sentinel Core is an **elite cybersecurity intelligence platform** that combines:
- **8 Real OSINT Modules** (DNS, WHOIS, SSL, CT, Shodan, VirusTotal, Wayback, Hunter.io)
- **Kimi Moonshot AI** via NVIDIA NIM API (12 Elite Roles)
- **Kali/Parrot Tool Integration** (nmap, subfinder, nuclei, sqlmap, gobuster, etc.)
- **MITRE ATT&CK Framework** Mapping & Export
- **Advanced Correlation Engine** for infrastructure analysis
- **Automated Playbook Engine** with pre-built workflows
- **Live Terminal** with Agentic AI command execution
- **Professional UI** with Glassmorphism design

**NO SIMULATED DATA** - All tools execute real commands and return actual results.

---

## ✨ Key Features

### 🔍 8 Built-in OSINT Modules (All Working)

| Module | Description | API Required | Status |
|--------|-------------|--------------|--------|
| **DNS Enumeration** | A, AAAA, MX, NS, TXT, CNAME, SOA records + Reverse DNS + Subdomain brute-force | ❌ No | ✅ Real |
| **WHOIS Lookup** | Domain registration, registrar, creation/expiry dates, nameservers | ❌ No | ✅ Real |
| **SSL Analysis** | Certificate details, validity, issuer, SAN, expiration alerts | ❌ No | ✅ Real |
| **Certificate Transparency** | Subdomain discovery via crt.sh API | ❌ No | ✅ Real |
| **Shodan Search** | IoT device discovery, open ports, services, vulnerabilities | ✅ Yes | ✅ Real |
| **VirusTotal Analysis** | URL/domain/IP reputation, malware detection, threat scores | ✅ Yes | ✅ Real |
| **Wayback Machine** | Historical web archives, URL captures over time | ❌ No | ✅ Real |
| **Hunter.io** | Email discovery, professional contact finding | ✅ Yes | ✅ Real |

### 🧠 Kimi Moonshot AI Integration (NVIDIA NIM)

**Model:** `moonshotai/kimi-k2.5` via `https://integrate.api.nvidia.com/v1/chat/completions`

#### 12 Elite AI Roles:
1. **Ethical Hacker** - Penetration testing expert
2. **Incident Responder** - DFIR specialist
3. **OSINT Specialist** - Open-source intelligence analyst
4. **Red Team Operator** - APT simulation expert
5. **Threat Hunter** - Proactive threat detection
6. **Cloud Security Expert** - AWS/Azure/GCP security
7. **Application Security Expert** - OWASP, SAST/DAST
8. **Intelligence Bureau Officer** - National security analyst
9. **Mossad Operator** - Covert operations specialist
10. **RAW Analyst** - Geopolitical intelligence
11. **Malware Analyst** - Reverse engineering expert
12. **SOC Analyst** - SIEM operations specialist

#### AI Capabilities:
- ✅ **Context-Aware Analysis** - Automatic injection of case data, entities, scan results
- ✅ **Agentic Mode** - Command detection, user confirmation, autonomous execution
- ✅ **Smart Token Management** - Daily budget tracking (100K tokens/day default)
- ✅ **Persistent Memory** - Conversation history stored in database
- ✅ **Report Generation** - Professional HTML/PDF reports with executive summaries
- ✅ **Next-Step Suggestions** - AI recommends investigation paths
- ✅ **MITRE ATT&CK Mapping** - Automatic technique identification

### 🛠️ Kali/Parrot Tool Integration (20+ Tools)

**Automatically detects and uses best tool for each task:**

| Category | Tools | Auto-Selected For |
|----------|-------|-------------------|
| **Reconnaissance** | `whois`, `dig`, `nslookup`, `subfinder`, `amass` | Domain/IP enumeration |
| **Web Analysis** | `httpx`, `nuclei`, `nikto`, `gobuster`, `dirb`, `sslscan`, `testssl.sh` | Web app scanning |
| **Network** | `nmap`, `masscan` | Port scanning, service detection |
| **Vulnerability** | `nuclei`, `nikto`, `sqlmap` | Vulnerability detection |
| **Forensics** | `wireshark`, `tcpdump`, `john`, `hashcat` | Evidence analysis |

**Custom Tool Creator:**
- Create custom Bash/PHP/Python tools via UI
- Template system with `{{target}}` placeholders
- JSON parameter support
- Category assignment (recon, web, network, vuln, forensics)
- One-click execution from case detail page

### 📊 Advanced Correlation Engine

**Automatic Infrastructure Correlation:**
- ✅ **IP Subnet Clustering** - Groups IPs by /24 subnets
- ✅ **Domain Cluster Analysis** - Identifies related domains via WHOIS patterns
- ✅ **SSL Certificate Correlation** - Links domains sharing certificates
- ✅ **WHOIS Pattern Matching** - Finds domains with same registrant/email
- ✅ **Vulnerability Chain Detection** - Connects related findings
- ✅ **Attack Campaign Detection** - Identifies coordinated attacks
- ✅ **STIX 2.1 Export** - Threat intelligence sharing format

### 🎯 MITRE ATT&CK Framework

**Full Integration:**
- ✅ **14 Tactics Covered** - Reconnaissance → Impact
- ✅ **22 Pre-loaded Techniques** - Common attack techniques
- ✅ **Automatic Technique Mapping** - Findings mapped to T-codes
- ✅ **Navigator Layer JSON Export** - Import into MITRE ATT&CK Navigator
- ✅ **Visual Heatmaps** - Color-coded by severity

### 📜 Automated Playbook Engine

**Pre-built Playbooks:**

#### 1. MITNICK_RECON (Kevin Mitnick Methodology)
```yaml
Steps:
  1. WHOIS Lookup (30s timeout)
  2. DNS Enumeration (60s)
  3. Certificate Transparency (60s)
  4. Subdomain Discovery (120s)
  5. HTTP Probe (120s)
  6. Nuclei Scan (300s)
```

#### 2. BUG_HUNTER_WEB (Top Bug Hunter Workflow)
```yaml
Steps:
  1. Subdomain Discovery (120s)
  2. HTTP Probe (120s)
  3. SSL Analysis (30s)
  4. Nuclei Scan (300s)
  5. Wayback Machine (60s)
```

#### 3. NETWORK_EXTERNAL (Elite Pentester Techniques)
```yaml
Steps:
  1. Nmap Scan (-sS -sV -O) (300s)
  2. Shodan Search (60s)
  3. SSL Scan (60s)
  4. Nikto Scan (300s)
```

**Features:**
- ✅ Conditional execution based on previous results
- ✅ Timeout management per step
- ✅ Parallel execution support
- ✅ Custom playbook creation via UI

### 🤖 ML-Based Anomaly Detection

**Built-in Anomaly Detection:**
- ✅ **Port Anomaly Detection** - Unusual port combinations
- ✅ **Subdomain Spray Detection** - Bulk subdomain registration patterns
- ✅ **Critical CVE Identification** - Auto-flag high-severity vulnerabilities
- ✅ **Certificate Anomalies** - Self-signed, expired, mismatched certs
- ✅ **Risk Score Calculation** - 0-100 score based on findings

### 📝 Integrated Notes System

**Full CRUD Operations:**
- ✅ Create, Read, Update, Delete notes
- ✅ Tag-based organization
- ✅ AI-Powered enhancement (formatting, technical accuracy)
- ✅ Auto-suggestions for next steps
- ✅ Case and entity association
- ✅ Author attribution

### 🛡️ Security Architecture

**Enterprise-Grade Security:**
- ✅ **Session Authentication** - No auto-login, secure cookies
- ✅ **bcrypt Password Hashing** - Industry-standard hashing
- ✅ **Comprehensive Audit Logging** - All actions tracked
- ✅ **Input Validation** - SQL injection prevention
- ✅ **Rate Limiting** - API abuse protection
- ✅ **Evidence Isolation Storage** - Forensic integrity
- ✅ **Role-Based Access Control** - Admin/Analyst roles
- ✅ **Command Whitelisting** - Terminal security

---

## 🚀 Installation

### Prerequisites
- Python 3.8+
- pip package manager
- Optional: Kali Linux tools (nmap, whois, dig, subfinder, nuclei, etc.)

### Quick Start

```bash
# Clone repository
cd /workspace/sentinel_core

# Install dependencies
pip install -r requirements.txt

# Initialize system (auto-registers modules)
python3 shadowseye.py

# Start application
python3 app.py
```

**Access:** http://localhost:5001

**Default Credentials:**
- Username: `admin`
- Password: `admin123`

⚠️ **Change default password immediately!**

---

## 📁 Project Structure

```
sentinel_core/
├── app.py                      # Main Flask application (1400+ lines)
├── shadowseye.py               # Elite launcher & module registry
├── requirements.txt            # Python dependencies
├── README.md                   # This file
│
├── config/
│   └── settings.json           # Persistent configuration (API keys)
│
├── db/
│   └── sentinel.db             # SQLite database
│
├── engine/
│   ├── __init__.py
│   ├── task_queue.py           # Async worker pool (5 workers)
│   └── script_engine.py        # Dynamic script execution
│
├── integrations/
│   ├── __init__.py
│   ├── kimi_ai.py              # Kimi Moonshot AI integration
│   └── correlation_engine.py   # Advanced correlation logic
│
├── models/
│   ├── __init__.py
│   └── intelligence.py         # Database schema
│
├── modules/                    # 8 OSINT Modules
│   ├── __init__.py
│   ├── dns_module.py           # DNS enumeration
│   ├── whois_module.py         # WHOIS lookup
│   ├── ssl_module.py           # SSL analysis
│   ├── crtsh_module.py         # Certificate transparency
│   ├── shodan_module.py        # Shodan integration
│   ├── virustotal_module.py    # VirusTotal analysis
│   ├── wayback_module.py       # Wayback Machine
│   └── hunter_module.py        # Hunter.io email discovery
│
├── templates/                  # 11 HTML Templates
│   ├── base.html               # Base layout with sidebar
│   ├── login.html              # Login page
│   ├── dashboard.html          # Dashboard with stats
│   ├── cases.html              # Cases list
│   ├── case_detail.html        # Case detail view
│   ├── tools.html              # Tools catalog
│   ├── playbooks.html          # Playbook library
│   ├── terminal.html           # Live terminal
│   ├── settings.html           # Settings/API keys
│   ├── audit_logs.html         # Audit log viewer
│   └── graph.html              # Entity graph view
│
├── static/
│   ├── css/
│   │   └── style.css           # Elite UI styles (Glassmorphism)
│   └── js/
│       └── app.js              # Frontend JavaScript
│
├── user_modules/               # Custom user-created tools
│
├── evidence/                   # Forensic report storage
│
└── logs/
    ├── app.log                 # Application logs
    └── shadowseye.log          # Launcher logs
```

---

## 🎨 UI Features

### Elite Professional Design
- **Framework:** Custom CSS with Glassmorphism effects
- **Theme:** Dark mode with Neon accents (Blue #00f0ff, Purple #bd00ff, Green #00ff88)
- **Font:** Inter font family throughout
- **Navigation:** Collapsible sidebar with active state tracking
- **Responsiveness:** Fully adaptive grid layouts (mobile-friendly)

### Interactivity
- ✅ **Toast Notifications** - Success/error messages with auto-dismiss
- ✅ **Modal Dialogs** - Confirmation dialogs, forms, details
- ✅ **Real-time Status Updates** - Live scan progress
- ✅ **Loading Spinners** - Async operation feedback
- ✅ **Keyboard Shortcuts** - Ctrl+K for AI, Escape to close modals

### Pages
1. **Dashboard** - Stats overview, recent scans, quick actions
2. **Cases** - Case management with filters
3. **Case Detail** - Entities, scans, findings, notes, AI analysis
4. **Tools** - Tool catalog with categories
5. **Terminal** - Live terminal with AI suggestions
6. **Playbooks** - Playbook library and executor
7. **Settings** - API key management, preferences
8. **Audit Logs** - Action history (admin only)
9. **Graph View** - Force-directed entity visualization

---

## 🔑 Configuration

### API Keys (Configure in /settings)

Navigate to **Settings** page after login:

| Service | Purpose | Get Key | Required |
|---------|---------|---------|----------|
| **NVIDIA NIM** | Kimi AI access | [build.nvidia.com](https://build.nvidia.com) | ✅ For AI features |
| **Shodan** | IoT device search | [shodan.io](https://shodan.io) | ❌ Optional |
| **VirusTotal** | Malware analysis | [virustotal.com](https://virustotal.com) | ❌ Optional |
| **Hunter.io** | Email discovery | [hunter.io](https://hunter.io) | ❌ Optional |

Keys are stored encrypted in `config/settings.json`.

---

## 📖 Usage Guide

### 1. Create a Case
```
Dashboard → New Case → Enter title/description/priority → Create
```

### 2. Add Entities
```
Case Detail → Add Entity → Select type (domain/IP/email/URL/hash) → Enter value
```

### 3. Run Scans
```
Click entity → Select scan module → Wait for results
OR
Auto-scan → Runs all relevant modules automatically
```

### 4. AI Analysis
```
Case Detail → AI Analyze → Select role (Ethical Hacker, etc.) → Get insights
```

### 5. Execute Playbook
```
Playbooks → Select playbook → Enter target → Execute
→ Automatically creates case and runs all steps
```

### 6. Use Terminal
```
Terminal → Type command (nmap, dig, whois, etc.) → Execute
OR
Enable Agentic Mode → AI suggests commands → Confirm → Execute
```

### 7. Generate Report
```
Case Detail → Generate Report → Select format (HTML/JSON/STIX) → Download
```

### 8. MITRE Export
```
Case Detail → Export MITRE → Downloads Navigator layer JSON
→ Import into MITRE ATT&CK Navigator
```

---

## 🔬 Module Details

### DNS Enumeration (`dns_module.py`)
**Real Implementation:**
- Uses `dnspython` library
- Queries: A, AAAA, MX, NS, TXT, CNAME, SOA, CAA
- Reverse DNS for A records
- Subdomain brute-force with 50+ common subdomains
- Error handling for NXDOMAIN, NoNameservers

### WHOIS Lookup (`whois_module.py`)
**Real Implementation:**
- Uses `python-whois` library
- Returns: registrar, org, country, dates, nameservers, status, emails
- Calculates domain age
- Categorizes: new (<90 days), recent (<1 year), established

### SSL Analysis (`ssl_module.py`)
**Real Implementation:**
- Uses `ssl` and `socket` libraries
- Returns: certificate details, issuer, validity, SAN, version
- Checks expiration, self-signed, weak algorithms

### Certificate Transparency (`crtsh_module.py`)
**Real Implementation:**
- Queries crt.sh API
- Returns all subdomains from CT logs
- Parses JSON response

### Shodan Search (`shodan_module.py`)
**Real Implementation:**
- Uses Shodan API
- Returns: open ports, services, vulnerabilities, geolocation
- Requires API key (free tier available)

### VirusTotal Analysis (`virustotal_module.py`)
**Real Implementation:**
- Uses VirusTotal API v3
- Returns: detection ratio, categories, threat scores
- Supports domain/IP/URL/hash analysis

### Wayback Machine (`wayback_module.py`)
**Real Implementation:**
- Queries Internet Archive CDX API
- Returns: historical URLs, capture dates
- No API key required

### Hunter.io (`hunter_module.py`)
**Real Implementation:**
- Uses Hunter.io API
- Returns: professional emails, sources, confidence scores
- Requires API key (free tier: 25 searches/month)

---

## 🧪 Testing

### Verify Modules Work
```python
from modules.dns_module import enumerate_dns
result = enumerate_dns('google.com')
print(result['records']['A'])  # Real IP addresses

from modules.whois_module import lookup_whois
result = lookup_whois('github.com')
print(result['registrar'])  # Real registrar name
```

### Test AI Integration
```python
from integrations.kimi_ai import KimiAIIntegration

kimi = KimiAIIntegration(api_key='your-nvidia-key')
result = kimi.chat('Analyze this domain: example.com', role='ethical_hacker')
print(result['response'])
```

---

## 📊 Database Schema

**Tables:**
- `users` - User accounts (bcrypt passwords)
- `cases` - Investigation cases
- `entities` - Targets (domains, IPs, emails, etc.)
- `relationships` - Entity relationships
- `scan_results` - Scan outputs
- `findings` - Security findings with MITRE mapping
- `notes` - Investigator notes
- `custom_tools` - User-created tools
- `playbooks` - Automated workflows
- `audit_logs` - Action history
- `api_keys` - Encrypted API keys
- `conversation_history` - AI chat history

---

## 🔐 Security Best Practices

1. **Change Default Password** immediately after first login
2. **Use HTTPS** in production (configure reverse proxy)
3. **Restrict Network Access** (firewall rules)
4. **Regular Backups** of `db/sentinel.db` and `config/settings.json`
5. **Audit Log Review** (admin dashboard)
6. **API Key Rotation** (quarterly)
7. **Update Dependencies** (`pip install --upgrade -r requirements.txt`)

---

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Kill existing process
pkill -f "python3 app.py"

# Or use different port
python3 app.py --port 5002
```

### Module Not Found
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### AI Not Responding
1. Check NVIDIA API key in Settings
2. Verify internet connectivity
3. Check token budget in settings.json

### Database Locked
```bash
# Remove lock file
rm db/sentinel.db-shm db/sentinel.db-wal
```

---

## 📈 Roadmap

### ✅ Phase 1 - Core Platform (COMPLETED)
- [x] Modular OSINT modules (8 total)
- [x] Security tool integrations
- [x] Asynchronous task execution
- [x] Intelligence graph engine
- [x] Automated reporting system

### ✅ Phase 2 - Intelligence Expansion (COMPLETED)
- [x] Advanced infrastructure correlation
- [x] MITRE ATT&CK technique mapping
- [x] Kimi Moonshot AI integration (12 elite roles)
- [x] ML anomaly detection with risk scoring
- [x] Integrated notes system with AI
- [x] Persistent storage for API keys

### 🔄 Phase 3 - AI-Assisted Operations (IN PROGRESS)
- [ ] Distributed task workers (Celery)
- [x] Automated playbook execution
- [x] Advanced correlation engine
- [ ] Large-scale threat intelligence integration (MISP, OTX)
- [ ] Real-time collaboration features
- [ ] Multi-user case assignments
- [ ] WebSocket live updates

---

## 📄 License

**Proprietary** - For authorized security testing only.

⚠️ **Legal Notice:** Only use this tool on systems you have explicit permission to test. Unauthorized access is illegal.

---

## 🤝 Contributing

This is a private project. For questions or support, contact the development team.

---

## 📞 Support

**Documentation:** See `/docs` folder  
**Issues:** Internal ticketing system  
**Emergency:** Contact security team lead

---

## 🏆 Credits

**Developed By:** Sentinel Core Team  
**AI Integration:** NVIDIA NIM API (Kimi Moonshot)  
**Inspired By:** Maltego, SpiderFoot, theHarvester, OSINT Framework

---

**Version:** 2.0.0  
**Last Updated:** March 2026  
**Build:** ELITE-PRODUCTION

---

<div align="center">

### 🛡️ Sentinel Core - Elite Cybersecurity Intelligence Platform

*Real Tools. Real Results. No Simulation.*

[Documentation](#) • [API Reference](#) • [Support](#)

</div>
