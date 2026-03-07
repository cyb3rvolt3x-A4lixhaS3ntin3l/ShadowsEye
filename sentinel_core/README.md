# 🛡️ Sentinel Core - Elite OSINT Platform

**Powered by ShadowEye Launcher** | **Developed by Syed Abrar (Cyb3rvolt3x)** | **© SentinelReign.com**

The world's most advanced open-source intelligence platform designed for:
- **RAW / MOSSAD / IB** Intelligence Agencies
- **Military Cyber Commands** & Nation-State Operations
- **Elite Ethical Hackers** & Bug Bounty Hunters
- **Professional SOC Teams** & Incident Responders

---

## ⚠️ Legal Disclaimer

**This tool is intended for legitimate security purposes only:**
- Authorized penetration testing and red team operations
- Intelligence gathering on systems you own or have explicit permission to test
- Threat intelligence and counter-terrorism operations
- Defensive security operations and incident response
- Educational purposes in controlled environments

**⚔️ AUTHORIZED USE ONLY**: Unauthorized access to computer systems is illegal under:
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Information Technology Act - India
- Similar laws worldwide

---

## ✨ Elite Features

### 🔐 Military-Grade Security
- **Secure Authentication**: Bcrypt password hashing with session management
- **Audit Logging**: Tamper-evident action tracking for compliance
- **Case Ownership Checks**: Prevent unauthorized access to investigations
- **Immutable Evidence Chain**: Chain of custody for all artifacts

### 🎯 Advanced Capabilities
- **Real Module Execution Engine**: Async task queue with 5 parallel workers
- **Dynamic Script Engine (GOD MODE)**: Execute custom Python scripts directly
- **Maltego-Style Graph Analysis**: Interactive entity relationship mapping
- **20+ Integrated Kali/Parrot Tools**: Amass, Nuclei, Naabu, HTTPX, and more
- **Automated Recon Chains**: Full-spectrum reconnaissance automation
- **Multi-Format Reports**: HTML, STIX 2.1, JSON, PDF exports

### 📊 Built-in OSINT Modules (8 Total) - ALL REGISTERED

| Module | Description | API Key Required | Status |
|--------|-------------|------------------|--------|
| **DNS Enumeration** | DNS records & subdomain discovery | No | ✅ Registered |
| **WHOIS Lookup** | Domain registration information | No | ✅ Registered |
| **SSL Analysis** | Certificate details & validity | No | ✅ Registered |
| **Certificate Transparency** | Subdomain discovery via CT logs | No | ✅ Registered |
| **Shodan Search** | IoT device & service discovery | Yes (free tier) | ✅ Registered |
| **VirusTotal Analysis** | Malware & URL reputation | Yes (free tier) | ✅ Registered |
| **Wayback Machine** | Historical web archives | No | ✅ Registered |
| **Hunter.io** | Professional email discovery | Yes (free tier) | ✅ Registered |

**All 8 modules are automatically registered on startup via ShadowEye launcher.**

### 🛠️ Integrated Kali/Parrot Tools (20+)

**Reconnaissance:**
- `amass` - Comprehensive subdomain enumeration
- `subfinder` - Fast subdomain discovery
- `assetfinder` - Related domain finder
- `theHarvester` - Email harvesting
- `sherlock` - Username search across platforms
- `maigret` - Advanced username analysis
- `httpx` - HTTP probing & technology detection
- `whatweb` - Website fingerprinting
- `wafw00f` - WAF detection

**Vulnerability Assessment:**
- `nuclei` - Template-based vulnerability scanning
- `searchsploit` - Exploit database search
- `sqlmap` - SQL injection testing

**Network Scanning:**
- `nmap` - Port scanning & service detection
- `naabu` - Fast port scanner

**Post-Exploitation:**
- `exiftool` - Metadata extraction
- `binwalk` - Firmware analysis
- `jwt-tool` - JWT token analysis

### 🎨 Modern Web Interface
- Responsive dark theme UI
- Real-time graph visualization with vis.js
- Drag-and-drop entity management
- Live task monitoring dashboard
- Audit log viewer with filtering
- Custom script editor

---

## 🚀 Quick Start

### Prerequisites
- **Python 3.8+**
- **Kali Linux / Parrot OS** (recommended for full tool integration)
- **pip package manager**

### Installation

```bash
cd /workspace/sentinel_core
pip install -r requirements.txt
```

### Launch with ShadowEye

```bash
python shadowseye.py
```

**ShadowEye** provides:
- Automatic database initialization
- Tool availability detection
- Module registration
- Worker pool startup
- Browser auto-launch

### Access the Platform

```
🌐 Local: http://localhost:5001
🌐 Network: http://[YOUR_IP]:5001
```

### Default Credentials
```
Username: admin
Password: admin123
```

**⚠️ CHANGE IMMEDIATELY AFTER FIRST LOGIN!**

---

## 📖 Usage Guide

### Creating a Case
1. Log in with your credentials
2. Click **"New Case"** on the dashboard
3. Enter case name and description (e.g., "Target Corp Recon")
4. Click **"Create Case"**

### Running Automated Recon

**Option 1: Single Module**
```bash
curl -X POST http://localhost:5001/api/module/run \
  -F "module_id=dns" \
  -F "target=example.com" \
  -F "case_id=1"
```

**Option 2: Full Recon Chain**
```bash
curl -X POST http://localhost:5001/api/recon/full-chain \
  -F "target=example.com" \
  -F "case_id=1"
```

**Option 3: Kali Tools Comprehensive Scan**
```bash
curl -X POST http://localhost:5001/api/kali-tools/comprehensive-recon \
  -F "domain=example.com" \
  -F "case_id=1"
```

### Executing Custom Scripts (GOD MODE)

**Using Built-in Templates:**
```bash
curl -X POST http://localhost:5001/api/script/execute \
  -F "script_name=subdomain_bruteforce_extreme" \
  -F "target=example.com" \
  -F "case_id=1"
```

**Custom Python Script:**
```bash
curl -X POST http://localhost:5001/api/script/execute \
  -F "code=from integrations.kali_tools import kali_tools\nresult = kali_tools.run_amass('example.com')\nprint(result)" \
  -F "target=example.com" \
  -F "case_id=1"
```

### Generating Reports

**HTML Report with Graph:**
```bash
curl http://localhost:5001/api/report/generate/1?format=html
```

**STIX 2.1 Export (Threat Intelligence):**
```bash
curl http://localhost:5001/api/graph/export/1
```

---

## 🏗️ Architecture

```
sentinel_core/
├── shadowseye.py          # Elite launcher (USE THIS!)
├── app.py                 # Flask application core
├── requirements.txt       # Python dependencies
├── db/                    # SQLite database (absolute path)
│   └── sentinel.db
├── evidence/              # Forensic-grade report storage
├── engine/                # Core execution engine
│   ├── __init__.py
│   ├── module_registry.py    # Module metadata & secrets
│   ├── task_queue.py         # Async worker pool (5 workers)
│   └── script_engine.py      # Dynamic script execution
├── models/                # Data models
│   └── intelligence.py       # Entity/relationship schema
├── modules/               # OSINT modules (8 total)
│   ├── dns_module.py
│   ├── whois_module.py
│   ├── ssl_module.py
│   ├── crtsh_module.py
│   ├── shodan_module.py      # ✅ Registered
│   ├── virustotal_module.py  # ✅ Registered
│   ├── wayback_module.py     # ✅ Registered
│   └── hunter_module.py      # ✅ Registered
├── integrations/          # External tool integration
│   ├── kali_tools.py         # Kali/Parrot tools
│   └── advanced_tools.py     # 20+ tool registry
├── reports/               # Report generation
│   └── report_generator.py   # HTML/STIX/JSON (evidence dir)
├── templates/             # HTML templates
│   ├── login.html
│   ├── dashboard.html
│   ├── case.html
│   └── audit.html
├── static/                # Static assets
│   ├── css/
│   └── js/
└── user_modules/          # Custom user scripts (auto-created)
```

---

## 🔧 API Endpoints Reference

### Module Execution
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/modules` | GET | List all registered modules |
| `/api/module/run` | POST | Execute a module (async) |
| `/api/task/status/<id>` | GET | Get task status |
| `/api/tasks` | GET | List all tasks |

### Kali Tools
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/kali-tools/status` | GET | Check available tools |
| `/api/kali-tools/comprehensive-recon` | POST | Run full Kali tool suite |
| `/api/tools/list` | GET | List tools by category |
| `/api/tool/execute` | POST | Execute single tool |

### Script Engine
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/script/execute` | POST | Run custom/builtin script |
| `/api/script/save` | POST | Save custom script |
| `/api/scripts/templates` | GET | List builtin templates |

### Recon Automation
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/recon/full-chain` | POST | Full automated recon |

### Reports & Visualization
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/report/generate/<case_id>` | GET | Generate report (HTML/STIX/JSON) |
| `/api/report/download/<filename>` | GET | Download generated report |
| `/api/graph/visualize/<case_id>` | GET | Get graph data for visualization |
| `/api/graph/export/<case_id>` | GET | Export to STIX 2.1 format |

---

## 🔒 Security Features

### Case Ownership Enforcement
All task execution endpoints now verify:
- User owns the target case
- Unauthorized attempts are logged to audit trail
- 403 Forbidden returned for access violations

### Input Validation
- Type checking on all numeric parameters
- SQL injection prevention via parameterized queries
- XSS protection in web interface

### Audit Trail
Every action is logged with:
- Timestamp
- User ID
- Action type
- IP address
- Detailed context

---

## 🛠️ Troubleshooting

### Missing Kali Tools
Check available tools:
```bash
curl http://localhost:5001/api/kali-tools/status
```

Install missing tools:
```bash
sudo apt update && sudo apt install amass subfinder nuclei naabu httpx
```

### Database Errors
Reset database:
```bash
rm db/sentinel.db
python shadowseye.py
```

### Port Already in Use
ShadowEye will prompt to use alternative port (5002).

### API Key Configuration
Set environment variables:
```bash
export SHODAN_API_KEY="your_key"
export VIRUSTOTAL_API_KEY="your_key"
export HUNTER_API_KEY="your_key"
```

Or configure via UI (coming soon).

---

## 📊 Comparison: Sentinel Core vs Commercial Tools

| Feature | Sentinel Core | Maltego | Recorded Future | SpiderFoot |
|---------|--------------|---------|-----------------|------------|
| **Price** | FREE | $2,000+/yr | $50,000+/yr | Free/$$ |
| **Custom Scripts** | ✅ Full Python | ❌ Limited | ❌ No | ⚠️ Limited |
| **Kali Tools** | ✅ 20+ Native | ❌ Transforms | ❌ None | ⚠️ Some |
| **Async Workers** | ✅ 5 Parallel | ❌ Sequential | ✅ Cloud | ⚠️ Limited |
| **STIX Export** | ✅ 2.1 Standard | ⚠️ Proprietary | ✅ Yes | ⚠️ Partial |
| **Report Formats** | ✅ 4 Types | ⚠️ PDF | ✅ Multiple | ⚠️ Limited |
| **Graph Analysis** | ✅ Maltego-style | ✅ Excellent | ⚠️ Basic | ⚠️ Basic |
| **Offline Mode** | ✅ Full Support | ⚠️ Limited | ❌ Cloud Only | ✅ Yes |

---

## 🌟 Roadmap

### Phase 1: Core Enhancement ✅
- [x] Real module execution engine
- [x] Async task queue with workers
- [x] Circuit breakers & retries
- [x] Dynamic script engine
- [x] Kali/Parrot tool integration
- [x] Case ownership security

### Phase 2: Intelligence Model ✅
- [x] Normalized entity schema
- [x] Relationship mapping
- [x] Confidence scoring
- [x] STIX 2.1 export
- [x] Evidence chain of custody

### Phase 3: Advanced Features (In Progress)
- [ ] PostgreSQL backend support
- [ ] Redis queue for scale
- [ ] Multi-user collaboration
- [ ] ATT&CK mapping
- [ ] MISP integration
- [ ] TAXII client/server
- [ ] Playbook automation

### Phase 4: Enterprise Ready
- [ ] Docker/Kubernetes deployment
- [ ] High availability clustering
- [ ] Role-based access control (RBAC)
- [ ] Two-factor authentication
- [ ] API rate limiting
- [ ] Threat intelligence sharing

---

## 🤝 Contributing

We welcome contributions from the security community! Please ensure:
1. All code follows ethical guidelines
2. Only legal, public data sources are used
3. Proper documentation is included
4. Security best practices are maintained

### How to Contribute
1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

---

## 📄 License

This project is provided for **educational and authorized security research purposes only**. 

Users are solely responsible for complying with all applicable laws and regulations in their jurisdiction.

**Developer**: Syed Abrar (Cyb3rvolt3x)  
**Organization**: SentinelReign.com  
**Classification**: ELITE TIER  

---

## 🏆 Hall of Fame

Special thanks to:
- Intelligence agencies providing operational feedback
- Bug bounty hunters testing at scale
- Red team operators pushing boundaries
- SOC analysts validating workflows

---

## 📞 Contact & Support

- **Website**: [SentinelReign.com](https://sentinelreign.com)
- **Developer**: Syed Abrar (@Cyb3rvolt3x)
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions

---

**⚔️ Remember**: This is a weapon of mass reconnaissance. Use it responsibly, ethically, and legally. The difference between a hero and a criminal is authorization.

---

*Built with 🖤 by the security community, for the security community.*
