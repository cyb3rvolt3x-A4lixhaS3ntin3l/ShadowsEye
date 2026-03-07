# 🛡️ SENTINEL CORE - ELITE OSINT PLATFORM

**Developed by:** Syed Abrar (Alias: Cyb3rvolt3x)  
**Organization:** [SentinelReign.com](https://sentinelreign.com)  
**Classification:** ELITE TIER - For Intelligence Agencies, Military & Ethical Hackers  

---

## 🎯 OVERVIEW

Sentinel Core is a **production-grade, modular OSINT platform** designed for:
- **RAW / MOSSAD / IB** Intelligence Operations
- **Military Cyber Commands** (USCYBERCOM, IDF, GCHQ, etc.)
- **Elite Bug Bounty Hunters** & Penetration Testers
- **SOC Teams** & Incident Responders
- **Threat Intelligence Analysts**

This is the **premier choice** for nation-state level reconnaissance, automated penetration testing workflows, and threat intelligence fusion.

---

## ⚡ KEY FEATURES

### 🔥 8 Built-in OSINT Modules
| Module | Description | API Key Required |
|--------|-------------|------------------|
| **DNS** | Comprehensive DNS enumeration with subdomain discovery | ❌ |
| **WHOIS** | Domain registration & ownership intelligence | ❌ |
| **SSL/TLS** | Certificate analysis & CT log correlation | ❌ |
| **CRTSH** | Subdomain discovery via Certificate Transparency | ❌ |
| **Shodan** | IoT device & service discovery | ✅ SHODAN_API_KEY |
| **VirusTotal** | Malware & URL reputation analysis | ✅ VIRUSTOTAL_API_KEY |
| **Wayback Machine** | Historical website archives | ❌ |
| **Hunter.io** | Professional email address discovery | ✅ HUNTER_API_KEY |

### 🛠️ 20+ Integrated Kali/Parrot Tools
Auto-detected and integrated:
- **Recon:** `amass`, `subfinder`, `assetfinder`, `theHarvester`, `sherlock`, `maigret`
- **Web:** `httpx`, `whatweb`, `wafw00f`, `gobuster`, `ffuf`
- **Vuln:** `nuclei`, `searchsploit`, `sqlmap`
- **Network:** `nmap`, `naabu`
- **Post-Exploit:** `exiftool`, `binwalk`, `jwt-tool`

### 🧠 Elite Automation Tactics

#### Kevin Mitnick's Social Engineering Recon
```python
# Auto-chain: Domain → Emails → Social Profiles → Password Breaches
target = "company.com"
1. Hunter.io → Employee emails
2. theHarvester → Additional emails & subdomains
3. Sherlock/Maigret → Social media profiles
4. DeHashed/HaveIBeenPwned → Credential leaks
```

#### RAW/MOSSAD Infrastructure Mapping
```python
# Complete infrastructure fingerprinting
target = "target.gov"
1. Amass (aggressive mode) → All subdomains
2. DNS enumeration → Record types (A, AAAA, MX, TXT, SPF, DMARC)
3. Shodan → Open ports, services, vulnerabilities
4. SSL analysis → Certificate chains, SANs
5. Nmap → Detailed port scanning
6. WhatWeb → Technology stack
7. Nuclei → Vulnerability detection
```

#### Top Bug Bounty Hunter Workflow
```python
# Automated bug hunting chain
target = "*.example.com"
1. Subdomain brute-forcing (Amass + Subfinder + Assetfinder)
2. HTTP probing (httpx) → Live hosts
3. Screenshot capture → Visual recon
4. Technology detection (WhatWeb)
5. Vulnerability scanning (Nuclei templates)
6. Parameter fuzzing (FFUF)
7. Report generation with PoC
```

#### Military-Grade Server Penetration Testing
```python
# Full server assessment
target = "192.168.1.100"
1. Nmap (-sS -sV -O -A) → Ports, versions, OS
2. Naabu → Fast port confirmation
3. Service-specific vuln scans
4. SearchSploit → Known exploits
5. JWT Tool → Token analysis (if web app)
6. ExifTool → Metadata extraction
7. Automated report with CVSS scores
```

### 🔄 Dynamic Script Engine ("GOD MODE")
Execute custom Python scripts directly from the UI or API:

**Builtin Templates:**
- `subdomain_bruteforce_extreme` - Multi-tool chain
- `vuln_scan_nuclei_critical` - Critical vuln detection
- `ip_recon_asn_bgp` - BGP/ASN intelligence

**Custom Scripts:**
```python
# Save your own automation
def my_custom_recon(target):
    results = {
        'subdomains': kali_tools.amass(target),
        'screenshots': advanced_tools.httpx_screenshots(target),
        'vulns': advanced_tools.nuclei_scan(target)
    }
    return results
```

### 📊 Maltego-Style Graph Analysis
- **Entity Types:** Domain, IP, ASN, Email, Certificate, Person, Organization, CVE, IOC
- **Relationships:** Resolves To, Owned By, Uses, Hosts, References
- **Confidence Scoring:** 0-100 with source reliability ratings (A-F)
- **Path Finding:** BFS algorithm to find connections between entities
- **Infrastructure Overlap:** Detect shared assets across campaigns

### 📑 Professional Report Generation
**Formats:**
- **Interactive HTML** with embedded network visualization (vis.js)
- **STIX 2.1** for threat intelligence sharing
- **JSON** for machine processing
- **PDF** (via browser print) for executive briefings

**Features:**
- Auto-logging of all actions to reports
- Live report editing
- Executive summaries with risk scores (0-100)
- Technical annexes with detailed findings
- IOC extraction & export
- Chain of custody evidence tracking

### 📝 Integrated Notes System
- Create case-specific notes
- Link notes to entities/evidence
- Markdown support
- Export with reports

---

## 🚀 INSTALLATION

### Prerequisites
- **Python 3.8+**
- **Kali Linux** or **Parrot OS** (recommended for tool integration)
- **Redis** (optional, for production queue)

### Quick Start
```bash
cd sentinel_core
pip install -r requirements.txt
python shadowseye.py
```

**Access:** http://localhost:5001  
**Default Credentials:** `admin` / `admin123`

⚠️ **CHANGE DEFAULT CREDENTIALS IMMEDIATELY!**

---

## 📖 API ENDPOINTS

### Authentication
- `POST /login` - User login
- `GET /logout` - User logout

### Cases
- `POST /case/new` - Create new case
- `GET /case/<id>` - View case details
- `GET /dashboard` - List all cases

### Module Execution
- `GET /api/modules` - List available modules
- `POST /api/module/run` - Execute module (async)
- `GET /api/task/status/<id>` - Get task status
- `GET /api/tasks` - List all tasks

### Advanced Recon
- `POST /api/kali-tools/comprehensive-recon` - Full Kali tool chain
- `POST /api/recon/full-chain` - Complete recon automation
- `GET /api/kali-tools/status` - Check available tools

### Custom Scripts
- `POST /api/script/execute` - Run custom/builtin script
- `POST /api/script/save` - Save custom script
- `GET /api/scripts/templates` - List builtin templates

### Tool Execution
- `GET /api/tools/list` - List all tools by category
- `POST /api/tool/execute` - Execute single tool

### Reports
- `GET /api/report/generate/<case_id>?format=html|stix|json` - Generate report
- `GET /api/report/download/<filename>` - Download report
- `GET /api/graph/visualize/<case_id>` - Graph data for visualization

### Entities & Relationships
- `POST /api/entity/add` - Add entity to case
- `POST /api/relationship/add` - Create relationship

---

## 🎯 USAGE EXAMPLES

### 1. Run DNS Enumeration
```bash
curl -X POST http://localhost:5001/api/module/run \
  -F "module_id=dns" \
  -F "target=example.com" \
  -F "case_id=1" \
  -F "priority=5"
```

### 2. Execute Custom Script
```bash
curl -X POST http://localhost:5001/api/script/execute \
  -F "script_name=subdomain_bruteforce_extreme" \
  -F "target=example.com" \
  -F "case_id=1"
```

### 3. Full Recon Chain
```bash
curl -X POST http://localhost:5001/api/recon/full-chain \
  -F "target=example.com" \
  -F "case_id=1"
```

### 4. Generate HTML Report
```bash
curl http://localhost:5001/api/report/generate/1?format=html \
  -o report.html
```

---

## 🔐 SECURITY FEATURES

- **Case Ownership Checks** - Users can only access their own cases
- **Audit Logging** - All actions logged with timestamps & IP addresses
- **Input Validation** - Strict schema validation on all inputs
- **Circuit Breakers** - Prevent cascade failures
- **Rate Limiting** - Configurable per-module rate limits
- **Secret Management** - Secure API key storage
- **Evidence Isolation** - Forensic-grade evidence storage in `/evidence/`

---

## 🏗️ ARCHITECTURE

```
sentinel_core/
├── engine/
│   ├── module_registry.py    # Module metadata & registration
│   ├── task_queue.py         # Async job processing (5 workers)
│   └── script_engine.py      # Dynamic Python script execution
├── modules/
│   ├── dns_module.py         # DNS enumeration
│   ├── whois_module.py       # WHOIS lookup
│   ├── ssl_module.py         # SSL analysis
│   ├── crtsh_module.py       # CT log search
│   ├── shodan_module.py      # Shodan integration
│   ├── virustotal_module.py  # VT analysis
│   ├── wayback_module.py     # Wayback Machine
│   └── hunter_module.py      # Hunter.io
├── integrations/
│   ├── kali_tools.py         # Kali/Parrot tools (12+)
│   └── advanced_tools.py     # Advanced security tools (20+)
├── models/
│   └── intelligence.py       # Normalized data model & graph
├── reports/
│   └── report_generator.py   # Multi-format report generation
├── evidence/                 # Forensic-grade evidence storage
├── user_scripts/             # Custom user scripts
├── custom_tools/             # User-created tools
├── shadowseye.py             # Elite launcher
└── app.py                    # Flask API & Web UI
```

---

## 📊 COMPARISON VS COMMERCIAL TOOLS

| Feature | Sentinel Core | Maltego | Recorded Future | Cobalt Strike |
|---------|--------------|---------|-----------------|---------------|
| Price | **FREE** | $15K+/yr | $50K+/yr | $100K+/yr |
| Custom Scripting | ✅ Full Python | ⚠️ Limited | ❌ | ⚠️ Aggressor |
| Tool Integration | ✅ 20+ Native | ⚠️ Transforms | ❌ | ✅ |
| Async Execution | ✅ 5 Workers | ❌ Sequential | ✅ | ✅ |
| Graph Analysis | ✅ Maltego-style | ✅ Excellent | ⚠️ Basic | ❌ |
| STIX Export | ✅ 2.1 Standard | ⚠️ Proprietary | ✅ | ❌ |
| Report Formats | ✅ 4 Types | ⚠️ PDF | ⚠️ PDF | ❌ |
| Kali Tools | ✅ Native | ❌ | ❌ | ❌ |
| Bug Bounty Workflow | ✅ Automated | ❌ | ❌ | ❌ |

---

## 🛡️ WATERMARK

All outputs include:
```
SentinelReign.com
Developed by Syed Abrar (Cyb3rvolt3x)
```

---

## ⚠️ LEGAL NOTICE

**This platform is designed for:**
- Authorized security research
- Bug bounty hunting (with written permission)
- Intelligence agency operations
- Military cyber warfare
- Corporate threat intelligence
- Penetration testing (with contract)

**Unauthorized use against systems without explicit permission is ILLEGAL and violates:**
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Information Technology Act - India
- Similar laws worldwide

**Users are solely responsible for compliance with applicable laws.**

---

## 📞 SUPPORT & CONTRIBUTION

**Developer:** Syed Abrar (Cyb3rvolt3x)  
**Organization:** SentinelReign.com  

### Contributing
1. Fork the repository
2. Create feature branch
3. Add tests
4. Submit pull request

### Reporting Issues
- Use GitHub Issues
- Include reproduction steps
- Specify environment (OS, Python version, tools installed)

---

## 🗺️ ROADMAP

### Phase 1 (Current)
- ✅ 8 built-in OSINT modules
- ✅ 20+ tool integrations
- ✅ Async task queue
- ✅ Graph analysis
- ✅ Report generation
- ✅ Custom scripting

### Phase 2 (In Progress)
- 🔄 Real-time collaboration
- 🔄 WebSocket live updates
- 🔄 Advanced correlation engine
- 🔄 ATT&CK mapping
- 🔄 MISP integration

### Phase 3 (Planned)
- ⏳ STIX/TAXII server
- ⏳ OpenCTI integration
- ⏳ ML-based anomaly detection
- ⏳ Automated playbook execution
- ⏳ Distributed worker scaling

---

## 📚 REFERENCES

- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [STIX 2.1 Specification](https://oasis-open.github.io/cti-documentation/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

**© 2024 SentinelReign.com | Developed by Syed Abrar (Cyb3rvolt3x)**

*"The best defense is intelligent offense."*
