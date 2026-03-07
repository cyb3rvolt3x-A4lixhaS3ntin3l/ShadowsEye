# 🛡️ SENTINEL CORE - ELITE OSINT PLATFORM

## The Ultimate Intelligence & Reconnaissance Platform for Elite Operators

**Built for:** RAW | MOSSAD | IB | Military Cyber Commands | Elite Ethical Hackers | SOC Teams

---

## 🔥 EXTREME FEATURES

### 1. **Dynamic Script Engine ("GOD MODE")**
- Execute custom Python scripts directly from the frontend
- Pre-built elite templates for rapid operations:
  - `subdomain_bruteforce_extreme` - Multi-tool chain enumeration
  - `vuln_scan_nuclei_critical` - Critical vulnerability scanning
  - `ip_recon_asn_bgp` - BGP/ASN intelligence gathering
- Real-time entity discovery and injection into intelligence graph
- Full API access to internal tools, databases, and external services

### 2. **20+ Elite Tool Integration** (Kali/Parrot OS Native)
**Reconnaissance:**
- Amass, Subfinder, Assetfinder, theHarvester, Sherlock, Maigret
- HTTPX, WhatWeb, WAFW00F, Gobuster, FFUF

**Vulnerability Assessment:**
- Nuclei, SearchSploit, SQLMap

**Network Scanning:**
- Nmap, Naabu, Masscan

**Post-Exploitation:**
- ExifTool, Binwalk, JWT Tool

**All tools auto-detected and executable via unified API!**

### 3. **Automated Reconnaissance Chains**
- One-click full-spectrum recon automation
- Parallel execution with 5 async workers
- Circuit breakers, retries, timeout protection
- Automatic entity extraction and relationship mapping

### 4. **Maltego-Style Intelligence Graph**
- Visual link analysis with interactive network graphs
- Entity types: Domain, IP, ASN, Email, CVE, Vulnerability, URL, Person, Organization
- Relationship types: Resolves_To, Owned_By, Uses, Hosts, Associated_With
- Confidence scoring (0-100) with source reliability ratings (A-F)
- Path finding between entities (BFS algorithm)
- Infrastructure overlap detection across cases

### 5. **Professional Report Generation**
**Export Formats:**
- **Interactive HTML** - Embedded network visualization, metrics dashboard
- **STIX 2.1** - Threat intelligence sharing standard
- **JSON** - Machine-readable data export
- **Markdown** - Executive summaries and technical annexes

**Report Sections:**
- Executive Summary (C-level briefings)
- Risk Assessment (scored 0-100)
- Technical Annex (detailed findings)
- Entity Inventory (categorized)
- Relationship Maps
- Immediate Action Recommendations

### 6. **Multi-Case Workflow**
- Isolated case workspaces
- Cross-case entity correlation
- Chain of custody tracking
- Immutable audit logs
- User-based access control

---

## 🚀 QUICK START

### Installation
```bash
cd sentinel_core
pip install -r requirements.txt
python app.py
```

### Access
- **URL:** http://localhost:5001
- **Default Credentials:** admin / admin123

### API Endpoints

#### Custom Script Execution
```bash
# Execute builtin template
curl -X POST http://localhost:5001/api/script/execute \
  -F "script_name=subdomain_bruteforce_extreme" \
  -F "target=example.com" \
  -F "case_id=1"

# Execute custom script
curl -X POST http://localhost:5001/api/script/execute \
  -F "code=def run(ctx):\n    ctx.log('Hello from custom script')\n    ctx.add_entity('DOMAIN', 'test.com')" \
  -F "target=example.com" \
  -F "case_id=1"

# Save custom script
curl -X POST http://localhost:5001/api/script/save \
  -F "name=my_custom_recon" \
  -F "code=def run(ctx): ..."
```

#### Tool Execution
```bash
# List available tools
curl http://localhost:5001/api/tools/list

# Execute single tool
curl -X POST http://localhost:5001/api/tool/execute \
  -F "tool_name=nuclei" \
  -F "target=https://example.com"

# Run full recon chain
curl -X POST http://localhost:5001/api/recon/full-chain \
  -F "target=example.com" \
  -F "case_id=1"
```

#### Report Generation
```bash
# Generate HTML report
curl http://localhost:5001/api/report/generate/1?format=html

# Generate STIX export
curl http://localhost:5001/api/report/generate/1?format=stix

# Download report
curl http://localhost:5001/api/report/download/CASE_1_report_20240101_120000.html -o report.html
```

#### Graph Visualization
```bash
# Get graph data for D3.js/vis.js
curl http://localhost:5001/api/graph/visualize/1

# Export to STIX
curl http://localhost:5001/api/graph/export/1
```

---

## 📁 PROJECT STRUCTURE

```
sentinel_core/
├── engine/
│   ├── module_registry.py    # Module metadata & registration
│   ├── task_queue.py         # Async job queue with workers
│   └── script_engine.py      # Dynamic Python script execution ⭐
├── integrations/
│   ├── kali_tools.py         # Kali/Parrot tool wrappers
│   └── advanced_tools.py     # 20+ elite tool registry ⭐
├── models/
│   └── intelligence.py       # Normalized intel data model
├── modules/
│   ├── dns_module.py         # DNS enumeration (hardened)
│   ├── whois_module.py       # WHOIS lookups
│   ├── ssl_module.py         # SSL/TLS analysis
│   └── crtsh_module.py       # Certificate transparency
├── reports/
│   └── report_generator.py   # Multi-format report engine ⭐
├── templates/                # Web UI templates
├── db/                       # SQLite database
└── app.py                    # Main Flask application
```

---

## 🎯 USE CASES

### Bug Bounty Hunters
- Automated subdomain enumeration with multiple tools
- Vulnerability scanning with Nuclei critical templates
- Technology stack fingerprinting
- WAF detection
- One-click report generation for submissions

### Red Teams
- Attack surface mapping
- Infrastructure reconnaissance
- ASN/BGP analysis
- Email harvesting for phishing simulations
- Custom script execution for specialized ops

### SOC/Incident Response
- IOC enrichment
- Infrastructure correlation across incidents
- STIX 2.1 export for threat sharing
- Timeline reconstruction
- Evidence chain of custody

### Military/Gov Agencies
- Classified-grade audit logging
- Multi-analyst case isolation
- Source reliability scoring
- Intelligence confidence metrics
- Air-gapped deployment capable

---

## 🔧 CUSTOMIZATION

### Adding Custom Tools
Edit `integrations/advanced_tools.py`:
```python
self.tools["my_tool"] = ToolDefinition(
    name="MyTool",
    command="mytool",
    description="Custom tool description",
    category="recon",
    args_template=["-target", "{target}", "-option"],
    output_format="json"
)
```

### Creating Custom Scripts
Via API or save `.py` files in `user_modules/`:
```python
def run(ctx):
    ctx.log("Starting custom operation...", "INIT")
    
    # Use any Python library
    import requests
    resp = requests.get(f"https://api.example.com/{ctx.target}")
    
    # Add discovered entities
    for item in resp.json():
        ctx.add_entity("IP", item["ip"], confidence=90, source="custom-api")
    
    # Chain external tools
    result = ctx.run_tool(["nmap", "-sV", ctx.target])
    
    return {"status": "complete", "entities": ctx.entities}
```

---

## ⚙️ CONFIGURATION

### Environment Variables
```bash
export SENTINEL_DB_PATH=/path/to/sentinel.db
export SENTINEL_SECRET_KEY=your-secret-key
export AMASS_CONFIG=/path/to/amass.ini
export SHODAN_API_KEY=your-key
export VIRUSTOTAL_API_KEY=your-key
```

### Performance Tuning
```python
# In app.py, adjust worker count
task_queue.start_workers(num_workers=10)  # For high-volume ops

# Adjust timeouts per task
task_queue.submit_task(..., timeout=1800, max_retries=3)
```

---

## 📊 ARCHITECTURE

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Web UI    │────▶│   Flask API      │────▶│  Task Queue     │
│  (Browser)  │◀────│  (app.py)        │◀────│  (5 Workers)    │
└─────────────┘     └──────────────────┘     └─────────────────┘
                           │                        │
                           ▼                        ▼
                    ┌──────────────┐        ┌──────────────┐
                    │Script Engine │        │Tool Registry │
                    │(God Mode)    │        │(20+ Tools)   │
                    └──────────────┘        └──────────────┘
                           │                        │
                           ▼                        ▼
                    ┌──────────────────────────────────────┐
                    │       Intelligence Graph             │
                    │  (Entities + Relationships + Scores) │
                    └──────────────────────────────────────┘
                                   │
                                   ▼
                          ┌─────────────────┐
                          │Report Generator │
                          │HTML/STIX/JSON   │
                          └─────────────────┘
```

---

## 🛡️ SECURITY NOTES

**AUTHORIZED USE ONLY**
- This tool is designed for legitimate security research
- Always obtain proper authorization before scanning
- Respect target systems and rate limits
- Comply with all applicable laws and regulations

**Operational Security:**
- Audit logs track all user actions
- Case isolation prevents cross-contamination
- Evidence chain of custody maintained
- No data leaves your infrastructure unless configured

---

## 📜 LICENSE

MIT License - See LICENSE file for details

---

## 🌟 WHY SENTINEL CORE?

| Feature | Sentinel Core | Alternatives |
|---------|--------------|--------------|
| Dynamic Scripting | ✅ Full Python | ❌ Limited |
| Tool Integration | ✅ 20+ Native | ⚠️ 3-5 Tools |
| Async Execution | ✅ 5+ Workers | ❌ Blocking |
| Graph Analysis | ✅ Maltego-style | ⚠️ Basic |
| Report Formats | ✅ 4 Formats | ⚠️ PDF Only |
| STIX Export | ✅ 2.1 Standard | ❌ Proprietary |
| Custom Tools | ✅ Easy Add | ❌ Hard-coded |
| Price | ✅ Free/Open | 💰 $$$$ |

---

**Built by elite operators, for elite operators.**

*Sentinel Core - Your First Choice for Intelligence Operations.*
