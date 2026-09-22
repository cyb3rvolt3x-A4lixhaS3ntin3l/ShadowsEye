> **Advanced / optional — not the product CLI.**
>
> Strangers and lab demos should use the **repository-root** `shadowseye.py`.
> `sentinel_core/` is an extended UI + multi-module platform (Flask app, extra
> integrations). It is demoted for now: keep for maintainers who need the
> dashboard; do not treat it as the primary entry. See root `README.md`.
>
> **Authorized use only.** Use only on systems you own or have written permission
> to assess. This is a lab / defender inventory UI — not a chaos or attack toolkit.

---

# 🛡️ Sentinel Core — cybersecurity intelligence platform (optional UI)

## Overview
Sentinel Core is an optional dashboard around authorized recon and OSINT modules,
with AI-assisted analysis via NVIDIA NIM (Kimi) and a glassmorphism UI. Prefer the
root CLI for strangers and lab demos.

## Features

### 🔐 Security & Authentication
- Secure session-based authentication with bcrypt password hashing
- Role-based access control (Admin, Analyst)
- Comprehensive audit logging
- No auto-login - secure session management

### 🧠 Kimi AI Integration (NVIDIA NIM)
- Direct integration with `https://integrate.api.nvidia.com/v1/chat/completions`
- Model: `moonshotai/kimi-k2.5`
- AI roles (authorized analysis personas): IB, Mossad, RAW, Red Team, Blue Team, Threat Hunter, etc.
- Context-aware prompts with case data injection
- Agentic mode for automated tool chaining

### 🛠️ Real Security Tools (No Simulation)
**Reconnaissance:**
- WHOIS Lookup (python-whois)
- DNS Enumeration (dnspython)
- Subdomain Discovery
- GeoIP Lookup

**Web Analysis:**
- HTTP/HTTPS Probing
- SSL/TLS Certificate Analysis
- Technology Stack Detection

**Network:**
- Port Scanning (nmap/python-nmap)
- Service Enumeration

**Vulnerability:**
- Shodan Integration
- VirusTotal Integration

**Forensics:**
- Email Breach Check
- File Hash Analysis

### 🎨 UI
- **Framework:** Custom CSS with Glassmorphism
- **Design:** Neon accents, Inter font, dark theme
- **Navigation:** Collapsible sidebar with active state tracking
- **Interactivity:** Toast notifications, modal dialogs, real-time updates
- **Responsiveness:** Fully adaptive grid layouts

### 📊 Intelligence & Automation
- Interactive entity graph view
- Pre-built playbooks (Mitnick Recon, Bug Hunter, Network Assessment)
- AI-enhanced note-taking
- Auto-generated reports

### 🔧 Custom Tool Creator
- UI-based custom command definition
- Parameter templating
- Category organization

## Installation

```bash
cd sentinel_core
pip install -r requirements.txt
python app.py
```

## Admin credentials (first boot)

There is **no** committed default password.

- **Username:** `admin`
- **Password:** set `SHADOWSEYE_ADMIN_PASSWORD` in the environment before first boot,
  **or** leave it unset and read the one-time generated password printed to the console
  on first startup. Change it immediately after login. Never commit a known password.

## Configuration
1. Navigate to Settings page
2. Add your NVIDIA API key (from build.nvidia.com)
3. Optionally add Shodan and VirusTotal API keys
4. Configure AI model and agentic mode

## API Endpoints
- `/login` - Authentication
- `/dashboard` - Main dashboard
- `/cases` - Case management
- `/tools` - Security tools
- `/playbooks` - Automation workflows
- `/terminal` - Live terminal
- `/settings` - Configuration
- `/ai/analyze` - AI analysis endpoint

## Project Structure
```
sentinel_core/
├── app.py              # Main Flask application
├── config/
│   └── settings.json   # Persistent configuration
├── data/
│   └── sentinel.db     # SQLite database
├── templates/          # HTML templates
├── static/
│   ├── css/
│   │   └── style.css   # UI styles
│   └── js/
│       └── app.js      # Frontend JavaScript
└── logs/               # Audit logs
```

## Security Notes
- All passwords hashed with bcrypt
- Session-based authentication
- Command whitelisting in terminal
- Audit trail for all actions
- API keys stored securely in settings.json

## License
Proprietary — authorized security testing / lab use only. Unauthorized scanning is out of scope.
