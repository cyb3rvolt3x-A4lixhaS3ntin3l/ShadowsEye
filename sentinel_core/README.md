# 🛡️ Sentinel Core - Advanced OSINT Framework

A professional, modular Open Source Intelligence (OSINT) reconnaissance platform designed for authorized security research, threat intelligence, and defensive security operations.

## ⚠️ Legal Disclaimer

**This tool is intended for legitimate security purposes only:**
- Authorized penetration testing
- Security research on systems you own or have explicit permission to test
- Threat intelligence gathering
- Defensive security operations
- Educational purposes in controlled environments

**Unauthorized use against systems without permission is illegal and violates computer fraud laws worldwide.**

## ✨ Features

### 🔐 Security & Compliance
- **Secure Authentication**: Bcrypt password hashing with session management
- **Audit Logging**: Complete action tracking for compliance and accountability
- **Access Control**: User-based case ownership and permissions
- **Session Management**: Persistent investigation sessions with SQLite backend

### 🎯 Core Capabilities
- **Case Management**: Organize investigations into separate cases
- **Maltego-like Visualization**: Interactive graph visualization using Cytoscape.js
- **Entity Relationship Mapping**: Link domains, IPs, emails, persons, organizations
- **Module System**: Extensible architecture for adding new OSINT modules

### 📊 Built-in OSINT Modules

| Module | Description | API Key Required |
|--------|-------------|------------------|
| WHOIS Lookup | Domain registration information | No |
| DNS Enumeration | DNS records & subdomain discovery | No |
| SSL Analysis | Certificate details & validity | No |
| Certificate Transparency | Subdomain discovery via CT logs | No |
| Shodan Search | Internet device search | Yes (free tier) |
| VirusTotal | File/URL analysis | Yes (free tier) |
| Wayback Machine | Historical web archives | No |
| Hunter.io | Email finder | Yes (free tier) |

### 🎨 Web Interface
- Modern, responsive UI with dark theme
- Interactive entity graph with auto-layout
- Real-time module execution
- Entity and relationship management
- Audit log viewer

## 🚀 Installation

### Prerequisites
- Python 3.8+
- pip package manager
- whois command (`apt-get install whois` on Debian/Ubuntu)

### Setup Steps

1. **Clone/Navigate to the project:**
```bash
cd /workspace/sentinel_core
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Run the application:**
```bash
python app.py
```

4. **Access the web interface:**
```
http://localhost:5000
```

### Default Credentials
- **Username:** `admin`
- **Password:** `admin123`

**⚠️ Change these credentials immediately after first login!**

## 📖 Usage Guide

### Creating a Case
1. Log in with your credentials
2. Click "New Case" on the dashboard
3. Enter case name and description
4. Click "Create Case"

### Adding Entities
1. Open a case
2. In the left panel, select entity type (Domain, IP, Email, etc.)
3. Enter the value and click "Add Entity"
4. Entity appears on the graph

### Creating Relationships
1. Note the Entity IDs from the graph or entity list
2. In the right panel, enter source and target entity IDs
3. Select relationship type (owns, resolves_to, hosted_on, etc.)
4. Click "Create Link"

### Running OSINT Modules
1. Click any module in the left panel
2. Enter the target (domain, IP, URL, etc.)
3. Click "Run"
4. Results are automatically added as entities

### Graph Visualization
- **Auto Layout**: Automatically arrange nodes for better visibility
- **Drag Nodes**: Reposition entities manually
- **Zoom**: Use mouse wheel to zoom in/out
- **Color Coding**: Different entity types have different colors

## 🏗️ Architecture

```
sentinel_core/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── db/                    # SQLite database storage
├── modules/               # OSINT modules
│   ├── whois_module.py
│   ├── dns_module.py
│   ├── ssl_module.py
│   └── crtsh_module.py
├── templates/             # HTML templates
│   ├── login.html
│   ├── dashboard.html
│   ├── case.html
│   └── audit.html
├── static/                # Static assets
│   ├── css/
│   ├── js/
│   └── images/
└── logs/                  # Application logs
```

## 🔧 Adding Custom Modules

Create a new module in `modules/`:

```python
#!/usr/bin/env python3
"""
Custom Module Description
"""

def run_module(target):
    """
    Main function that executes the module
    Returns dict with 'status' and 'data' keys
    """
    # Your implementation here
    return {
        'status': 'success',
        'target': target,
        'data': {'result': 'your data'}
    }
```

Then add it to the module list in `app.py`.

## 📝 Database Schema

- **users**: User accounts with hashed passwords
- **cases**: Investigation cases
- **entities**: Graph nodes (domains, IPs, emails, etc.)
- **relationships**: Graph edges linking entities
- **audit_log**: Complete action history

## 🔒 Security Best Practices

1. **Change default credentials** immediately
2. **Use HTTPS** in production (configure with reverse proxy)
3. **Restrict access** to trusted networks only
4. **Regular backups** of the database
5. **Review audit logs** periodically
6. **Keep dependencies updated**

## 🛠️ Troubleshooting

### Common Issues

**whois command not found:**
```bash
apt-get install whois  # Debian/Ubuntu
yum install whois      # RHEL/CentOS
```

**Port already in use:**
Edit `app.py` and change the port number in `app.run()`

**Database errors:**
Delete `db/sentinel.db` and restart the application

## 📄 License

This project is provided for educational and authorized security research purposes only. Users are responsible for complying with all applicable laws and regulations.

## 🤝 Contributing

Contributions should:
- Follow ethical guidelines
- Include proper documentation
- Use only legal, public data sources
- Maintain security best practices

## 🌟 Future Enhancements

- [ ] API key management UI
- [ ] Report generation (PDF/HTML)
- [ ] Collaborative case sharing
- [ ] Advanced filtering and search
- [ ] Data export/import
- [ ] Additional OSINT modules
- [ ] Two-factor authentication
- [ ] Docker containerization

---

**Remember**: With great power comes great responsibility. Always use this tool ethically and legally.
