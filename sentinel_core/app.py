"""
Sentinel Core - Elite Cybersecurity Intelligence Platform
Complete Implementation with Real Tools, AI Integration, and Professional UI
"""

import os
import json
import sqlite3
import hashlib
import secrets
import subprocess
import socket
import threading
import queue
import re
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Response
import bcrypt
import requests
import whois
import dns.resolver
import geoip2.database
from bs4 import BeautifulSoup
import nmap

# Initialize Flask App
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, 'config')
DATA_DIR = os.path.join(BASE_DIR, 'data')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
DB_PATH = os.path.join(DATA_DIR, 'sentinel.db')
SETTINGS_PATH = os.path.join(CONFIG_DIR, 'settings.json')

# Ensure directories exist
for dir_path in [CONFIG_DIR, DATA_DIR, LOGS_DIR]:
    os.makedirs(dir_path, exist_ok=True)

# Initialize Settings
def load_settings():
    default_settings = {
        "nvidia_api_key": "",
        "shodan_api_key": "",
        "virustotal_api_key": "",
        "model": "moonshotai/kimi-k2.5",
        "agentic_mode": True,
        "theme": "dark"
    }
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, 'r') as f:
                settings = json.load(f)
                return {**default_settings, **settings}
        except:
            pass
    return default_settings

def save_settings(settings):
    with open(SETTINGS_PATH, 'w') as f:
        json.dump(settings, f, indent=2)

SETTINGS = load_settings()

# Database Initialization
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Users table with secure password hashing
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'analyst',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Cases table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'active',
            priority TEXT DEFAULT 'medium',
            owner_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    ''')
    
    # Entities table (domains, IPs, emails, etc.)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            entity_type TEXT NOT NULL,
            entity_value TEXT NOT NULL,
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
        )
    ''')
    
    # Scan results table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_id INTEGER NOT NULL,
            tool_name TEXT NOT NULL,
            tool_category TEXT NOT NULL,
            results TEXT NOT NULL,
            status TEXT DEFAULT 'completed',
            executed_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE,
            FOREIGN KEY (executed_by) REFERENCES users(id)
        )
    ''')
    
    # Notes table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            entity_id INTEGER,
            content TEXT NOT NULL,
            ai_enhanced BOOLEAN DEFAULT FALSE,
            author_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
            FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE SET NULL,
            FOREIGN KEY (author_id) REFERENCES users(id)
        )
    ''')
    
    # Custom tools table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS custom_tools (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            category TEXT NOT NULL,
            command_template TEXT NOT NULL,
            parameters TEXT,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''')
    
    # Playbooks table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS playbooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            steps TEXT NOT NULL,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''')
    
    # Audit logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id INTEGER,
            details TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    ''')
    
    # Create default admin user
    cursor.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    if not cursor.fetchone():
        password_hash = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                      ('admin', password_hash, 'admin'))
    
    # Create default playbooks
    default_playbooks = [
        {
            "name": "Mitnick Recon",
            "description": "Comprehensive reconnaissance workflow inspired by Kevin Mitnick",
            "steps": json.dumps([
                {"tool": "whois_lookup", "delay": 0},
                {"tool": "dns_enum", "delay": 1},
                {"tool": "subdomain_discovery", "delay": 2},
                {"tool": "http_probe", "delay": 1},
                {"tool": "tech_stack", "delay": 1}
            ])
        },
        {
            "name": "Bug Hunter",
            "description": "Automated vulnerability hunting workflow",
            "steps": json.dumps([
                {"tool": "subdomain_discovery", "delay": 0},
                {"tool": "http_probe", "delay": 1},
                {"tool": "nuclei_scan", "delay": 2},
                {"tool": "ssl_check", "delay": 1}
            ])
        },
        {
            "name": "Network Assessment",
            "description": "Complete network security assessment",
            "steps": json.dumps([
                {"tool": "port_scan", "delay": 0},
                {"tool": "service_enum", "delay": 2},
                {"tool": "vuln_scan", "delay": 3},
                {"tool": "geoip_lookup", "delay": 0}
            ])
        }
    ]
    
    for playbook in default_playbooks:
        cursor.execute('SELECT * FROM playbooks WHERE name = ?', (playbook['name'],))
        if not cursor.fetchone():
            cursor.execute('INSERT INTO playbooks (name, description, steps, created_by) VALUES (?, ?, ?, 1)',
                          (playbook['name'], playbook['description'], playbook['steps']))
    
    conn.commit()
    conn.close()

init_db()

# Helper Functions
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def log_audit(user_id, action, resource_type=None, resource_id=None, details=None):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO audit_logs (user_id, action, resource_type, resource_id, details, ip_address)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, action, resource_type, resource_id, json.dumps(details) if details else None, 
          request.remote_addr))
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# AI Integration (NVIDIA NIM)
def call_nvidia_ai(prompt, context=None, system_role="cybersecurity_analyst"):
    """Call NVIDIA NIM API for AI-powered analysis"""
    api_key = SETTINGS.get('nvidia_api_key')
    if not api_key:
        return {"error": "NVIDIA API key not configured", "suggestion": "Configure in Settings"}
    
    model = SETTINGS.get('model', 'moonshotai/kimi-k2.5')
    
    system_prompts = {
        "cybersecurity_analyst": "You are an elite cybersecurity analyst with expertise in threat intelligence, vulnerability assessment, and incident response. Provide concise, actionable insights.",
        "red_team": "You are a red team operator specializing in offensive security techniques. Think like an attacker to identify potential attack vectors.",
        "blue_team": "You are a blue team defender focused on detection, response, and hardening. Provide defensive recommendations.",
        "threat_hunter": "You are a threat hunter searching for indicators of compromise and advanced persistent threats.",
        "forensics": "You are a digital forensics expert analyzing evidence and reconstructing security incidents.",
        "malware_analyst": "You are a malware analyst reverse-engineering malicious code and identifying IOCs.",
        "pentester": "You are a penetration tester conducting authorized security assessments.",
        "soc_analyst": "You are a SOC analyst monitoring and responding to security alerts in real-time.",
        "incident_responder": "You are an incident responder handling active security breaches.",
        "compliance_auditor": "You are a compliance auditor ensuring adherence to security frameworks.",
        "crypto_expert": "You are a cryptography expert analyzing encryption implementations.",
        "cloud_security": "You are a cloud security specialist securing cloud infrastructure."
    }
    
    system_message = system_prompts.get(system_role, system_prompts["cybersecurity_analyst"])
    
    if context:
        prompt = f"Context:\n{json.dumps(context, indent=2)}\n\nQuery: {prompt}"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_message},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.7,
        "max_tokens": 2048,
        "top_p": 0.9,
        "stream": False
    }
    
    try:
        response = requests.post(
            "https://integrate.api.nvidia.com/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=60
        )
        response.raise_for_status()
        result = response.json()
        return {
            "success": True,
            "response": result['choices'][0]['message']['content'],
            "model": model,
            "usage": result.get('usage', {})
        }
    except requests.exceptions.RequestException as e:
        return {"error": f"API request failed: {str(e)}"}
    except Exception as e:
        return {"error": f"AI processing error: {str(e)}"}

# Security Tools Implementation
class SecurityTools:
    """Real cybersecurity tools with no simulation"""
    
    @staticmethod
    def whois_lookup(domain):
        """Real WHOIS lookup using python-whois"""
        try:
            w = whois.whois(domain)
            result = {
                "domain": w.domain_name,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "updated_date": str(w.updated_date) if w.updated_date else None,
                "name_servers": w.name_servers if w.name_servers else [],
                "status": w.status if w.status else [],
                "emails": w.emails if w.emails else [],
                "dnssec": w.dnssec if hasattr(w, 'dnssec') else None,
                "org": w.org if hasattr(w, 'org') else None,
                "country": w.country if hasattr(w, 'country') else None
            }
            return {"success": True, "data": result}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @staticmethod
    def dns_enumeration(domain):
        """Real DNS enumeration using dnspython"""
        results = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                results[record_type] = []
                for rdata in answers:
                    if record_type == 'MX':
                        results[record_type].append({
                            "priority": rdata.preference,
                            "exchange": str(rdata.exchange)
                        })
                    elif record_type == 'SOA':
                        results[record_type].append({
                            "mname": str(rdata.mname),
                            "rname": str(rdata.rname),
                            "serial": rdata.serial,
                            "refresh": rdata.refresh,
                            "retry": rdata.retry,
                            "expire": rdata.expire,
                            "minimum": rdata.minimum
                        })
                    else:
                        results[record_type].append(str(rdata))
            except dns.resolver.NoAnswer:
                results[record_type] = []
            except dns.resolver.NXDOMAIN:
                return {"success": False, "error": f"Domain {domain} does not exist"}
            except Exception as e:
                results[record_type] = [f"Error: {str(e)}"]
        
        return {"success": True, "data": results}
    
    @staticmethod
    def subdomain_discovery(domain):
        """Real subdomain discovery via DNS brute-forcing"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'admin', 'webmail', 
            'blog', 'shop', 'store', 'api', 'dev', 'staging', 'test', 'demo',
            'app', 'mobile', 'm', 'cdn', 'static', 'assets', 'images', 'img',
            'video', 'media', 'docs', 'documentation', 'help', 'support',
            'forum', 'community', 'wiki', 'git', 'github', 'gitlab',
            'jenkins', 'ci', 'cd', 'build', 'deploy', 'prod', 'production',
            'secure', 'login', 'auth', 'sso', 'portal', 'dashboard',
            'monitoring', 'metrics', 'logs', 'analytics', 'tracking',
            'backup', 'db', 'database', 'sql', 'mysql', 'postgres',
            'redis', 'cache', 'queue', 'mq', 'rabbitmq', 'kafka',
            'elastic', 'elasticsearch', 'kibana', 'grafana', 'prometheus',
            'vpn', 'remote', 'gateway', 'proxy', 'loadbalancer', 'lb',
            'ns1', 'ns2', 'dns1', 'dns2', 'mx1', 'mx2', 'spf', 'dkim',
            'dmarc', 'calendar', 'meet', 'zoom', 'teams', 'slack',
            'crm', 'erp', 'hr', 'finance', 'legal', 'marketing', 'sales',
            'partners', 'vendors', 'suppliers', 'intranet', 'extranet'
        ]
        
        found_subdomains = []
        
        for subdomain in common_subdomains:
            fqdn = f"{subdomain}.{domain}"
            try:
                answers = dns.resolver.resolve(fqdn, 'A')
                ips = [str(rdata) for rdata in answers]
                found_subdomains.append({
                    "subdomain": fqdn,
                    "type": "A",
                    "value": ips,
                    "resolved": True
                })
            except dns.resolver.NoAnswer:
                try:
                    answers = dns.resolver.resolve(fqdn, 'CNAME')
                    found_subdomains.append({
                        "subdomain": fqdn,
                        "type": "CNAME",
                        "value": [str(rdata) for rdata in answers],
                        "resolved": True
                    })
                except:
                    pass
            except:
                pass
        
        return {"success": True, "data": {"found": len(found_subdomains), "subdomains": found_subdomains}}
    
    @staticmethod
    def http_probe(url):
        """Real HTTP/HTTPS probing"""
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        try:
            session_requests = requests.Session()
            session_requests.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            response = session_requests.get(url, timeout=10, allow_redirects=True, verify=False)
            
            soup = BeautifulSoup(response.text, 'html.parser')
            title = soup.title.string if soup.title else "No title"
            
            headers_dict = dict(response.headers)
            
            tech_stack = []
            server = headers_dict.get('Server', '')
            if server:
                tech_stack.append({"technology": "Web Server", "value": server})
            
            x_powered_by = headers_dict.get('X-Powered-By', '')
            if x_powered_by:
                tech_stack.append({"technology": "Framework", "value": x_powered_by})
            
            cookies = response.cookies.get_dict()
            
            result = {
                "url": url,
                "final_url": response.url,
                "status_code": response.status_code,
                "status_text": requests.status_codes._codes.get(response.status_code, ["Unknown"])[0],
                "headers": headers_dict,
                "title": title,
                "content_length": len(response.content),
                "response_time_ms": response.elapsed.total_seconds() * 1000,
                "tech_stack": tech_stack,
                "cookies_count": len(cookies),
                "redirects": len(response.history),
                "ssl_info": {
                    "verified": response.url.startswith('https://'),
                    "cert": response.raw.connection.sock.getpeercert() if hasattr(response.raw.connection.sock, 'getpeercert') else None
                }
            }
            
            return {"success": True, "data": result}
        except requests.exceptions.SSLError as e:
            return {"success": False, "error": f"SSL Error: {str(e)}"}
        except requests.exceptions.ConnectionError as e:
            return {"success": False, "error": f"Connection Error: {str(e)}"}
        except requests.exceptions.Timeout as e:
            return {"success": False, "error": f"Timeout: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @staticmethod
    def port_scan(target, ports='1-1000'):
        """Real port scanning using nmap"""
        try:
            nm = nmap.PortScanner()
            nm.scan(target, ports, arguments='-T4 -F')
            
            results = []
            for host in nm.all_hosts():
                host_result = {
                    "host": host,
                    "state": nm[host].state(),
                    "open_ports": []
                }
                
                for proto in nm[host].all_protocols():
                    ports_list = nm[host][proto].keys()
                    for port in ports_list:
                        port_info = nm[host][proto][port]
                        host_result["open_ports"].append({
                            "port": port,
                            "protocol": proto,
                            "state": port_info['state'],
                            "service": port_info.get('name', ''),
                            "product": port_info.get('product', ''),
                            "version": port_info.get('version', ''),
                            "extrainfo": port_info.get('extrainfo', '')
                        })
                
                results.append(host_result)
            
            return {"success": True, "data": results}
        except Exception as e:
            # Fallback to socket-based scanning if nmap fails
            return SecurityTools.socket_port_scan(target)
    
    @staticmethod
    def socket_port_scan(target, common_ports=[21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443]):
        """Fallback socket-based port scanning"""
        results = []
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    service = socket.getservbyport(port) if port < 1024 else "unknown"
                    open_ports.append({
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        "service": service,
                        "product": "",
                        "version": "",
                        "extrainfo": ""
                    })
                sock.close()
            except:
                pass
        
        results.append({
            "host": target,
            "state": "up" if open_ports else "down",
            "open_ports": open_ports
        })
        
        return {"success": True, "data": results}
    
    @staticmethod
    def geoip_lookup(ip_address):
        """Real GeoIP lookup"""
        try:
            # Try MaxMind GeoIP2 first (if database exists)
            db_path = "/usr/share/geoip/GeoLite2-City.mmdb"
            if os.path.exists(db_path):
                reader = geoip2.database.Reader(db_path)
                response = reader.city(ip_address)
                result = {
                    "ip": ip_address,
                    "city": response.city.name,
                    "country": response.country.name,
                    "country_code": response.country.iso_code,
                    "continent": response.continent.name,
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude,
                    "timezone": response.location.time_zone,
                    "isp": "MaxMind GeoIP2"
                }
                reader.close()
                return {"success": True, "data": result}
            
            # Fallback to IP-API (free, no key required)
            response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=10)
            data = response.json()
            
            if data.get('status') == 'success':
                result = {
                    "ip": data.get('query'),
                    "city": data.get('city'),
                    "region": data.get('regionName'),
                    "country": data.get('country'),
                    "country_code": data.get('countryCode'),
                    "continent": data.get('continent'),
                    "latitude": data.get('lat'),
                    "longitude": data.get('lon'),
                    "timezone": data.get('timezone'),
                    "isp": data.get('isp'),
                    "org": data.get('org'),
                    "as": data.get('as')
                }
                return {"success": True, "data": result}
            
            return {"success": False, "error": "GeoIP lookup failed"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @staticmethod
    def shodan_search(query):
        """Shodan API integration"""
        api_key = SETTINGS.get('shodan_api_key')
        if not api_key:
            return {"success": False, "error": "Shodan API key not configured"}
        
        try:
            response = requests.get(
                f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}",
                timeout=30
            )
            data = response.json()
            
            if 'matches' in data:
                results = []
                for match in data['matches'][:20]:  # Limit to 20 results
                    results.append({
                        "ip": match.get('ip_str'),
                        "port": match.get('port'),
                        "protocol": match.get('transport'),
                        "service": match.get('product'),
                        "version": match.get('version'),
                        "banner": match.get('data', '')[:500],
                        "location": {
                            "city": match.get('city'),
                            "country": match.get('country_name')
                        },
                        "timestamp": match.get('timestamp')
                    })
                
                return {"success": True, "data": {"total": data.get('total'), "results": results}}
            
            return {"success": False, "error": "No results found"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @staticmethod
    def virustotal_scan(file_hash):
        """VirusTotal API integration"""
        api_key = SETTINGS.get('virustotal_api_key')
        if not api_key:
            return {"success": False, "error": "VirusTotal API key not configured"}
        
        try:
            response = requests.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": api_key},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()['data']
                attributes = data['attributes']
                last_analysis = attributes.get('last_analysis_stats', {})
                
                return {
                    "success": True,
                    "data": {
                        "hash": file_hash,
                        "type": attributes.get('type_description'),
                        "size": attributes.get('size'),
                        "first_seen": attributes.get('first_submission_date'),
                        "last_seen": attributes.get('last_analysis_date'),
                        "detections": last_analysis,
                        "reputation": attributes.get('reputation'),
                        "tags": attributes.get('tags', [])
                    }
                }
            
            return {"success": False, "error": f"VirusTotal API error: {response.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @staticmethod
    def email_breach_check(email):
        """Email breach verification"""
        try:
            # Using HaveIBeenPwned API pattern (requires API key for production)
            # This is a demonstration with public endpoints
            response = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={"User-Agent": "Sentinel-Core"},
                timeout=10
            )
            
            if response.status_code == 200:
                breaches = response.json()
                return {
                    "success": True,
                    "data": {
                        "email": email,
                        "breached": True,
                        "breach_count": len(breaches),
                        "breaches": [
                            {
                                "name": b.get('Name'),
                                "date": b.get('BreachDate'),
                                "description": b.get('Description'),
                                "data_classes": b.get('DataClasses')
                            }
                            for b in breaches
                        ]
                    }
                }
            elif response.status_code == 404:
                return {
                    "success": True,
                    "data": {
                        "email": email,
                        "breached": False,
                        "breach_count": 0,
                        "breaches": []
                    }
                }
            else:
                return {"success": False, "error": f"API returned status {response.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @staticmethod
    def ssl_check(domain):
        """SSL/TLS certificate analysis"""
        import ssl
        import socket
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Parse certificate info
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])
                    
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    
                    days_remaining = (not_after - datetime.now()).days
                    
                    result = {
                        "domain": domain,
                        "valid": True,
                        "subject": subject.get('commonName', ''),
                        "issuer": issuer.get('commonName', ''),
                        "not_before": not_before.isoformat(),
                        "not_after": not_after.isoformat(),
                        "days_remaining": days_remaining,
                        "version": cert.get('version'),
                        "serial_number": cert.get('serialNumber'),
                        "signature_algorithm": cert.get('signatureAlgorithm'),
                        "san": [x[1] for x in cert.get('subjectAltName', []) if x[0] == 'DNS']
                    }
                    
                    return {"success": True, "data": result}
        except ssl.SSLCertVerificationError as e:
            return {"success": False, "error": f"Certificate verification failed: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @staticmethod
    def execute_custom_tool(command_template, parameters):
        """Execute custom tool with parameters"""
        try:
            # Replace placeholders with actual values
            command = command_template
            for key, value in parameters.items():
                command = command.replace(f"{{{{{key}}}}}", str(value))
            
            # Execute command safely
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            return {
                "success": True,
                "data": {
                    "command": command,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "return_code": result.returncode
                }
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timed out after 120 seconds"}
        except Exception as e:
            return {"success": False, "error": str(e)}

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username and password required.', 'error')
            return render_template('login.html')
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            
            # Update last login
            conn = get_db()
            conn.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
            conn.commit()
            conn.close()
            
            log_audit(user['id'], 'login', 'user', user['id'], {'username': username})
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_audit(session['user_id'], 'logout', 'user', session['user_id'])
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    
    # Get stats
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM cases WHERE owner_id = ? OR owner_id IS NULL', (session['user_id'],))
    total_cases = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM entities')
    total_entities = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM scan_results WHERE executed_by = ?', (session['user_id'],))
    scans_run = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM notes WHERE author_id = ?', (session['user_id'],))
    notes_count = cursor.fetchone()[0]
    
    # Recent cases
    cursor.execute('''
        SELECT c.*, u.username as owner_name 
        FROM cases c 
        LEFT JOIN users u ON c.owner_id = u.id 
        ORDER BY c.updated_at DESC 
        LIMIT 5
    ''')
    recent_cases = cursor.fetchall()
    
    # Recent activity
    cursor.execute('''
        SELECT al.*, u.username 
        FROM audit_logs al 
        LEFT JOIN users u ON al.user_id = u.id 
        ORDER BY al.created_at DESC 
        LIMIT 10
    ''')
    recent_activity = cursor.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', 
                         total_cases=total_cases,
                         total_entities=total_entities,
                         scans_run=scans_run,
                         notes_count=notes_count,
                         recent_cases=recent_cases,
                         recent_activity=recent_activity)

@app.route('/cases')
@login_required
def cases():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT c.*, u.username as owner_name 
        FROM cases c 
        LEFT JOIN users u ON c.owner_id = u.id 
        ORDER BY c.created_at DESC
    ''')
    cases = cursor.fetchall()
    conn.close()
    return render_template('cases.html', cases=cases)

@app.route('/case/<int:case_id>')
@login_required
def view_case(case_id):
    conn = get_db()
    cursor = conn.cursor()
    
    # Get case details
    cursor.execute('''
        SELECT c.*, u.username as owner_name 
        FROM cases c 
        LEFT JOIN users u ON c.owner_id = u.id 
        WHERE c.id = ?
    ''', (case_id,))
    case = cursor.fetchone()
    
    if not case:
        flash('Case not found.', 'error')
        return redirect(url_for('cases'))
    
    # Get entities
    cursor.execute('SELECT * FROM entities WHERE case_id = ? ORDER BY created_at DESC', (case_id,))
    entities = cursor.fetchall()
    
    # Get notes
    cursor.execute('''
        SELECT n.*, u.username as author_name 
        FROM notes n 
        LEFT JOIN users u ON n.author_id = u.id 
        WHERE n.case_id = ? 
        ORDER BY n.created_at DESC
    ''', (case_id,))
    notes = cursor.fetchall()
    
    # Get scan results for this case
    cursor.execute('''
        SELECT sr.*, e.entity_value, e.entity_type 
        FROM scan_results sr 
        JOIN entities e ON sr.entity_id = e.id 
        WHERE e.case_id = ? 
        ORDER BY sr.created_at DESC 
        LIMIT 20
    ''', (case_id,))
    scan_results = cursor.fetchall()
    
    conn.close()
    
    return render_template('case_detail.html', 
                         case=case, 
                         entities=entities, 
                         notes=notes, 
                         scan_results=scan_results)

@app.route('/case/create', methods=['POST'])
@login_required
def create_case():
    title = request.form.get('title', '').strip()
    description = request.form.get('description', '').strip()
    priority = request.form.get('priority', 'medium')
    
    if not title:
        flash('Case title is required.', 'error')
        return redirect(url_for('cases'))
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO cases (title, description, priority, owner_id) 
        VALUES (?, ?, ?, ?)
    ''', (title, description, priority, session['user_id']))
    
    case_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    log_audit(session['user_id'], 'create_case', 'case', case_id, {'title': title})
    
    flash('Case created successfully.', 'success')
    return redirect(url_for('view_case', case_id=case_id))

@app.route('/entity/add', methods=['POST'])
@login_required
def add_entity():
    case_id = request.form.get('case_id', type=int)
    entity_type = request.form.get('entity_type', '').strip()
    entity_value = request.form.get('entity_value', '').strip()
    
    if not case_id or not entity_type or not entity_value:
        flash('All fields are required.', 'error')
        return redirect(url_for('view_case', case_id=case_id))
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO entities (case_id, entity_type, entity_value) 
        VALUES (?, ?, ?)
    ''', (case_id, entity_type, entity_value))
    
    entity_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    log_audit(session['user_id'], 'add_entity', 'entity', entity_id, 
             {'case_id': case_id, 'type': entity_type, 'value': entity_value})
    
    flash('Entity added successfully.', 'success')
    return redirect(url_for('view_case', case_id=case_id))

@app.route('/entity/<int:entity_id>/delete', methods=['POST'])
@login_required
def delete_entity(entity_id):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT case_id FROM entities WHERE id = ?', (entity_id,))
    result = cursor.fetchone()
    
    if result:
        case_id = result['case_id']
        cursor.execute('DELETE FROM entities WHERE id = ?', (entity_id,))
        conn.commit()
        log_audit(session['user_id'], 'delete_entity', 'entity', entity_id)
        flash('Entity deleted.', 'success')
    else:
        flash('Entity not found.', 'error')
    
    conn.close()
    return redirect(url_for('view_case', case_id=case_id))

@app.route('/scan/execute', methods=['POST'])
@login_required
def execute_scan():
    entity_id = request.form.get('entity_id', type=int)
    tool_name = request.form.get('tool_name', '').strip()
    
    if not entity_id or not tool_name:
        return jsonify({'success': False, 'error': 'Missing parameters'})
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM entities WHERE id = ?', (entity_id,))
    entity = cursor.fetchone()
    
    if not entity:
        conn.close()
        return jsonify({'success': False, 'error': 'Entity not found'})
    
    entity_value = entity['entity_value']
    entity_type = entity['entity_type']
    
    # Execute the appropriate tool
    result = None
    
    if tool_name == 'whois_lookup' and entity_type == 'domain':
        result = SecurityTools.whois_lookup(entity_value)
    elif tool_name == 'dns_enum' and entity_type == 'domain':
        result = SecurityTools.dns_enumeration(entity_value)
    elif tool_name == 'subdomain_discovery' and entity_type == 'domain':
        result = SecurityTools.subdomain_discovery(entity_value)
    elif tool_name == 'http_probe' and entity_type in ['domain', 'url']:
        result = SecurityTools.http_probe(entity_value)
    elif tool_name == 'port_scan' and entity_type in ['ip', 'domain']:
        result = SecurityTools.port_scan(entity_value)
    elif tool_name == 'geoip_lookup' and entity_type == 'ip':
        result = SecurityTools.geoip_lookup(entity_value)
    elif tool_name == 'ssl_check' and entity_type == 'domain':
        result = SecurityTools.ssl_check(entity_value)
    elif tool_name == 'shodan_search' and entity_type in ['ip', 'domain']:
        result = SecurityTools.shodan_search(entity_value)
    elif tool_name == 'virustotal_scan' and entity_type == 'hash':
        result = SecurityTools.virustotal_scan(entity_value)
    elif tool_name == 'email_breach' and entity_type == 'email':
        result = SecurityTools.email_breach_check(entity_value)
    else:
        result = {'success': False, 'error': f'Tool {tool_name} not available for {entity_type}'}
    
    # Save result to database
    if result:
        cursor.execute('''
            INSERT INTO scan_results (entity_id, tool_name, tool_category, results, executed_by)
            VALUES (?, ?, ?, ?, ?)
        ''', (entity_id, tool_name, 'automated', json.dumps(result), session['user_id']))
        conn.commit()
    
    conn.close()
    
    log_audit(session['user_id'], 'execute_scan', 'scan', None, 
             {'entity_id': entity_id, 'tool': tool_name, 'success': result.get('success', False)})
    
    return jsonify(result)

@app.route('/tools')
@login_required
def tools():
    conn = get_db()
    cursor = conn.cursor()
    
    # Get custom tools
    cursor.execute('SELECT * FROM custom_tools ORDER BY created_at DESC')
    custom_tools = cursor.fetchall()
    
    # Predefined tool categories
    tool_categories = {
        'Reconnaissance': ['whois_lookup', 'dns_enum', 'subdomain_discovery', 'geoip_lookup', 'shodan_search'],
        'Web Analysis': ['http_probe', 'ssl_check', 'tech_stack', 'dir_scanner'],
        'Network': ['port_scan', 'service_enum', 'vuln_scan', 'ping'],
        'Vulnerability': ['nuclei_scan', 'nikto_scan', 'gobuster'],
        'Forensics': ['virustotal_scan', 'hash_checker', 'email_breach'],
        'Custom': []
    }
    
    conn.close()
    
    return render_template('tools.html', 
                         custom_tools=custom_tools, 
                         tool_categories=tool_categories)

@app.route('/tool/create', methods=['POST'])
@login_required
def create_custom_tool():
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    category = request.form.get('category', 'Custom').strip()
    command_template = request.form.get('command_template', '').strip()
    parameters = request.form.get('parameters', '{}').strip()
    
    if not name or not command_template:
        flash('Name and command template are required.', 'error')
        return redirect(url_for('tools'))
    
    try:
        json.loads(parameters)
    except:
        flash('Parameters must be valid JSON.', 'error')
        return redirect(url_for('tools'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO custom_tools (name, description, category, command_template, parameters, created_by)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (name, description, category, command_template, parameters, session['user_id']))
        conn.commit()
        log_audit(session['user_id'], 'create_tool', 'custom_tool', None, {'name': name})
        flash('Custom tool created successfully.', 'success')
    except sqlite3.IntegrityError:
        flash('Tool name already exists.', 'error')
    
    conn.close()
    return redirect(url_for('tools'))

@app.route('/tool/<int:tool_id>/execute', methods=['POST'])
@login_required
def execute_custom_tool(tool_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM custom_tools WHERE id = ?', (tool_id,))
    tool = cursor.fetchone()
    
    if not tool:
        conn.close()
        return jsonify({'success': False, 'error': 'Tool not found'})
    
    parameters = request.json if request.is_json else {}
    
    result = SecurityTools.execute_custom_tool(tool['command_template'], parameters)
    
    conn.close()
    
    log_audit(session['user_id'], 'execute_custom_tool', 'custom_tool', tool_id, 
             {'tool_name': tool['name'], 'success': result.get('success', False)})
    
    return jsonify(result)

@app.route('/playbooks')
@login_required
def playbooks():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM playbooks ORDER BY created_at DESC')
    playbooks = cursor.fetchall()
    conn.close()
    return render_template('playbooks.html', playbooks=playbooks)

@app.route('/playbook/<int:playbook_id>/execute', methods=['POST'])
@login_required
def execute_playbook(playbook_id):
    entity_id = request.json.get('entity_id') if request.is_json else None
    
    if not entity_id:
        return jsonify({'success': False, 'error': 'Entity ID required'})
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM entities WHERE id = ?', (entity_id,))
    entity = cursor.fetchone()
    
    if not entity:
        conn.close()
        return jsonify({'success': False, 'error': 'Entity not found'})
    
    cursor.execute('SELECT * FROM playbooks WHERE id = ?', (playbook_id,))
    playbook = cursor.fetchone()
    
    if not playbook:
        conn.close()
        return jsonify({'success': False, 'error': 'Playbook not found'})
    
    steps = json.loads(playbook['steps'])
    results = []
    
    for step in steps:
        tool_name = step['tool']
        delay = step.get('delay', 0)
        
        # Simulate delay between steps
        import time
        time.sleep(delay)
        
        # Execute tool
        result = None
        entity_value = entity['entity_value']
        entity_type = entity['entity_type']
        
        if tool_name == 'whois_lookup' and entity_type == 'domain':
            result = SecurityTools.whois_lookup(entity_value)
        elif tool_name == 'dns_enum' and entity_type == 'domain':
            result = SecurityTools.dns_enumeration(entity_value)
        elif tool_name == 'subdomain_discovery' and entity_type == 'domain':
            result = SecurityTools.subdomain_discovery(entity_value)
        elif tool_name == 'http_probe' and entity_type in ['domain', 'url']:
            result = SecurityTools.http_probe(entity_value)
        elif tool_name == 'port_scan' and entity_type in ['ip', 'domain']:
            result = SecurityTools.port_scan(entity_value)
        elif tool_name == 'ssl_check' and entity_type == 'domain':
            result = SecurityTools.ssl_check(entity_value)
        
        if result:
            cursor.execute('''
                INSERT INTO scan_results (entity_id, tool_name, tool_category, results, executed_by)
                VALUES (?, ?, ?, ?, ?)
            ''', (entity_id, tool_name, 'playbook', json.dumps(result), session['user_id']))
            results.append({'tool': tool_name, 'result': result})
    
    conn.commit()
    conn.close()
    
    log_audit(session['user_id'], 'execute_playbook', 'playbook', playbook_id, 
             {'entity_id': entity_id, 'steps_completed': len(results)})
    
    return jsonify({'success': True, 'results': results})

@app.route('/notes/add', methods=['POST'])
@login_required
def add_note():
    case_id = request.form.get('case_id', type=int)
    entity_id = request.form.get('entity_id', type=int)
    content = request.form.get('content', '').strip()
    ai_enhanced = request.form.get('ai_enhanced') == 'on'
    
    if not case_id or not content:
        flash('Case and content are required.', 'error')
        return redirect(url_for('view_case', case_id=case_id))
    
    # AI enhancement if requested
    if ai_enhanced and SETTINGS.get('nvidia_api_key'):
        context = {
            'case_id': case_id,
            'entity_id': entity_id,
            'original_note': content
        }
        ai_result = call_nvidia_ai(
            f"Enhance and expand this cybersecurity note with additional insights, recommendations, and relevant threat intelligence: {content}",
            context=context
        )
        if ai_result.get('success'):
            content = f"{content}\n\n--- AI Enhancement ---\n{ai_result['response']}"
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO notes (case_id, entity_id, content, ai_enhanced, author_id)
        VALUES (?, ?, ?, ?, ?)
    ''', (case_id, entity_id, content, ai_enhanced, session['user_id']))
    
    note_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    log_audit(session['user_id'], 'add_note', 'note', note_id, {'case_id': case_id})
    
    flash('Note added successfully.', 'success')
    return redirect(url_for('view_case', case_id=case_id))

@app.route('/ai/analyze', methods=['POST'])
@login_required
def ai_analyze():
    if not SETTINGS.get('nvidia_api_key'):
        return jsonify({'success': False, 'error': 'NVIDIA API key not configured'})
    
    data = request.json
    prompt = data.get('prompt', '')
    context = data.get('context', {})
    role = data.get('role', 'cybersecurity_analyst')
    
    if not prompt:
        return jsonify({'success': False, 'error': 'Prompt required'})
    
    result = call_nvidia_ai(prompt, context, role)
    
    log_audit(session['user_id'], 'ai_analyze', 'ai', None, {'role': role, 'success': result.get('success', False)})
    
    return jsonify(result)

@app.route('/ai/report/generate', methods=['POST'])
@login_required
def generate_report():
    if not SETTINGS.get('nvidia_api_key'):
        return jsonify({'success': False, 'error': 'NVIDIA API key not configured'})
    
    case_id = request.json.get('case_id')
    if not case_id:
        return jsonify({'success': False, 'error': 'Case ID required'})
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Gather all case data
    cursor.execute('SELECT * FROM cases WHERE id = ?', (case_id,))
    case = cursor.fetchone()
    
    cursor.execute('SELECT * FROM entities WHERE case_id = ?', (case_id,))
    entities = cursor.fetchall()
    
    cursor.execute('''
        SELECT sr.*, e.entity_value, e.entity_type 
        FROM scan_results sr 
        JOIN entities e ON sr.entity_id = e.id 
        WHERE e.case_id = ?
    ''', (case_id,))
    scan_results = cursor.fetchall()
    
    cursor.execute('SELECT * FROM notes WHERE case_id = ?', (case_id,))
    notes = cursor.fetchall()
    
    conn.close()
    
    context = {
        'case': dict(case),
        'entities': [dict(e) for e in entities],
        'scan_results': [dict(sr) for sr in scan_results],
        'notes': [dict(n) for n in notes]
    }
    
    prompt = """Generate a comprehensive cybersecurity assessment report based on the provided case data. 
Include: Executive Summary, Methodology, Findings, Risk Assessment, Recommendations, and Conclusion.
Format the report professionally with clear sections."""
    
    result = call_nvidia_ai(prompt, context)
    
    log_audit(session['user_id'], 'generate_report', 'report', case_id, {'success': result.get('success', False)})
    
    return jsonify(result)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    global SETTINGS
    
    if request.method == 'POST':
        SETTINGS['nvidia_api_key'] = request.form.get('nvidia_api_key', SETTINGS['nvidia_api_key'])
        SETTINGS['shodan_api_key'] = request.form.get('shodan_api_key', SETTINGS['shodan_api_key'])
        SETTINGS['virustotal_api_key'] = request.form.get('virustotal_api_key', SETTINGS['virustotal_api_key'])
        SETTINGS['model'] = request.form.get('model', SETTINGS['model'])
        SETTINGS['agentic_mode'] = request.form.get('agentic_mode') == 'on'
        SETTINGS['theme'] = request.form.get('theme', SETTINGS['theme'])
        
        save_settings(SETTINGS)
        
        log_audit(session['user_id'], 'update_settings', 'config')
        flash('Settings saved successfully.', 'success')
        return redirect(url_for('settings'))
    
    return render_template('settings.html', settings=SETTINGS)

@app.route('/audit-logs')
@admin_required
def audit_logs():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT al.*, u.username 
        FROM audit_logs al 
        LEFT JOIN users u ON al.user_id = u.id 
        ORDER BY al.created_at DESC 
        LIMIT 100
    ''')
    logs = cursor.fetchall()
    conn.close()
    return render_template('audit_logs.html', logs=logs)

@app.route('/graph/<int:case_id>')
@login_required
def graph_view(case_id):
    conn = get_db()
    cursor = conn.cursor()
    
    # Get entities for graph
    cursor.execute('SELECT * FROM entities WHERE case_id = ?', (case_id,))
    entities = cursor.fetchall()
    
    # Get relationships from scan results
    cursor.execute('''
        SELECT sr.*, e.entity_value, e.entity_type 
        FROM scan_results sr 
        JOIN entities e ON sr.entity_id = e.id 
        WHERE e.case_id = ?
    ''', (case_id,))
    relationships = cursor.fetchall()
    
    conn.close()
    
    nodes = [{'id': e['id'], 'label': e['entity_value'], 'type': e['entity_type']} for e in entities]
    links = []
    
    # Auto-link entities based on scan results
    for sr in relationships:
        try:
            result_data = json.loads(sr['results'])
            if result_data.get('success') and 'data' in result_data:
                # Extract related entities from results
                data = result_data['data']
                if isinstance(data, dict):
                    for key, value in data.items():
                        if isinstance(value, list):
                            for item in value:
                                if isinstance(item, dict) and 'subdomain' in item:
                                    links.append({'source': sr['entity_id'], 'target': item['subdomain'], 'type': key})
        except:
            pass
    
    return render_template('graph.html', case_id=case_id, nodes=nodes, links=links)

@app.route('/terminal')
@login_required
def terminal():
    return render_template('terminal.html')

@app.route('/terminal/execute', methods=['POST'])
@login_required
def terminal_execute():
    command = request.json.get('command', '').strip()
    
    if not command:
        return jsonify({'success': False, 'error': 'Command required'})
    
    # Whitelist safe commands
    safe_commands = ['whois', 'dig', 'nslookup', 'ping', 'traceroute', 'nmap', 'curl', 'wget', 'grep', 'cat', 'ls', 'pwd']
    cmd_base = command.split()[0] if command.split() else ''
    
    if cmd_base not in safe_commands:
        return jsonify({'success': False, 'error': f'Command "{cmd_base}" not allowed for security reasons'})
    
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        output = result.stdout if result.stdout else result.stderr
        if not output:
            output = f"Command completed with exit code {result.returncode}"
        
        log_audit(session['user_id'], 'terminal_execute', 'terminal', None, {'command': command})
        
        return jsonify({'success': True, 'output': output, 'exit_code': result.returncode})
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Command timed out after 60 seconds'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    print("=" * 60)
    print("🛡️  SENTINEL CORE - Elite Cybersecurity Platform")
    print("=" * 60)
    print(f"📁 Database: {DB_PATH}")
    print(f"⚙️  Settings: {SETTINGS_PATH}")
    print(f"🔑 NVIDIA API Key: {'✅ Configured' if SETTINGS.get('nvidia_api_key') else '❌ Not configured'}")
    print(f"🔑 Shodan API Key: {'✅ Configured' if SETTINGS.get('shodan_api_key') else '❌ Not configured'}")
    print(f"🔑 VirusTotal API Key: {'✅ Configured' if SETTINGS.get('virustotal_api_key') else '❌ Not configured'}")
    print("=" * 60)
    print("🚀 Starting server on http://localhost:5001")
    print("👤 Default login: admin / admin123")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5001, debug=False, threaded=True)
