import os
import json
import time
import uuid
import sqlite3
import subprocess
import re
import socket
import struct
import threading
import requests
import whois
import dns.resolver
import geoip2.database
import bcrypt
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, Response, send_from_directory
from functools import wraps
from datetime import datetime
from collections import defaultdict

# Configuration
DB_PATH = 'sentinel_core.db'
SETTINGS_FILE = 'config/settings.json'
GEOIP_DB_PATH = 'config/GeoLite2-City.mmdb'

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32).hex())

# Ensure directories exist
os.makedirs('config', exist_ok=True)
os.makedirs('reports', exist_ok=True)
os.makedirs('notes', exist_ok=True)
os.makedirs('logs', exist_ok=True)

# --- Database Initialization ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Users table with secure password storage
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, role TEXT, created_at TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS cases 
                 (id INTEGER PRIMARY KEY, name TEXT, description TEXT, created_at TEXT, status TEXT, owner TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS entities 
                 (id INTEGER PRIMARY KEY, case_id INTEGER, type TEXT, value TEXT, tags TEXT, meta TEXT, created_at TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS notes 
                 (id INTEGER PRIMARY KEY, title TEXT, content TEXT, tags TEXT, created_at TEXT, author TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS audit_log 
                 (id INTEGER PRIMARY KEY, action TEXT, user TEXT, timestamp TEXT, details TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS scan_results 
                 (id INTEGER PRIMARY KEY, entity_id INTEGER, tool_name TEXT, result TEXT, created_at TEXT)''')
    
    # Create default admin with secure password
    try:
        admin_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        c.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)", 
                  ('admin', admin_password, 'admin', datetime.now().isoformat()))
    except sqlite3.IntegrityError:
        pass
    
    conn.commit()
    conn.close()

init_db()

# --- Settings Management (Persistent) ---
def load_settings():
    default_settings = {
        "nvidia_api_key": "",
        "openai_api_key": "",
        "model": "moonshotai/kimi-k2.5",
        "agentic_mode": False,
        "memory_enabled": True,
        "daily_token_limit": 50000,
        "shodan_api_key": "",
        "virustotal_api_key": ""
    }
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'r') as f:
            loaded = json.load(f)
            default_settings.update(loaded)
    return default_settings

def save_settings(settings):
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(settings, f, indent=4)

# --- Logging Utility ---
def log_audit(action, user, details=""):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO audit_log (action, user, timestamp, details) VALUES (?, ?, ?, ?)",
              (action, user, datetime.now().isoformat(), details))
    conn.commit()
    conn.close()

# --- Kimi / NVIDIA AI Integration ---
def call_kimi_ai(prompt, context="", system_role="Ethical Hacker"):
    settings = load_settings()
    api_key = settings.get("nvidia_api_key")
    
    if not api_key:
        return {"error": "NVIDIA API Key not configured in Settings.", "fallback": True}

    invoke_url = "https://integrate.api.nvidia.com/v1/chat/completions"
    
    full_prompt = f"""
    [SYSTEM ROLE]: You are an elite {system_role} with expertise in cybersecurity, threat intelligence, and digital forensics.
    [CONTEXT]: {context}
    [USER QUERY]: {prompt}
    
    Provide a professional, detailed, and actionable response. Include:
    1. Executive Summary
    2. Key Findings
    3. Risk Assessment
    4. Recommended Actions
    5. Technical Details
    """

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    payload = {
        "model": "moonshotai/kimi-k2.5",
        "messages": [
            {"role": "system", "content": f"You are an elite {system_role} assistant providing cybersecurity analysis."},
            {"role": "user", "content": full_prompt}
        ],
        "max_tokens": 16384,
        "temperature": 0.7,
        "top_p": 0.9,
        "stream": False
    }

    try:
        response = requests.post(invoke_url, headers=headers, json=payload, timeout=60)
        response.raise_for_status()
        data = response.json()
        return {
            "response": data['choices'][0]['message']['content'],
            "usage": data.get('usage', {}),
            "success": True
        }
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP Error: {e.response.status_code} - {e.response.text}", "fallback": True}
    except Exception as e:
        return {"error": f"AI Request failed: {str(e)}", "fallback": True}

# --- REAL SCANNING TOOLS ---

def perform_whois_lookup(domain):
    """Real WHOIS lookup using python-whois library"""
    try:
        w = whois.whois(domain)
        result = {
            "domain": w.domain_name,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date) if w.creation_date else "N/A",
            "expiration_date": str(w.expiration_date) if w.expiration_date else "N/A",
            "updated_date": str(w.updated_date) if w.updated_date else "N/A",
            "name_servers": w.name_servers if w.name_servers else [],
            "status": w.status if w.status else [],
            "emails": w.emails if w.emails else [],
            "org": w.org if w.org else "N/A",
            "country": w.country if w.country else "N/A"
        }
        return {"success": True, "data": result}
    except Exception as e:
        return {"success": False, "error": str(e)}

def perform_dns_enumeration(domain):
    """Real DNS enumeration using dnspython"""
    results = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    
    try:
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                results[rtype] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                results[rtype] = []
            except dns.resolver.NXDOMAIN:
                return {"success": False, "error": f"Domain {domain} does not exist"}
            except Exception as e:
                results[rtype] = [f"Error: {str(e)}"]
        
        return {"success": True, "data": results}
    except Exception as e:
        return {"success": False, "error": str(e)}

def discover_subdomains(domain):
    """Real subdomain discovery using DNS brute-forcing with common wordlist"""
    common_subdomains = [
        'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'admin', 'webmail', 'blog', 
        'shop', 'store', 'api', 'dev', 'staging', 'test', 'prod', 'app', 'mobile',
        'cdn', 'static', 'assets', 'media', 'images', 'img', 'files', 'docs',
        'support', 'help', 'portal', 'login', 'auth', 'sso', 'vpn', 'remote',
        'git', 'github', 'gitlab', 'jenkins', 'ci', 'cd', 'build', 'deploy',
        'db', 'database', 'sql', 'mysql', 'postgres', 'redis', 'mongo',
        'internal', 'intranet', 'extranet', 'partner', 'vendor', 'customer'
    ]
    
    found = []
    for sub in common_subdomains:
        fqdn = f"{sub}.{domain}"
        try:
            socket.gethostbyname(fqdn)
            found.append(fqdn)
        except socket.gaierror:
            pass
    
    return {"success": True, "data": {"found_subdomains": found, "total_found": len(found)}}

def http_probe(domain):
    """Real HTTP/HTTPS probing to check web services"""
    results = []
    protocols = ['http', 'https']
    
    for proto in protocols:
        url = f"{proto}://{domain}"
        try:
            resp = requests.get(url, timeout=10, allow_redirects=True)
            results.append({
                "url": url,
                "status_code": resp.status_code,
                "server": resp.headers.get('Server', 'N/A'),
                "content_type": resp.headers.get('Content-Type', 'N/A'),
                "redirect_url": resp.url if resp.url != url else None,
                "title": extract_html_title(resp.text) if 'text/html' in resp.headers.get('Content-Type', '') else 'N/A'
            })
        except requests.exceptions.RequestException as e:
            results.append({"url": url, "error": str(e)})
    
    return {"success": True, "data": results}

def extract_html_title(html):
    """Extract title from HTML content"""
    match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else 'N/A'

def nmap_scan(ip):
    """Real Nmap scan if available, fallback to basic port scan"""
    try:
        # Check if nmap is installed
        subprocess.run(['nmap', '--version'], capture_output=True, timeout=5)
        # Run nmap scan
        cmd = ['nmap', '-sV', '-sC', '-oG', '-', ip]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {"success": True, "data": result.stdout, "raw": result.stdout}
    except FileNotFoundError:
        # Fallback to basic Python port scan
        return basic_port_scan(ip)
    except Exception as e:
        return {"success": False, "error": str(e)}

def basic_port_scan(ip):
    """Basic TCP port scan as fallback when nmap is not available"""
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]
    open_ports = []
    
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            pass
    
    return {"success": True, "data": {"open_ports": open_ports, "scan_type": "basic_tcp"}}

def geoip_lookup(ip):
    """Real GeoIP lookup using MaxMind database or IP-API fallback"""
    # Try local GeoIP database first
    if os.path.exists(GEOIP_DB_PATH):
        try:
            reader = geoip2.database.Reader(GEOIP_DB_PATH)
            response = reader.city(ip)
            result = {
                "ip": ip,
                "city": response.city.name,
                "country": response.country.name,
                "country_code": response.country.iso_code,
                "continent": response.continent.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "timezone": response.location.time_zone,
                "postal_code": response.postal.code
            }
            reader.close()
            return {"success": True, "data": result}
        except Exception as e:
            pass
    
    # Fallback to free IP-API
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        data = resp.json()
        if data.get('status') == 'success':
            return {"success": True, "data": data}
        return {"success": False, "error": data.get('message', 'Unknown error')}
    except Exception as e:
        return {"success": False, "error": str(e)}

def shodan_lookup(ip):
    """Shodan API lookup for IP reconnaissance"""
    settings = load_settings()
    api_key = settings.get("shodan_api_key")
    
    if not api_key:
        return {"success": False, "error": "Shodan API key not configured"}
    
    try:
        resp = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}", timeout=30)
        data = resp.json()
        if 'error' in data:
            return {"success": False, "error": data['error']}
        return {"success": True, "data": data}
    except Exception as e:
        return {"success": False, "error": str(e)}

def breach_check(email):
    """Check email against known breach databases using HaveIBeenPwned API"""
    # Note: HIBP requires API key for automated access
    # This is a placeholder that checks format and provides guidance
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return {"success": False, "error": "Invalid email format"}
    
    # Free alternative: Use Firefox Monitor API or similar
    # For now, provide domain analysis
    domain = email.split('@')[1]
    mx_records = perform_dns_enumeration(domain)
    
    return {
        "success": True,
        "data": {
            "email": email,
            "domain": domain,
            "mx_records": mx_records.get('data', {}).get('MX', []),
            "note": "For comprehensive breach checking, configure HaveIBeenPwned API key or use their website directly at https://haveibeenpwned.com/"
        }
    }

def osint_search(email):
    """OSINT search for email addresses"""
    domain = email.split('@')[1] if '@' in email else email
    
    # Search for email patterns in public sources (simulated via DNS/MX checks)
    results = {
        "email": email,
        "domain_info": perform_whois_lookup(domain),
        "dns_info": perform_dns_enumeration(domain),
        "social_media_hints": []
    }
    
    # Check common social media patterns
    username = email.split('@')[0]
    platforms = ['twitter', 'instagram', 'facebook', 'linkedin', 'github', 'gitlab']
    
    for platform in platforms:
        # This would normally check actual APIs, but we provide structure
        results["social_media_hints"].append({
            "platform": platform,
            "potential_username": username,
            "check_url": f"https://{platform}.com/{username}"
        })
    
    return {"success": True, "data": results}

def virustotal_scan(target):
    """VirusTotal API scan for domains/IPs/URLs"""
    settings = load_settings()
    api_key = settings.get("virustotal_api_key")
    
    if not api_key:
        return {"success": False, "error": "VirusTotal API key not configured"}
    
    # Determine target type
    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', target):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
    elif '.' in target:
        url = f"https://www.virustotal.com/api/v3/domains/{target}"
    else:
        return {"success": False, "error": "Invalid target format"}
    
    try:
        headers = {'x-apikey': api_key}
        resp = requests.get(url, headers=headers, timeout=30)
        data = resp.json()
        return {"success": True, "data": data}
    except Exception as e:
        return {"success": False, "error": str(e)}

# --- Auth Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes: Auth ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
            session['user'] = username
            session['role'] = user[3]
            log_audit('LOGIN', username, 'Successful login')
            return redirect(url_for('dashboard'))
        
        log_audit('LOGIN_FAILED', username or 'unknown', 'Failed login attempt')
        return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- Routes: Main Pages ---
@app.route('/')
@login_required
def dashboard():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM cases")
    case_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM notes")
    note_count = c.fetchone()[0]
    conn.close()
    return render_template('dashboard.html', cases=case_count, notes=note_count)

@app.route('/cases')
@login_required
def cases():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM cases ORDER BY created_at DESC")
    cases = c.fetchall()
    conn.close()
    return render_template('cases.html', cases=cases)

@app.route('/case/<int:case_id>')
@login_required
def view_case(case_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM cases WHERE id=?", (case_id,))
    case = c.fetchone()
    c.execute("SELECT * FROM entities WHERE case_id=?", (case_id,))
    entities = c.fetchall()
    conn.close()
    return render_template('case_detail.html', case=case, entities=entities)

@app.route('/notes')
@login_required
def notes_page():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM notes ORDER BY created_at DESC")
    notes = c.fetchall()
    conn.close()
    return render_template('notes.html', notes=notes)

@app.route('/reports')
@login_required
def reports_page():
    files = [f for f in os.listdir('reports') if f.endswith('.html')]
    return render_template('reports.html', files=files)

@app.route('/terminal')
@login_required
def terminal_page():
    return render_template('terminal.html')

@app.route('/settings')
@login_required
def settings_page():
    settings = load_settings()
    return render_template('settings.html', settings=settings)

# --- Routes: API Actions ---

@app.route('/api/create_case', methods=['POST'])
@login_required
def create_case():
    name = request.json.get('name')
    desc = request.json.get('description')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO cases (name, description, created_at, status, owner) VALUES (?, ?, ?, ?, ?)",
              (name, desc, datetime.now().isoformat(), 'Active', session['user']))
    conn.commit()
    case_id = c.lastrowid
    log_audit('CREATE_CASE', session['user'], f'Created case: {name}')
    conn.close()
    return jsonify({"success": True, "id": case_id})

@app.route('/api/add_entity', methods=['POST'])
@login_required
def add_entity():
    case_id = request.json.get('case_id')
    etype = request.json.get('type')
    value = request.json.get('value')
    tags = request.json.get('tags', '')
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO entities (case_id, type, value, tags, meta, created_at) VALUES (?, ?, ?, ?, ?, ?)",
              (case_id, etype, value, tags, json.dumps({"created_by": session['user']}), datetime.now().isoformat()))
    conn.commit()
    eid = c.lastrowid
    log_audit('ADD_ENTITY', session['user'], f'Added {etype}: {value} to case {case_id}')
    conn.close()
    return jsonify({"success": True, "id": eid})

@app.route('/api/get_entity_actions', methods=['POST'])
@login_required
def get_entity_actions():
    """Returns available tools/actions based on entity type"""
    etype = request.json.get('type')
    actions = []
    
    if etype == 'domain':
        actions = [
            {"id": "whois", "name": "WHOIS Lookup", "icon": "fa-book"},
            {"id": "dns", "name": "DNS Enumeration", "icon": "fa-network-wired"},
            {"id": "subfinder", "name": "Subdomain Scan", "icon": "fa-search"},
            {"id": "httpx", "name": "HTTP Probe", "icon": "fa-globe"},
            {"id": "kimi_analyze", "name": "AI Threat Analysis", "icon": "fa-robot", "ai": True}
        ]
    elif etype == 'ip':
        actions = [
            {"id": "nmap", "name": "Nmap Scan", "icon": "fa-broadcast-tower"},
            {"id": "geoip", "name": "GeoIP Location", "icon": "fa-map-marker-alt"},
            {"id": "shodan", "name": "Shodan Lookup", "icon": "fa-eye"},
            {"id": "kimi_analyze", "name": "AI Vulnerability Assessment", "icon": "fa-robot", "ai": True}
        ]
    elif etype == 'email':
        actions = [
            {"id": "breach", "name": "Breach Check", "icon": "fa-exclamation-triangle"},
            {"id": "osint", "name": "OSINT Search", "icon": "fa-user-search"}
        ]
    else:
        actions = [{"id": "generic", "name": "Generic Search", "icon": "fa-search"}]
        
    return jsonify(actions)

@app.route('/api/execute_tool', methods=['POST'])
@login_required
def execute_tool():
    tool_id = request.json.get('tool_id')
    target = request.json.get('target')
    
    log_audit('EXECUTE_TOOL', session['user'], f'Running {tool_id} on {target}')
    
    result = None
    scan_data = None
    
    # Execute real tools based on tool_id
    if tool_id == 'whois':
        scan_data = perform_whois_lookup(target)
    elif tool_id == 'dns':
        scan_data = perform_dns_enumeration(target)
    elif tool_id == 'subfinder':
        scan_data = discover_subdomains(target)
    elif tool_id == 'httpx':
        scan_data = http_probe(target)
    elif tool_id == 'nmap':
        scan_data = nmap_scan(target)
    elif tool_id == 'geoip':
        scan_data = geoip_lookup(target)
    elif tool_id == 'shodan':
        scan_data = shodan_lookup(target)
    elif tool_id == 'breach':
        scan_data = breach_check(target)
    elif tool_id == 'osint':
        scan_data = osint_search(target)
    elif tool_id == 'virustotal':
        scan_data = virustotal_scan(target)
    elif tool_id == 'kimi_analyze':
        settings = load_settings()
        role = "Threat Intelligence Analyst"
        ai_resp = call_kimi_ai(f"Analyze {target} for potential threats, vulnerabilities, and security posture.", 
                               context=f"Target: {target}\nTool: AI-Powered Threat Analysis", 
                               system_role=role)
        if 'response' in ai_resp:
            result = ai_resp['response']
            scan_data = {"success": True, "data": {"ai_analysis": result}}
        else:
            return jsonify({"result": "AI Analysis failed: " + str(ai_resp.get('error')), "success": False})
    else:
        return jsonify({"result": f"Unknown tool: {tool_id}", "success": False})
    
    # Format result for display
    if scan_data:
        if scan_data.get('success'):
            result = json.dumps(scan_data.get('data', {}), indent=2, default=str)
        else:
            result = f"Error: {scan_data.get('error', 'Unknown error')}"
    
    # Store scan result in database
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id FROM entities WHERE value=?", (target,))
    entity_row = c.fetchone()
    entity_id = entity_row[0] if entity_row else None
    
    if entity_id:
        c.execute("INSERT INTO scan_results (entity_id, tool_name, result, created_at) VALUES (?, ?, ?, ?)",
                  (entity_id, tool_id, result[:10000] if result else '', datetime.now().isoformat()))
        conn.commit()
    conn.close()
    
    return jsonify({"result": result, "success": scan_data.get('success', True) if scan_data else True})

@app.route('/api/ask_kimi', methods=['POST'])
@login_required
def ask_kimi():
    query = request.json.get('query')
    context = request.json.get('context', '')
    role = request.json.get('role', 'Ethical Hacker')
    
    response = call_kimi_ai(query, context=context, system_role=role)
    return jsonify(response)

@app.route('/api/save_settings', methods=['POST'])
@login_required
def save_settings_route():
    data = request.json
    current = load_settings()
    
    if 'api_key' in data:
        current['nvidia_api_key'] = data['api_key']
    if 'agentic' in data:
        current['agentic_mode'] = data['agentic']
    if 'shodan_api_key' in data:
        current['shodan_api_key'] = data['shodan_api_key']
    if 'virustotal_api_key' in data:
        current['virustotal_api_key'] = data['virustotal_api_key']
    if 'model' in data:
        current['model'] = data['model']
    
    save_settings(current)
    log_audit('UPDATE_SETTINGS', session['user'], 'Updated application settings')
    return jsonify({"success": True})

@app.route('/api/create_note', methods=['POST'])
@login_required
def create_note():
    title = request.json.get('title')
    content = request.json.get('content')
    tags = request.json.get('tags')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO notes (title, content, tags, created_at, author) VALUES (?, ?, ?, ?, ?)",
              (title, content, tags, datetime.now().isoformat(), session['user']))
    conn.commit()
    log_audit('CREATE_NOTE', session['user'], f'Created note: {title}')
    conn.close()
    return jsonify({"success": True})

@app.route('/api/generate_report', methods=['POST'])
@login_required
def generate_report():
    case_id = request.json.get('case_id')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM cases WHERE id=?", (case_id,))
    case = c.fetchone()
    c.execute("SELECT * FROM entities WHERE case_id=?", (case_id,))
    entities = c.fetchall()
    c.execute("SELECT tool_name, result, created_at FROM scan_results WHERE entity_id IN (SELECT id FROM entities WHERE case_id=?) ORDER BY created_at DESC", (case_id,))
    scan_results = c.fetchall()
    conn.close()
    
    # Generate AI analysis if API key is configured
    ai_analysis = None
    settings = load_settings()
    if settings.get('nvidia_api_key'):
        entity_summary = ", ".join([f"{e[2]}:{e[3]}" for e in entities[:10]])
        ai_resp = call_kimi_ai(
            f"Provide a comprehensive security assessment report for case '{case[1]}'. Entities found: {entity_summary}",
            context=f"Case: {case[1]}, Status: {case[4]}, Description: {case[2]}",
            system_role="Senior Security Analyst"
        )
        if 'response' in ai_resp:
            ai_analysis = ai_resp['response']
    
    # Generate HTML Report
    report_name = f"report_{case_id}_{int(time.time())}.html"
    path = os.path.join('reports', report_name)
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Sentinel Core Report: {case[1]}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; background: #f5f5f5; }}
            .container {{ background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 15px; }}
            h2 {{ color: #34495e; margin-top: 30px; }}
            .meta {{ color: #7f8c8d; margin-bottom: 20px; }}
            .entity {{ background: #ecf0f1; padding: 15px; margin: 10px 0; border-left: 5px solid #3498db; border-radius: 5px; }}
            .entity strong {{ color: #2c3e50; }}
            .scan-result {{ background: #fff3cd; padding: 15px; margin: 10px 0; border-left: 5px solid #ffc107; border-radius: 5px; }}
            .ai-section {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px; border-radius: 10px; margin-top: 30px; }}
            .ai-section h3 {{ color: white; border-bottom: 2px solid rgba(255,255,255,0.3); padding-bottom: 10px; }}
            pre {{ background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; font-size: 12px; }}
            .footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Intelligence Report: {case[1]}</h1>
            <div class="meta">
                <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Status:</strong> {case[4]}</p>
                <p><strong>Owner:</strong> {case[5] if len(case) > 5 and case[5] else 'N/A'}</p>
                <p><strong>Description:</strong> {case[2]}</p>
            </div>
            
            <h2>📊 Executive Summary</h2>
            <p>This automated reconnaissance report contains findings for <strong>{len(entities)} entities</strong> discovered during the investigation of {case[1]}.</p>
            
            <h2>🔍 Entities & Findings</h2>
    """
    
    for ent in entities:
        html_content += f"""
        <div class="entity">
            <strong>{ent[2].upper()}</strong>: {ent[3]}
            <br><small>Tags: {ent[4] if ent[4] else 'None'}</small>
        </div>"""
    
    if scan_results:
        html_content += "<h2>🔬 Scan Results</h2>"
        for sr in scan_results[:20]:  # Limit to 20 results
            html_content += f"""
            <div class="scan-result">
                <strong>{sr[0].upper()}</strong> - {sr[2]}
                <pre>{sr[1][:2000]}</pre>
            </div>"""
    
    # Add AI Analysis
    if ai_analysis:
        html_content += f"""
        <div class="ai-section">
            <h3>🤖 AI Strategic Analysis (Kimi)</h3>
            <div style="white-space: pre-wrap;">{ai_analysis}</div>
        </div>"""
    elif settings.get('nvidia_api_key'):
        html_content += """
        <div class="ai-section">
            <h3>🤖 AI Strategic Analysis</h3>
            <p>AI analysis was requested but could not be completed. Please check your API key configuration.</p>
        </div>"""
    
    html_content += """
            <div class="footer">
                <p>Generated by Sentinel Core - Advanced Cybersecurity Investigation Platform</p>
                <p><em>For authorized security testing purposes only.</em></p>
            </div>
        </div>
    </body>
    </html>"""
    
    with open(path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    log_audit('GENERATE_REPORT', session['user'], f'Generated report for case {case_id}')
        
    return jsonify({"success": True, "filename": report_name})

# --- Additional API Routes ---

@app.route('/api/get_scan_history', methods=['POST'])
@login_required
def get_scan_history():
    entity_id = request.json.get('entity_id')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT tool_name, result, created_at FROM scan_results WHERE entity_id=? ORDER BY created_at DESC", (entity_id,))
    results = c.fetchall()
    conn.close()
    return jsonify({"success": True, "history": results})

@app.route('/api/delete_entity', methods=['POST'])
@login_required
def delete_entity():
    entity_id = request.json.get('entity_id')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM entities WHERE id=?", (entity_id,))
    c.execute("DELETE FROM scan_results WHERE entity_id=?", (entity_id,))
    conn.commit()
    log_audit('DELETE_ENTITY', session['user'], f'Deleted entity {entity_id}')
    conn.close()
    return jsonify({"success": True})

@app.route('/api/update_case_status', methods=['POST'])
@login_required
def update_case_status():
    case_id = request.json.get('case_id')
    status = request.json.get('status')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE cases SET status=? WHERE id=?", (status, case_id))
    conn.commit()
    log_audit('UPDATE_CASE_STATUS', session['user'], f'Updated case {case_id} to {status}')
    conn.close()
    return jsonify({"success": True})

@app.route('/reports/<filename>')
@login_required
def serve_report(filename):
    return send_from_directory('reports', filename)

@app.route('/api/get_audit_log', methods=['GET'])
@login_required
def get_audit_log():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT action, user, timestamp, details FROM audit_log ORDER BY timestamp DESC LIMIT 100")
    logs = c.fetchall()
    conn.close()
    return jsonify({"success": True, "logs": logs})

if __name__ == '__main__':
    print("🚀 Sentinel Core Starting...")
    print("📡 Access at http://localhost:5001")
    app.run(debug=True, host='0.0.0.0', port=5001)
