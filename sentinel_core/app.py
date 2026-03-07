import os
import json
import time
import uuid
import sqlite3
import threading
import requests
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, Response
from functools import wraps
from datetime import datetime

# Configuration
APP_SECRET = os.urandom(24).hex()
DB_PATH = 'sentinel_core.db'
SETTINGS_FILE = 'config/settings.json'

app = Flask(__name__)
app.secret_key = APP_SECRET

# Ensure directories exist
os.makedirs('config', exist_ok=True)
os.makedirs('reports', exist_ok=True)
os.makedirs('notes', exist_ok=True)

# --- Database Initialization ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS cases 
                 (id INTEGER PRIMARY KEY, name TEXT, description TEXT, created_at TEXT, status TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS entities 
                 (id INTEGER PRIMARY KEY, case_id INTEGER, type TEXT, value TEXT, tags TEXT, meta TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS notes 
                 (id INTEGER PRIMARY KEY, title TEXT, content TEXT, tags TEXT, created_at TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS audit_log 
                 (id INTEGER PRIMARY KEY, action TEXT, user TEXT, timestamp TEXT)''')
    
    # Default Admin
    try:
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                  ('admin', 'admin123', 'admin'))
    except sqlite3.IntegrityError:
        pass
    
    conn.commit()
    conn.close()

init_db()

# --- Settings Management (Persistent) ---
def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'r') as f:
            return json.load(f)
    return {
        "nvidia_api_key": "",
        "model": "moonshotai/kimi-k2.5",
        "agentic_mode": False,
        "memory_enabled": True,
        "daily_token_limit": 50000
    }

def save_settings(settings):
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(settings, f, indent=4)

# --- Kimi / NVIDIA AI Integration (EXACT METHOD SPECIFIED) ---
def call_kimi_ai(prompt, context="", system_role="Ethical Hacker"):
    settings = load_settings()
    api_key = settings.get("nvidia_api_key")
    
    if not api_key:
        return {"error": "API Key not configured in Settings.", "fallback": True}

    # EXACT URL FROM USER REQUEST
    invoke_url = "https://integrate.api.nvidia.com/v1/chat/completions"
    
    # Construct full prompt with context and role
    full_prompt = f"""
    [SYSTEM ROLE]: You are an elite {system_role}. 
    [CONTEXT]: {context}
    [USER QUERY]: {prompt}
    
    Provide a professional, actionable response. If agentic mode is on, suggest specific commands.
    """

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json"
    }

    payload = {
        "model": "moonshotai/kimi-k2.5",
        "messages": [
            {"role": "system", "content": f"You are an elite {system_role} assistant."},
            {"role": "user", "content": full_prompt}
        ],
        "max_tokens": 16384,
        "temperature": 1.00,
        "top_p": 1.00,
        "stream": False, 
        "chat_template_kwargs": {"thinking": True}
    }

    try:
        response = requests.post(invoke_url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        return {
            "response": data['choices'][0]['message']['content'],
            "usage": data.get('usage', {}),
            "success": True
        }
    except Exception as e:
        return {"error": str(e), "fallback": True}

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
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            session['user'] = username
            session['role'] = user[3]
            return redirect(url_for('dashboard'))
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
    c.execute("INSERT INTO cases (name, description, created_at, status) VALUES (?, ?, ?, ?)",
              (name, desc, datetime.now().isoformat(), 'Active'))
    conn.commit()
    case_id = c.lastrowid
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
    c.execute("INSERT INTO entities (case_id, type, value, tags, meta) VALUES (?, ?, ?, ?, ?)",
              (case_id, etype, value, tags, json.dumps({"created_by": session['user']})))
    conn.commit()
    eid = c.lastrowid
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
    # Mock execution for safety, in real deploy use subprocess with strict validation
    result = f"Executed {tool_id} on {target}. Results simulated for security."
    if tool_id == 'kimi_analyze':
        settings = load_settings()
        role = "Threat Intelligence Analyst"
        ai_resp = call_kimi_ai(f"Analyze {target} for potential threats and vulnerabilities.", context=f"Target: {target}", system_role=role)
        if 'response' in ai_resp:
            result = ai_resp['response']
        else:
            result = "AI Analysis failed: " + str(ai_resp.get('error'))
            
    return jsonify({"result": result})

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
    save_settings(current)
    return jsonify({"success": True})

@app.route('/api/create_note', methods=['POST'])
@login_required
def create_note():
    title = request.json.get('title')
    content = request.json.get('content')
    tags = request.json.get('tags')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO notes (title, content, tags, created_at) VALUES (?, ?, ?, ?)",
              (title, content, tags, datetime.now().isoformat()))
    conn.commit()
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
    conn.close()
    
    # Generate HTML Report
    report_name = f"report_{case_id}_{int(time.time())}.html"
    path = os.path.join('reports', report_name)
    
    html_content = f"""
    <html><head><title>Sentinel Core Report: {case[1]}</title>
    <style>body{{font-family:'Segoe UI',sans-serif; max-width:900px; margin:0 auto; padding:20px;}}
    h1{{color:#2c3e50; border-bottom:2px solid #3498db;}} .entity{{background:#f8f9fa; padding:10px; margin:5px 0; border-left:4px solid #3498db;}}
    .ai-section{{background:#e8f4fd; padding:15px; border-radius:5px; margin-top:20px;}}</style></head>
    <body>
    <h1>Intelligence Report: {case[1]}</h1>
    <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
    <p><strong>Status:</strong> {case[4]}</p>
    <h2>Executive Summary</h2>
    <p>Automated reconnaissance and analysis completed for {case[1]}.</p>
    <h2>Findings & Entities</h2>
    """
    
    for ent in entities:
        html_content += f"<div class='entity'><strong>{ent[2].upper()}</strong>: {ent[3]} <br><small>Tags: {ent[4]}</small></div>"
    
    # Add AI Summary if key exists
    settings = load_settings()
    if settings.get('nvidia_api_key'):
        html_content += "<div class='ai-section'><h3>🤖 AI Strategic Analysis (Kimi)</h3><p>Connecting to NVIDIA NIM for deep analysis...</p><p><em>(Run 'Generate AI Insights' in the case view to populate this section with live data.)</em></p></div>"
    
    html_content += "</body></html>"
    
    with open(path, 'w') as f:
        f.write(html_content)
        
    return jsonify({"success": True, "filename": report_name})

if __name__ == '__main__':
    print("🚀 Sentinel Core Starting...")
    print("📡 Access at http://localhost:5001")
    app.run(debug=True, host='0.0.0.0', port=5001)
