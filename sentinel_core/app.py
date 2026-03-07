#!/usr/bin/env python3
"""
Sentinel Core - Advanced OSINT Framework
A professional, modular reconnaissance platform for authorized security research.

Features:
- Real module execution engine with async task queue
- Circuit breakers, retries, and timeouts
- Normalized intelligence data model
- Kali/Parrot OS tools integration (amass, assetfinder, sublist3r, nuclei, naabu)
- Entity relationship graph with confidence scoring
- Evidence chain of custody
- STIX 2.1 export capability
"""

import os
import sys
import sqlite3
import hashlib
import secrets
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
import bcrypt

# Initialize Flask App
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Use absolute path for database (fixes relative path issue)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'db', 'sentinel.db')

# Import engine components
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from engine.module_registry import registry, register_builtin_modules, ModuleMetadata
from engine.task_queue import task_queue, JobStatus
from engine.script_engine import engine as script_engine
from models.intelligence import IntelligenceGraph, create_entity, create_relationship, EntityType, RelationshipType
from integrations.kali_tools import kali_tools
from integrations.advanced_tools import registry as tool_registry
from reports.report_generator import generator as report_generator

# Database Initialization
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )''')
    
    # Sessions/Cases table
    c.execute('''CREATE TABLE IF NOT EXISTS cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Entities table (for Maltego-like graph)
    c.execute('''CREATE TABLE IF NOT EXISTS entities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER,
        entity_type TEXT NOT NULL,
        value TEXT NOT NULL,
        metadata TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (case_id) REFERENCES cases (id)
    )''')
    
    # Relationships table
    c.execute('''CREATE TABLE IF NOT EXISTS relationships (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER,
        source_id INTEGER,
        target_id INTEGER,
        relationship_type TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (case_id) REFERENCES cases (id),
        FOREIGN KEY (source_id) REFERENCES entities (id),
        FOREIGN KEY (target_id) REFERENCES entities (id)
    )''')
    
    # Audit log table
    c.execute('''CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Create default admin user if not exists
    c.execute("SELECT * FROM users WHERE username = ?", ('admin',))
    if not c.fetchone():
        hashed_pw = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", ('admin', hashed_pw))
        print("[*] Default admin user created: admin / admin123")
    
    conn.commit()
    conn.close()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this resource.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def log_audit(user_id, action, details, ip_address):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("INSERT INTO audit_log (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)",
              (user_id, action, details, ip_address))
    conn.commit()
    conn.close()

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
            session['user_id'] = user[0]
            session['username'] = user[1]
            
            # Update last login
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute("UPDATE users SET last_login = ? WHERE id = ?", (datetime.now(), user[0]))
            conn.commit()
            conn.close()
            
            log_audit(user[0], 'LOGIN', f'User {username} logged in', request.remote_addr)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_audit(session['user_id'], 'LOGOUT', f'User {session["username"]} logged out', request.remote_addr)
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT * FROM cases WHERE user_id = ? ORDER BY created_at DESC", (session['user_id'],))
    cases = c.fetchall()
    conn.close()
    return render_template('dashboard.html', cases=cases)

@app.route('/case/new', methods=['POST'])
@login_required
def create_case():
    name = request.form.get('name')
    description = request.form.get('description')
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("INSERT INTO cases (user_id, name, description) VALUES (?, ?, ?)",
              (session['user_id'], name, description))
    case_id = c.lastrowid
    conn.commit()
    conn.close()
    
    log_audit(session['user_id'], 'CREATE_CASE', f'Created case: {name}', request.remote_addr)
    flash('Case created successfully!', 'success')
    return redirect(url_for('case_view', case_id=case_id))

@app.route('/case/<int:case_id>')
@login_required
def case_view(case_id):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Verify ownership
    c.execute("SELECT * FROM cases WHERE id = ? AND user_id = ?", (case_id, session['user_id']))
    case = c.fetchone()
    if not case:
        conn.close()
        flash('Case not found or access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get entities
    c.execute("SELECT * FROM entities WHERE case_id = ?", (case_id,))
    entities = c.fetchall()
    
    # Get relationships
    c.execute("SELECT * FROM relationships WHERE case_id = ?", (case_id,))
    relationships = c.fetchall()
    
    conn.close()
    
    return render_template('case.html', case=case, entities=entities, relationships=relationships)

@app.route('/api/entity/add', methods=['POST'])
@login_required
def add_entity():
    case_id = request.form.get('case_id')
    entity_type = request.form.get('entity_type')
    value = request.form.get('value')
    metadata = request.form.get('metadata', '{}')
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Verify ownership
    c.execute("SELECT id FROM cases WHERE id = ? AND user_id = ?", (case_id, session['user_id']))
    if not c.fetchone():
        conn.close()
        return jsonify({'error': 'Access denied'}), 403
    
    c.execute("INSERT INTO entities (case_id, entity_type, value, metadata) VALUES (?, ?, ?, ?)",
              (case_id, entity_type, value, metadata))
    entity_id = c.lastrowid
    conn.commit()
    conn.close()
    
    log_audit(session['user_id'], 'ADD_ENTITY', f'Added {entity_type}: {value}', request.remote_addr)
    return jsonify({'success': True, 'entity_id': entity_id})

@app.route('/api/relationship/add', methods=['POST'])
@login_required
def add_relationship():
    case_id = request.form.get('case_id')
    source_id = request.form.get('source_id')
    target_id = request.form.get('target_id')
    relationship_type = request.form.get('relationship_type')
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Verify ownership
    c.execute("SELECT id FROM cases WHERE id = ? AND user_id = ?", (case_id, session['user_id']))
    if not c.fetchone():
        conn.close()
        return jsonify({'error': 'Access denied'}), 403
    
    c.execute("INSERT INTO relationships (case_id, source_id, target_id, relationship_type) VALUES (?, ?, ?, ?)",
              (case_id, source_id, target_id, relationship_type))
    conn.commit()
    conn.close()
    
    log_audit(session['user_id'], 'ADD_RELATIONSHIP', f'Linked {source_id} to {target_id}', request.remote_addr)
    return jsonify({'success': True})

@app.route('/api/modules')
@login_required
def list_modules():
    """List all registered modules from the registry"""
    # Register builtin modules on first call
    if not registry.modules:
        register_builtin_modules()
    
    modules = registry.list_modules()
    
    # Add Kali tools info
    available_tools = kali_tools.get_available_tools()
    for mod in modules:
        mod['kali_tools_available'] = available_tools
    
    return jsonify(modules)

@app.route('/api/module/run', methods=['POST'])
@login_required
def run_module():
    """Submit a module execution task to the async queue"""
    module_id = request.form.get('module_id')
    target = request.form.get('target')
    try:
        case_id = int(request.form.get('case_id'))
        priority = int(request.form.get('priority', 5))
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid case_id or priority'}), 400
    
    # CASE OWNERSHIP CHECK - Critical security control
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT id FROM cases WHERE id = ? AND user_id = ?", (case_id, session['user_id']))
    if not c.fetchone():
        conn.close()
        log_audit(session['user_id'], 'UNAUTHORIZED_MODULE_RUN', 
                 f'User attempted to run module on unauthorized case {case_id}', 
                 request.remote_addr)
        return jsonify({'error': 'Access denied: Case not found or you do not own it'}), 403
    conn.close()
    
    # Validate module exists
    module_info = registry.get_module(module_id)
    if not module_info:
        return jsonify({'error': f'Module {module_id} not found'}), 404
    
    # Check required secrets
    if not registry.has_required_secrets(module_id):
        missing = [s for s in module_info['metadata'].required_secrets if s not in registry.secrets]
        if missing:
            return jsonify({'error': f'Missing required secrets: {missing}. Please configure API keys.'}), 400
    
    # Submit to task queue
    task_id = task_queue.submit_task(
        module_id=module_id,
        target=target,
        case_id=case_id,
        user_id=session['user_id'],
        priority=priority,
        timeout=module_info['metadata'].timeout,
        max_retries=module_info['metadata'].retries
    )
    
    # Log the action
    log_audit(session['user_id'], 'QUEUE_MODULE', 
             f'Queued {module_id} on {target} (task: {task_id})', 
             request.remote_addr)
    
    return jsonify({
        'status': 'queued',
        'task_id': task_id,
        'message': f'Module {module_id} queued for execution on {target}'
    })

@app.route('/api/task/status/<task_id>')
@login_required
def get_task_status(task_id):
    """Get status of an async task"""
    task = task_queue.get_task_status(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    return jsonify(task)

@app.route('/api/tasks')
@login_required
def list_tasks():
    """List all tasks for current user's cases"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT id FROM cases WHERE user_id = ?", (session['user_id'],))
    case_ids = [row[0] for row in c.fetchall()]
    conn.close()
    
    all_tasks = []
    for case_id in case_ids:
        tasks = task_queue.get_all_tasks(case_id=case_id)
        all_tasks.extend(tasks)
    
    return jsonify(sorted(all_tasks, key=lambda t: t['created_at'], reverse=True)[:100])

@app.route('/api/kali-tools/status')
@login_required
def kali_tools_status():
    """Get available Kali/Parrot OS tools"""
    return jsonify({
        'available_tools': kali_tools.get_available_tools(),
        'all_tools': list(kali_tools.available_tools.keys())
    })

@app.route('/api/kali-tools/comprehensive-recon', methods=['POST'])
@login_required
def run_comprehensive_recon():
    """Run comprehensive reconnaissance using all available Kali tools"""
    domain = request.form.get('domain')
    try:
        case_id = int(request.form.get('case_id'))
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid case_id'}), 400
    
    if not domain:
        return jsonify({'error': 'Domain required'}), 400
    
    # CASE OWNERSHIP CHECK - Critical security control
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT id FROM cases WHERE id = ? AND user_id = ?", (case_id, session['user_id']))
    if not c.fetchone():
        conn.close()
        log_audit(session['user_id'], 'UNAUTHORIZED_RECON', 
                 f'User attempted comprehensive recon on unauthorized case {case_id}', 
                 request.remote_addr)
        return jsonify({'error': 'Access denied: Case not found or you do not own it'}), 403
    conn.close()
    
    # Verify the kali_comprehensive executor is registered
    if 'kali_comprehensive' not in task_queue.executors:
        return jsonify({'error': 'Comprehensive recon module not initialized. Please restart the server.'}), 500
    
    # This is a long-running operation, submit to queue
    task_id = task_queue.submit_task(
        module_id='kali_comprehensive',
        target=domain,
        case_id=case_id,
        user_id=session['user_id'],
        priority=3,
        timeout=600,
        max_retries=1
    )
    
    # Store task reference
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("""
        INSERT INTO entities (case_id, entity_type, value, metadata) 
        VALUES (?, ?, ?, ?)
    """, (case_id, 'recon_task', f'Comprehensive recon: {domain}', 
          json.dumps({'task_id': task_id, 'started_at': datetime.now().isoformat()})))
    conn.commit()
    conn.close()
    
    log_audit(session['user_id'], 'COMPREHENSIVE_RECON', 
             f'Started comprehensive recon on {domain}', request.remote_addr)
    
    return jsonify({
        'status': 'queued',
        'task_id': task_id,
        'message': f'Comprehensive reconnaissance queued for {domain}'
    })

@app.route('/api/script/execute', methods=['POST'])
@login_required
def execute_custom_script():
    """Execute a custom Python script or builtin template"""
    script_name = request.form.get('script_name')
    code = request.form.get('code')  # Raw code for ad-hoc execution
    target = request.form.get('target')
    try:
        case_id = int(request.form.get('case_id'))
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid case_id'}), 400
    
    if not target:
        return jsonify({'error': 'Target required'}), 400
    
    # CASE OWNERSHIP CHECK - Critical security control
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT id FROM cases WHERE id = ? AND user_id = ?", (case_id, session['user_id']))
    if not c.fetchone():
        conn.close()
        log_audit(session['user_id'], 'UNAUTHORIZED_SCRIPT_EXEC', 
                 f'User attempted script execution on unauthorized case {case_id}', 
                 request.remote_addr)
        return jsonify({'error': 'Access denied: Case not found or you do not own it'}), 403
    conn.close()
    
    # Execute the script
    result = script_engine.execute_script(
        script_name=script_name,
        code=code,
        case_id=case_id,
        target=target
    )
    
    if result['status'] == 'success':
        # Save discovered entities to database
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        
        for entity in result.get('entities', []):
            c.execute("""
                INSERT INTO entities (case_id, entity_type, value, metadata)
                VALUES (?, ?, ?, ?)
            """, (case_id, entity['type'], entity['value'], 
                  json.dumps(entity)))
        
        conn.commit()
        conn.close()
        
        log_audit(session['user_id'], 'EXECUTE_SCRIPT', 
                 f'Executed script {script_name or "custom"} on {target}', 
                 request.remote_addr)
        
        return jsonify(result)
    else:
        return jsonify(result), 500

@app.route('/api/script/save', methods=['POST'])
@login_required
def save_custom_script():
    """Save a custom script for later use"""
    name = request.form.get('name')
    code = request.form.get('code')
    author = session['username']
    
    if not name or not code:
        return jsonify({'error': 'Name and code required'}), 400
    
    filename = script_engine.save_user_script(name, code, author)
    
    log_audit(session['user_id'], 'SAVE_SCRIPT', 
             f'Saved custom script: {name}', request.remote_addr)
    
    return jsonify({
        'status': 'success',
        'filename': filename,
        'message': f'Script "{name}" saved successfully'
    })

@app.route('/api/scripts/templates')
@login_required
def list_script_templates():
    """List available builtin script templates"""
    templates = list(script_engine.builtin_templates.keys())
    return jsonify({
        'templates': templates,
        'count': len(templates)
    })

@app.route('/api/tools/list')
@login_required
def list_all_tools():
    """List all available tools by category"""
    categories = ['recon', 'vuln', 'exploit', 'post', 'network']
    result = {}
    for cat in categories:
        result[cat] = tool_registry.get_available_tools_by_category(cat)
    return jsonify(result)

@app.route('/api/tool/execute', methods=['POST'])
@login_required
def execute_single_tool():
    """Execute a single registered tool"""
    tool_name = request.form.get('tool_name')
    target = request.form.get('target')
    custom_args = request.form.get('custom_args', '')
    
    if not tool_name or not target:
        return jsonify({'error': 'Tool name and target required'}), 400
    
    args_list = custom_args.split() if custom_args else None
    result = tool_registry.execute_tool(tool_name, target, args_list)
    
    return jsonify(result)

@app.route('/api/recon/full-chain', methods=['POST'])
@login_required
def run_full_recon_chain():
    """Run full reconnaissance chain using all available tools"""
    target = request.form.get('target')
    try:
        case_id = int(request.form.get('case_id'))
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid case_id'}), 400
    
    if not target:
        return jsonify({'error': 'Target required'}), 400
    
    # CASE OWNERSHIP CHECK - Critical security control
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT id FROM cases WHERE id = ? AND user_id = ?", (case_id, session['user_id']))
    if not c.fetchone():
        conn.close()
        log_audit(session['user_id'], 'UNAUTHORIZED_FULL_RECON', 
                 f'User attempted full recon on unauthorized case {case_id}', 
                 request.remote_addr)
        return jsonify({'error': 'Access denied: Case not found or you do not own it'}), 403
    conn.close()
    
    # Verify executor is registered
    if 'full_recon_chain' not in task_queue.executors:
        return jsonify({'error': 'Full recon chain module not initialized. Please restart the server.'}), 500
    
    # Submit to async queue (long running)
    task_id = task_queue.submit_task(
        module_id='full_recon_chain',
        target=target,
        case_id=case_id,
        user_id=session['user_id'],
        priority=2,
        timeout=900,
        max_retries=0
    )
    
    log_audit(session['user_id'], 'FULL_RECON_CHAIN', 
             f'Started full recon chain on {target}', request.remote_addr)
    
    return jsonify({
        'status': 'queued',
        'task_id': task_id,
        'message': f'Full reconnaissance chain queued for {target}'
    })

@app.route('/api/report/generate/<int:case_id>', methods=['GET'])
@login_required
def generate_report(case_id):
    """Generate comprehensive report for a case"""
    format_type = request.args.get('format', 'html')
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Verify ownership and get case data
    c.execute("SELECT * FROM cases WHERE id = ? AND user_id = ?", (case_id, session['user_id']))
    case = c.fetchone()
    if not case:
        conn.close()
        return jsonify({'error': 'Case not found'}), 404
    
    # Get entities and relationships
    c.execute("SELECT * FROM entities WHERE case_id = ?", (case_id,))
    entities_rows = c.fetchall()
    c.execute("SELECT * FROM relationships WHERE case_id = ?", (case_id,))
    relationships_rows = c.fetchall()
    conn.close()
    
    # Build case data structure
    case_data = {
        'id': case[1],  # case ID
        'name': case[2],
        'target': case[2],  # Use name as target for now
        'entities': [
            {
                'id': r[0],
                'type': r[2],
                'value': r[3],
                'meta': json.loads(r[4]) if r[4] else {},
                'source': json.loads(r[4]).get('source', 'manual') if r[4] else 'manual',
                'confidence': json.loads(r[4]).get('confidence', 50) if r[4] else 50
            }
            for r in entities_rows
        ],
        'relationships': [
            {
                'id': r[0],
                'source': r[2],
                'target': r[3],
                'type': r[4],
                'confidence': 50
            }
            for r in relationships_rows
        ]
    }
    
    # Generate report
    filepath = report_generator.save_report(case_data, format=format_type)
    
    log_audit(session['user_id'], 'GENERATE_REPORT', 
             f'Generated {format_type} report for case {case_id}', 
             request.remote_addr)
    
    return jsonify({
        'status': 'success',
        'filepath': filepath,
        'download_url': f'/api/report/download/{filepath.split("/")[-1]}'
    })

@app.route('/api/report/download/<filename>')
@login_required
def download_report(filename):
    """Download a generated report"""
    from flask import send_file
    filepath = os.path.join(report_generator.templates_path, filename)
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    return jsonify({'error': 'File not found'}), 404

@app.route('/api/graph/visualize/<int:case_id>')
@login_required
def visualize_graph(case_id):
    """Get graph data for visualization"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    c.execute("SELECT * FROM entities WHERE case_id = ?", (case_id,))
    entities_rows = c.fetchall()
    c.execute("SELECT * FROM relationships WHERE case_id = ?", (case_id,))
    relationships_rows = c.fetchall()
    conn.close()
    
    nodes = []
    entity_map = {}
    for i, row in enumerate(entities_rows):
        eid, _, etype, value, metadata, _ = row
        entity_map[eid] = i
        try:
            meta = json.loads(metadata) if metadata else {}
        except:
            meta = {}
        
        color = '#667eea'
        if etype == 'IP': color = '#e74c3c'
        elif etype == 'DOMAIN': color = '#3498db'
        elif etype == 'VULNERABILITY': color = '#e67e22'
        elif etype == 'EMAIL': color = '#9b59b6'
        
        nodes.append({
            'id': i,
            'label': value[:30] + '...' if len(value) > 30 else value,
            'group': etype,
            'color': color,
            'data': {'value': value, 'metadata': meta}
        })
    
    edges = []
    for row in relationships_rows:
        _, _, src_id, tgt_id, rtype, _ = row
        if src_id in entity_map and tgt_id in entity_map:
            edges.append({
                'from': entity_map[src_id],
                'to': entity_map[tgt_id],
                'label': rtype
            })
    
    return jsonify({
        'nodes': nodes,
        'edges': edges
    })

@app.route('/api/graph/export/<int:case_id>')
@login_required
def export_graph(case_id):
    """Export case intelligence graph to STIX format"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Verify ownership
    c.execute("SELECT id FROM cases WHERE id = ? AND user_id = ?", (case_id, session['user_id']))
    if not c.fetchone():
        conn.close()
        return jsonify({'error': 'Access denied'}), 403
    
    # Get entities and relationships
    c.execute("SELECT * FROM entities WHERE case_id = ?", (case_id,))
    entities_data = c.fetchall()
    c.execute("SELECT * FROM relationships WHERE case_id = ?", (case_id,))
    relationships_data = c.fetchall()
    
    conn.close()
    
    # Build graph
    graph = IntelligenceGraph()
    
    # Add entities (convert from DB format)
    entity_map = {}
    for row in entities_data:
        eid, _, etype, value, metadata, created = row
        try:
            meta = json.loads(metadata) if metadata else {}
        except:
            meta = {}
        
        entity = create_entity(
            EntityType(etype) if etype in [e.value for e in EntityType] else EntityType.IOC,
            value,
            metadata=meta,
            confidence=meta.get('confidence', 50)
        )
        graph.add_entity(entity)
        entity_map[eid] = entity.id
    
    # Add relationships
    for row in relationships_data:
        rid, _, src_id, tgt_id, rtype, created = row
        if src_id in entity_map and tgt_id in entity_map:
            rel = create_relationship(
                graph.entities[entity_map[src_id]],
                graph.entities[entity_map[tgt_id]],
                RelationshipType.ASSOCIATED_WITH  # Default type
            )
            graph.add_relationship(rel)
    
    # Export to STIX
    stix_bundle = graph.export_stix()
    
    log_audit(session['user_id'], 'EXPORT_STIX', 
             f'Exported case {case_id} to STIX format', request.remote_addr)
    
    return jsonify(stix_bundle)

@app.route('/audit')
@login_required
def audit_log():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT * FROM audit_log WHERE user_id = ? ORDER BY timestamp DESC LIMIT 100", (session['user_id'],))
    logs = c.fetchall()
    conn.close()
    return render_template('audit.html', logs=logs)

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Register builtin modules
    register_builtin_modules()
    
    # Register module executors with task queue
    for module_id, module_data in registry.modules.items():
        if module_data['executor']:
            task_queue.register_executor(module_id, module_data['executor'])
    
    # Register advanced tool executors
    def full_recon_executor(task):
        """Execute full reconnaissance chain"""
        return tool_registry.run_recon_chain(task.target)
    
    task_queue.register_executor('full_recon_chain', full_recon_executor)
    
    def kali_comprehensive_executor(task):
        """Execute comprehensive Kali tools scan"""
        return kali_tools.run_comprehensive_recon(task.target)
    
    task_queue.register_executor('kali_comprehensive', kali_comprehensive_executor)
    
    # Start async workers
    task_queue.start_workers(num_workers=5)  # Increased workers for parallel execution
    
    # Register result callback to save results to DB
    def on_task_complete(task):
        """Save completed task results to database"""
        if task.result or task.error:
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            
            metadata = {
                'task_id': task.task_id,
                'status': task.status.value,
                'started_at': task.started_at,
                'completed_at': task.completed_at,
                'retry_count': task.retry_count
            }
            
            if task.result:
                metadata['result'] = task.result
            if task.error:
                metadata['error'] = task.error
            
            c.execute("""
                INSERT INTO entities (case_id, entity_type, value, metadata) 
                VALUES (?, ?, ?, ?)
            """, (task.case_id, f'module_result_{task.module_id}', 
                  f'{task.module_id}: {task.target}', json.dumps(metadata)))
            
            conn.commit()
            conn.close()
    
    task_queue.on_result(on_task_complete)
    
    print("=" * 70)
    print("🛡️  SENTINEL CORE - ELITE OSINT PLATFORM INITIALIZED")
    print("=" * 70)
    print("[*] Module execution engine: ACTIVE")
    print("[*] Task queue workers: 5 (parallel)")
    print("[*] Circuit breakers: ENABLED")
    print("[*] Dynamic script engine: READY (GOD MODE)")
    print("[*] Advanced tool integration: 20+ TOOLS")
    print("[*] Report generator: HTML/STIX/JSON/PDF")
    print(f"[*] Available Kali tools: {', '.join(kali_tools.get_available_tools()) or 'None detected'}")
    print(f"[*] Registered tools: {len(tool_registry.tools)}")
    print(f"[*] Script templates: {len(script_engine.builtin_templates)}")
    print("-" * 70)
    print("📖 QUICK START:")
    print("   1. Access web UI: http://localhost:5001")
    print("   2. Login: admin / admin123")
    print("   3. Create a case and run recon chains")
    print("   4. Execute custom scripts via API")
    print("   5. Generate Maltego-style reports")
    print("-" * 70)
    print("⚡ API ENDPOINTS:")
    print("   POST /api/script/execute    - Run custom Python scripts")
    print("   POST /api/script/save       - Save custom scripts")
    print("   GET  /api/scripts/templates - List builtin templates")
    print("   POST /api/tool/execute      - Execute single tool")
    print("   POST /api/recon/full-chain  - Full recon automation")
    print("   GET  /api/report/generate   - Generate reports")
    print("   GET  /api/graph/visualize   - Graph visualization data")
    print("=" * 70)
    
    try:
        app.run(debug=False, host='0.0.0.0', port=5001)
    finally:
        task_queue.stop_workers()
