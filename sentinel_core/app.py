#!/usr/bin/env python3
"""
Sentinel Core - Advanced OSINT Framework
A professional, modular reconnaissance platform for authorized security research.
"""

import os
import sys
import sqlite3
import hashlib
import secrets
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
import bcrypt

# Initialize Flask App
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
DATABASE = 'db/sentinel.db'

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
    # List available OSINT modules
    modules = [
        {'id': 'whois', 'name': 'WHOIS Lookup', 'description': 'Domain registration information'},
        {'id': 'dns', 'name': 'DNS Enumeration', 'description': 'DNS records and subdomains'},
        {'id': 'ssl', 'name': 'SSL Certificate Analysis', 'description': 'Certificate details and validity'},
        {'id': 'shodan', 'name': 'Shodan Search', 'description': 'Internet-connected devices (requires API key)'},
        {'id': 'virustotal', 'name': 'VirusTotal', 'description': 'File and URL analysis (requires API key)'},
        {'id': 'crtsh', 'name': 'Certificate Transparency', 'description': 'Subdomain discovery via CT logs'},
        {'id': 'wayback', 'name': 'Wayback Machine', 'description': 'Historical web page archives'},
        {'id': 'hunter', 'name': 'Hunter.io', 'description': 'Email finder (requires API key)'},
    ]
    return jsonify(modules)

@app.route('/api/module/run', methods=['POST'])
@login_required
def run_module():
    module_id = request.form.get('module_id')
    target = request.form.get('target')
    case_id = request.form.get('case_id')
    
    # Here you would implement actual module logic
    # For now, we'll simulate a response
    result = {
        'status': 'success',
        'module': module_id,
        'target': target,
        'data': {'message': f'Module {module_id} executed on {target}. Implement actual logic in modules/ directory.'}
    }
    
    # Add result as entity
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("INSERT INTO entities (case_id, entity_type, value, metadata) VALUES (?, ?, ?, ?)",
              (case_id, 'scan_result', f'{module_id}: {target}', str(result)))
    conn.commit()
    conn.close()
    
    log_audit(session['user_id'], 'RUN_MODULE', f'Ran {module_id} on {target}', request.remote_addr)
    return jsonify(result)

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
    init_db()
    print("[*] Sentinel Core OSINT Framework initialized")
    print("[*] Access the web interface at http://localhost:5001")
    print("[*] Default credentials: admin / admin123")
    app.run(debug=False, host='0.0.0.0', port=5001)
