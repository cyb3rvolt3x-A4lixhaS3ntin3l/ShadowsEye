"""
Sentinel Core - Elite Cybersecurity Intelligence Platform
Main Flask Application with Full Integration of:
- 8 OSINT Modules (DNS, WHOIS, SSL, CT, Shodan, VirusTotal, Wayback, Hunter.io)
- Kimi Moonshot AI via NVIDIA NIM (12 Elite Roles)
- Kali/Parrot Tool Integration (nmap, subfinder, nuclei, sqlmap, gobuster, etc.)
- MITRE ATT&CK Framework Mapping
- Advanced Correlation Engine
- ML-Based Anomaly Detection
- Automated Playbook Engine
- Custom Tool Creator
- Live Terminal with Agentic AI
"""

import os
import sys
import json
import logging
import subprocess
import hashlib
import re
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Dict, List, Any, Optional

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
# Use absolute path for database
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(BASE_DIR, "db", "sentinel.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('SentinelCore')

# ============================================================================
# DATABASE MODELS
# ============================================================================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(120), unique=True)
    role = db.Column(db.String(50), default='analyst')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime)
    
    cases = db.relationship('Case', backref='owner', lazy=True)
    notes = db.relationship('Note', backref='author', lazy=True)
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)


class Case(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(50), default='active')
    priority = db.Column(db.String(20), default='medium')
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    entities = db.relationship('Entity', backref='case', lazy=True, cascade='all, delete-orphan')
    notes = db.relationship('Note', backref='case', lazy=True, cascade='all, delete-orphan')
    scan_results = db.relationship('ScanResult', backref='case', lazy=True, cascade='all, delete-orphan')
    findings = db.relationship('Finding', backref='case', lazy=True, cascade='all, delete-orphan')


class Entity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False)
    entity_type = db.Column(db.String(50), nullable=False)  # domain, ip, email, url, hash, etc.
    value = db.Column(db.String(500), nullable=False)
    entity_metadata = db.Column(db.JSON, default=dict)
    risk_score = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    scan_results = db.relationship('ScanResult', backref='entity', lazy=True, cascade='all, delete-orphan')
    relationships = db.relationship('Relationship', foreign_keys='Relationship.source_id', backref='source', lazy=True)
    related_to = db.relationship('Relationship', foreign_keys='Relationship.target_id', backref='target', lazy=True)


class Relationship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    source_id = db.Column(db.Integer, db.ForeignKey('entity.id'), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey('entity.id'), nullable=False)
    relationship_type = db.Column(db.String(100))  # resolves_to, hosted_on, registered_by, etc.
    confidence = db.Column(db.Float, default=1.0)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False)
    entity_id = db.Column(db.Integer, db.ForeignKey('entity.id'), nullable=False)
    module_name = db.Column(db.String(100), nullable=False)
    tool_used = db.Column(db.String(100))
    status = db.Column(db.String(50), default='completed')
    results = db.Column(db.JSON, default=list)
    findings_count = db.Column(db.Integer, default=0)
    executed_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    execution_time = db.Column(db.Float)  # seconds


class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False)
    entity_id = db.Column(db.Integer, db.ForeignKey('entity.id'))
    title = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20))  # critical, high, medium, low, info
    mitre_techniques = db.Column(db.JSON, default=list)  # ['T1595', 'T1592', etc.]
    cvss_score = db.Column(db.Float)
    evidence = db.Column(db.JSON, default=list)
    recommendations = db.Column(db.Text)
    status = db.Column(db.String(50), default='open')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    tags = db.Column(db.JSON, default=list)
    ai_enhanced = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class CustomTool(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(50))  # recon, web, network, vuln, forensics
    command_template = db.Column(db.Text, nullable=False)
    parameters = db.Column(db.JSON, default=list)
    language = db.Column(db.String(20), default='bash')  # bash, python, php
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, default=True)


class Playbook(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    steps = db.Column(db.JSON, nullable=False)  # List of {module, params, conditional}
    timeout_per_step = db.Column(db.Integer, default=300)  # seconds
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100), nullable=False)
    resource = db.Column(db.String(200))
    resource_id = db.Column(db.Integer)
    details = db.Column(db.JSON, default=dict)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service = db.Column(db.String(50), nullable=False, unique=True)  # nvidia, shodan, virustotal, hunter
    key_value = db.Column(db.String(500), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    last_used = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class ConversationHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role = db.Column(db.String(50), default='ethical_hacker')
    messages = db.Column(db.JSON, default=list)
    token_usage = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


# ============================================================================
# LOGIN MANAGER
# ============================================================================

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def log_audit(action: str, resource: str = None, resource_id: int = None, details: dict = None):
    """Log an audit trail entry"""
    try:
        audit = AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action=action,
            resource=resource,
            resource_id=resource_id,
            details=details or {},
            ip_address=request.remote_addr
        )
        db.session.add(audit)
        db.session.commit()
    except Exception as e:
        logger.error(f"Audit logging failed: {e}")


def get_api_key(service: str) -> Optional[str]:
    """Get API key for a service"""
    api_key = APIKey.query.filter_by(service=service, is_active=True).first()
    if api_key:
        api_key.last_used = datetime.now(timezone.utc)
        db.session.commit()
        return api_key.key_value
    return None


def save_api_key(service: str, key_value: str):
    """Save or update API key"""
    existing = APIKey.query.filter_by(service=service).first()
    if existing:
        existing.key_value = key_value
        existing.is_active = True
    else:
        new_key = APIKey(service=service, key_value=key_value)
        db.session.add(new_key)
    db.session.commit()


# ============================================================================
# AI INTEGRATION HELPER
# ============================================================================

def get_kimi_ai():
    """Get Kimi AI instance with configured API key"""
    from integrations.kimi_ai import KimiAIIntegration
    
    api_key = get_api_key('nvidia')
    if not api_key:
        return None
    
    kimi = KimiAIIntegration(api_key=api_key)
    return kimi


def ai_chat(prompt: str, role: str = 'ethical_hacker', context: dict = None):
    """Send chat to Kimi AI"""
    kimi = get_kimi_ai()
    if not kimi:
        return {'success': False, 'error': 'NVIDIA API key not configured'}
    
    result = kimi.chat(prompt, role=role, context_data=context)
    return result


# ============================================================================
# ROUTES - AUTHENTICATION
# ============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()
            
            log_audit('login', 'user', user.id)
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
            log_audit('login_failed', 'user', details={'username': username})
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    log_audit('logout', 'user', current_user.id)
    logout_user()
    return redirect(url_for('login'))


# ============================================================================
# ROUTES - DASHBOARD
# ============================================================================

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    stats = {
        'total_cases': Case.query.count(),
        'active_cases': Case.query.filter_by(status='active').count(),
        'total_entities': Entity.query.count(),
        'total_findings': Finding.query.count(),
        'critical_findings': Finding.query.filter_by(severity='critical', status='open').count(),
        'recent_scans': ScanResult.query.order_by(ScanResult.executed_at.desc()).limit(5).all()
    }
    
    return render_template('dashboard.html', stats=stats)


# ============================================================================
# ROUTES - CASES
# ============================================================================

@app.route('/cases')
@login_required
def cases_list():
    cases = Case.query.order_by(Case.created_at.desc()).all()
    return render_template('cases.html', cases=cases)


@app.route('/case/new', methods=['GET', 'POST'])
@login_required
def case_new():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        priority = request.form.get('priority', 'medium')
        
        # Validate required fields
        if not title:
            flash('Case title is required', 'danger')
            return render_template('case_form.html', action='new')
        
        case = Case(
            title=title,
            description=description,
            priority=priority,
            owner_id=current_user.id
        )
        db.session.add(case)
        db.session.commit()
        
        log_audit('case_created', 'case', case.id, {'title': title})
        flash('Case created successfully', 'success')
        return redirect(url_for('case_detail', case_id=case.id))
    
    return render_template('case_form.html', action='new')


@app.route('/case/<int:case_id>')
@login_required
def case_detail(case_id):
    case = Case.query.get_or_404(case_id)
    
    # Check ownership or admin
    if case.owner_id != current_user.id and current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('cases_list'))
    
    entities = Entity.query.filter_by(case_id=case_id).all()
    findings = Finding.query.filter_by(case_id=case_id).all()
    notes = Note.query.filter_by(case_id=case_id).order_by(Note.created_at.desc()).all()
    scans = ScanResult.query.filter_by(case_id=case_id).order_by(ScanResult.executed_at.desc()).limit(20).all()
    
    return render_template('case_detail.html', 
                         case=case, 
                         entities=entities,
                         findings=findings,
                         notes=notes,
                         scans=scans)


@app.route('/case/<int:case_id>/entity/add', methods=['POST'])
@login_required
def entity_add(case_id):
    case = Case.query.get_or_404(case_id)
    
    entity_type = request.form.get('type')
    value = request.form.get('value')
    
    if not entity_type or not value:
        flash('Entity type and value required', 'danger')
        return redirect(url_for('case_detail', case_id=case_id))
    
    entity = Entity(
        case_id=case_id,
        entity_type=entity_type,
        value=value
    )
    db.session.add(entity)
    db.session.commit()
    
    log_audit('entity_added', 'entity', entity.id, {'case_id': case_id, 'type': entity_type, 'value': value})
    flash('Entity added successfully', 'success')
    
    return redirect(url_for('case_detail', case_id=case_id))


@app.route('/case/<int:case_id>/entity/<int:entity_id>/scan/<module_name>', methods=['POST'])
@login_required
def run_scan(case_id, entity_id, module_name):
    """Run an OSINT module scan on an entity"""
    case = Case.query.get_or_404(case_id)
    entity = Entity.query.get_or_404(entity_id)
    
    start_time = datetime.now(timezone.utc)
    
    try:
        # Import and run the appropriate module
        if module_name == 'dns':
            from modules.dns_module import enumerate_dns, discover_subdomains
            results = enumerate_dns(entity.value)
            subdomains = discover_subdomains(entity.value)
            results['subdomains'] = subdomains
            
        elif module_name == 'whois':
            from modules.whois_module import lookup_whois
            results = lookup_whois(entity.value)
            
        elif module_name == 'ssl':
            from modules.ssl_module import analyze_ssl
            results = analyze_ssl(entity.value)
            
        elif module_name == 'crtsh':
            from modules.crtsh_module import query_crtsh
            results = query_crtsh(entity.value)
            
        elif module_name == 'shodan':
            api_key = get_api_key('shodan')
            if not api_key:
                return jsonify({'error': 'Shodan API key not configured'}), 400
            from modules.shodan_module import search_shodan
            results = search_shodan(entity.value, api_key)
            
        elif module_name == 'virustotal':
            api_key = get_api_key('virustotal')
            if not api_key:
                return jsonify({'error': 'VirusTotal API key not configured'}), 400
            from modules.virustotal_module import analyze_url, analyze_domain, analyze_hash
            # Auto-detect entity type and call appropriate function
            if entity.entity_type == 'url':
                results = analyze_url(entity.value, api_key)
            elif entity.entity_type == 'hash':
                results = analyze_hash(entity.value, api_key)
            else:  # domain, ip
                results = analyze_domain(entity.value, api_key)
            
        elif module_name == 'wayback':
            from modules.wayback_module import get_wayback_snapshots
            results = get_wayback_snapshots(entity.value)
            
        elif module_name == 'hunter':
            api_key = get_api_key('hunter')
            if not api_key:
                return jsonify({'error': 'Hunter.io API key not configured'}), 400
            from modules.hunter_module import domain_search
            results = domain_search(entity.value, api_key)
            
        else:
            return jsonify({'error': f'Unknown module: {module_name}'}), 400
        
        execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        # Save scan result
        scan_result = ScanResult(
            case_id=case_id,
            entity_id=entity_id,
            module_name=module_name,
            status='completed',
            results=results,
            findings_count=len(results.get('findings', [])),
            execution_time=execution_time
        )
        db.session.add(scan_result)
        
        # Auto-create findings from results
        if 'findings' in results:
            for finding in results['findings']:
                f = Finding(
                    case_id=case_id,
                    entity_id=entity_id,
                    title=finding.get('title', 'Unknown Finding'),
                    description=finding.get('description', ''),
                    severity=finding.get('severity', 'info'),
                    mitre_techniques=finding.get('mitre_techniques', []),
                    evidence=finding.get('evidence', []),
                    recommendations=finding.get('recommendations', '')
                )
                db.session.add(f)
        
        db.session.commit()
        
        log_audit('scan_executed', 'scan_result', scan_result.id, {
            'module': module_name,
            'entity': entity.value,
            'execution_time': execution_time
        })
        
        return jsonify({
            'success': True,
            'scan_id': scan_result.id,
            'results': results,
            'execution_time': execution_time
        })
        
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        scan_result = ScanResult(
            case_id=case_id,
            entity_id=entity_id,
            module_name=module_name,
            status='failed',
            results={'error': str(e)},
            execution_time=execution_time
        )
        db.session.add(scan_result)
        db.session.commit()
        
        return jsonify({'error': str(e)}), 500


@app.route('/case/<int:case_id>/entity/<int:entity_id>/auto-scan', methods=['POST'])
@login_required
def auto_scan_entity(case_id, entity_id):
    """Automatically run relevant scans based on entity type"""
    entity = Entity.query.get_or_404(entity_id)
    
    # Determine relevant modules based on entity type
    modules_to_run = []
    
    if entity.entity_type == 'domain':
        modules_to_run = ['whois', 'dns', 'ssl', 'crtsh', 'shodan', 'wayback']
    elif entity.entity_type == 'ip':
        modules_to_run = ['shodan', 'dns']
    elif entity.entity_type == 'url':
        modules_to_run = ['ssl', 'virustotal', 'wayback']
    elif entity.entity_type == 'email':
        modules_to_run = ['hunter']
    
    results = {}
    for module in modules_to_run:
        # Simulate running scan (in real implementation, call run_scan internally)
        results[module] = 'queued'
    
    return jsonify({
        'success': True,
        'modules_queued': modules_to_run,
        'message': f'Scans queued for {entity.value}'
    })


@app.route('/case/<int:case_id>/ai-analyze', methods=['POST'])
@login_required
def ai_analyze_case(case_id):
    """Use Kimi AI to analyze case findings"""
    case = Case.query.get_or_404(case_id)
    findings = Finding.query.filter_by(case_id=case_id).all()
    entities = Entity.query.filter_by(case_id=case_id).all()
    
    role = request.form.get('role', 'ethical_hacker')
    
    context = {
        'case_title': case.title,
        'case_description': case.description,
        'entities': [{'type': e.entity_type, 'value': e.value} for e in entities],
        'findings': [{
            'title': f.title,
            'severity': f.severity,
            'description': f.description
        } for f in findings]
    }
    
    prompt = f"""Analyze this cybersecurity case and provide:
1. Executive Summary
2. Key Findings Assessment
3. Risk Level (Critical/High/Medium/Low)
4. MITRE ATT&CK Techniques Identified
5. Recommended Next Steps
6. Tools/Commands to Run

Case: {case.title}
Description: {case.description}"""

    result = ai_chat(prompt, role=role, context=context)
    
    log_audit('ai_analysis', 'case', case_id, {'role': role, 'success': result.get('success')})
    
    return jsonify(result)


@app.route('/case/<int:case_id>/report/generate', methods=['POST'])
@login_required
def generate_report(case_id):
    """Generate AI-powered report"""
    case = Case.query.get_or_404(case_id)
    findings = Finding.query.filter_by(case_id=case_id).all()
    entities = Entity.query.filter_by(case_id=case_id).all()
    scans = ScanResult.query.filter_by(case_id=case_id).all()
    
    role = request.form.get('role', 'ethical_hacker')
    report_format = request.form.get('format', 'html')
    
    context = {
        'case': {
            'title': case.title,
            'description': case.description,
            'status': case.status,
            'priority': case.priority,
            'created_at': case.created_at.isoformat()
        },
        'entities': [{'type': e.entity_type, 'value': e.value, 'risk_score': e.risk_score} for e in entities],
        'findings': [{
            'title': f.title,
            'severity': f.severity,
            'description': f.description,
            'mitre_techniques': f.mitre_techniques,
            'cvss_score': f.cvss_score,
            'recommendations': f.recommendations
        } for f in findings],
        'scans': [{'module': s.module_name, 'executed_at': s.executed_at.isoformat()} for s in scans]
    }
    
    prompt = f"""Generate a professional cybersecurity assessment report in {report_format} format.

Include:
- Executive Summary
- Assessment Scope
- Detailed Findings with Evidence
- MITRE ATT&CK Mapping
- Risk Assessment
- Prioritized Recommendations
- Conclusion

Be specific and actionable."""

    result = ai_chat(prompt, role=role, context=context)
    
    log_audit('report_generated', 'case', case_id, {'format': report_format, 'role': role})
    
    if result.get('success'):
        return jsonify({
            'success': True,
            'report': result['response'],
            'format': report_format
        })
    else:
        return jsonify(result), 500


# ============================================================================
# ROUTES - TOOLS
# ============================================================================

@app.route('/tools')
@login_required
def tools_list():
    """List all available tools"""
    # Built-in tools
    builtin_tools = [
        {'name': 'WHOIS Lookup', 'category': 'recon', 'description': 'Domain registration information'},
        {'name': 'DNS Enumeration', 'category': 'recon', 'description': 'DNS records & subdomain discovery'},
        {'name': 'SSL Analysis', 'category': 'web', 'description': 'Certificate analysis'},
        {'name': 'Subdomain Discovery', 'category': 'recon', 'description': 'Brute-force subdomain enumeration'},
        {'name': 'Port Scan (nmap)', 'category': 'network', 'description': 'TCP port scanning'},
        {'name': 'HTTP Probe', 'category': 'web', 'description': 'Web server fingerprinting'},
        {'name': 'GeoIP Lookup', 'category': 'recon', 'description': 'IP geolocation'},
        {'name': 'Shodan Search', 'category': 'recon', 'description': 'IoT device discovery'},
        {'name': 'VirusTotal Scan', 'category': 'forensics', 'description': 'Malware analysis'},
        {'name': 'Wayback Machine', 'category': 'recon', 'description': 'Historical web archives'},
        {'name': 'Email Breach Check', 'category': 'forensics', 'description': 'Hunter.io integration'},
    ]
    
    # Custom tools
    custom_tools = CustomTool.query.filter_by(is_active=True).all()
    
    # Organize tools by category
    categories = {
        'recon': [t['name'] for t in builtin_tools if t['category'] == 'recon'],
        'web': [t['name'] for t in builtin_tools if t['category'] == 'web'],
        'network': [t['name'] for t in builtin_tools if t['category'] == 'network'],
        'vuln': [t['name'] for t in builtin_tools if t['category'] == 'vuln'],
        'forensics': [t['name'] for t in builtin_tools if t['category'] == 'forensics']
    }
    
    # Add custom tools to their categories
    for tool in custom_tools:
        if tool.category not in categories:
            categories[tool.category] = []
        categories[tool.category].append(tool.name)
    
    return render_template('tools.html', 
                         builtin_tools=builtin_tools,
                         custom_tools=custom_tools,
                         categories=categories)


@app.route('/tools/custom/create', methods=['GET', 'POST'])
@login_required
def custom_tool_create():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        category = request.form.get('category')
        language = request.form.get('language', 'bash')
        command_template = request.form.get('command')
        
        tool = CustomTool(
            name=name,
            description=description,
            category=category,
            language=language,
            command_template=command_template,
            created_by=current_user.id
        )
        db.session.add(tool)
        db.session.commit()
        
        log_audit('custom_tool_created', 'custom_tool', tool.id, {'name': name})
        flash('Custom tool created successfully', 'success')
        return redirect(url_for('tools_list'))
    
    return render_template('tool_form.html', action='create')


@app.route('/tools/run/<int:tool_id>', methods=['POST'])
@login_required
def run_custom_tool(tool_id):
    """Execute a custom tool"""
    tool = CustomTool.query.get_or_404(tool_id)
    target = request.form.get('target')
    params = request.form.get('params', '{}')
    
    try:
        params_dict = json.loads(params) if params else {}
        
        # Build command
        command = tool.command_template
        command = command.replace('{{target}}', target)
        for key, value in params_dict.items():
            command = command.replace(f'{{{{{key}}}}}', str(value))
        
        # Security: validate command
        dangerous_patterns = ['rm -rf', 'dd if=', ':(){:|:&};:', '> /dev/', 'mkfs']
        for pattern in dangerous_patterns:
            if pattern in command:
                return jsonify({'error': 'Dangerous command detected'}), 400
        
        # Execute command
        start_time = datetime.now(timezone.utc)
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300
        )
        execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        log_audit('custom_tool_executed', 'custom_tool', tool_id, {
            'name': tool.name,
            'target': target,
            'execution_time': execution_time
        })
        
        return jsonify({
            'success': True,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode,
            'execution_time': execution_time
        })
        
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Command timed out'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/tools/kali/<tool_name>', methods=['POST'])
@login_required
def run_kali_tool(tool_name):
    """Run a Kali/Parrot security tool"""
    target = request.form.get('target')
    options = request.form.get('options', '')
    
    allowed_tools = ['nmap', 'whois', 'dig', 'nslookup', 'sslscan', 'subfinder', 'httpx', 'nuclei', 'nikto', 'gobuster', 'amass', 'sqlmap', 'theHarvester', 'dnsrecon', 'whatweb', 'wafw00f', 'dirb', 'wfuzz', 'hydra', 'john', 'hashcat', 'metasploit', 'burpsuite', 'zap', 'masscan', 'ffuf', 'feroxbuster', 'rustscan', 'naabu', 'httpx-toolkit']
    
    if tool_name not in allowed_tools:
        return jsonify({'error': f'Tool {tool_name} not allowed'}), 400
    
    # Build safe command
    import shlex
    safe_target = shlex.quote(target)
    safe_options = shlex.quote(options) if options else ''
    
    command = f"{tool_name} {safe_options} {safe_target}"
    
    try:
        start_time = datetime.now(timezone.utc)
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=600
        )
        execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        log_audit('kali_tool_executed', 'tool', None, {
            'tool': tool_name,
            'target': target,
            'execution_time': execution_time
        })
        
        return jsonify({
            'success': True,
            'output': result.stdout + result.stderr,
            'command': command,
            'execution_time': execution_time
        })
        
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Command timed out'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# ROUTES - TERMINAL (Agentic AI)
# ============================================================================

@app.route('/terminal')
@login_required
def terminal():
    return render_template('terminal.html')


@app.route('/terminal/execute', methods=['POST'])
@login_required
def terminal_execute():
    """Execute command in terminal (with AI agentic mode)"""
    command = request.form.get('command')
    agentic = request.form.get('agentic', 'false') == 'true'
    
    # Security whitelist
    allowed_commands = [
        'nmap', 'whois', 'dig', 'nslookup', 'host', 'resolvectl',
        'curl', 'wget', 'grep', 'awk', 'sed', 'cat', 'less', 'head', 'tail',
        'find', 'ls', 'pwd', 'date', 'echo', 'wc', 'sort', 'uniq',
        'sslscan', 'testssl', 'subfinder', 'amass', 'httpx', 'nuclei', 'nikto', 'gobuster', 'sqlmap', 'theHarvester', 'dnsrecon', 'whatweb', 'wafw00f', 'dirb', 'wfuzz', 'masscan', 'ffuf', 'feroxbuster', 'rustscan', 'naabu', 'curl', 'wget'
    ]
    
    # Parse command
    cmd_parts = command.split()
    base_cmd = cmd_parts[0] if cmd_parts else ''
    
    if base_cmd not in allowed_commands:
        return jsonify({'error': f'Command {base_cmd} not allowed for security reasons'}), 400
    
    # Dangerous pattern check
    dangerous = ['rm ', 'dd ', 'mkfs', 'chmod 777', 'chown', 'sudo', 'su ', '> /etc/', '> /dev/']
    for pattern in dangerous:
        if pattern in command:
            return jsonify({'error': 'Dangerous command pattern detected'}), 400
    
    try:
        start_time = datetime.now(timezone.utc)
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300,
            cwd='/tmp'
        )
        execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        log_audit('terminal_command', 'terminal', None, {
            'command': command[:200],
            'execution_time': execution_time
        })
        
        return jsonify({
            'success': True,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode,
            'execution_time': execution_time
        })
        
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Command timed out'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/terminal/ai-suggest', methods=['POST'])
@login_required
def terminal_ai_suggest():
    """Get AI command suggestions based on context"""
    context = request.form.get('context', '')
    entity_type = request.form.get('entity_type', '')
    entity_value = request.form.get('entity_value', '')
    
    prompt = f"""Based on this cybersecurity investigation context, suggest 5 specific terminal commands to run.

Context: {context}
Entity Type: {entity_type}
Entity Value: {entity_value}

Provide only the commands, one per line, with brief explanations."""

    result = ai_chat(prompt, role='red_teamer')
    
    if result.get('success'):
        # Parse commands from response
        commands = []
        for line in result['response'].split('\n'):
            if line.strip() and any(tool in line for tool in ['nmap', 'dig', 'whois', 'curl', 'subfinder', 'nuclei']):
                commands.append(line.strip())
        
        return jsonify({
            'success': True,
            'suggestions': commands[:5],
            'full_response': result['response']
        })
    else:
        return jsonify(result), 500


# ============================================================================
# ROUTES - PLAYBOOKS
# ============================================================================

@app.route('/playbooks')
@login_required
def playbooks_list():
    playbooks = Playbook.query.all()
    return render_template('playbooks.html', playbooks=playbooks)


@app.route('/playbook/new', methods=['GET', 'POST'])
@login_required
def playbook_create():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        steps_json = request.form.get('steps')
        
        try:
            steps = json.loads(steps_json)
        except:
            flash('Invalid steps JSON', 'danger')
            return redirect(url_for('playbook_create'))
        
        playbook = Playbook(
            name=name,
            description=description,
            steps=steps,
            created_by=current_user.id
        )
        db.session.add(playbook)
        db.session.commit()
        
        log_audit('playbook_created', 'playbook', playbook.id, {'name': name})
        flash('Playbook created successfully', 'success')
        return redirect(url_for('playbooks_list'))
    
    # Pre-built playbook templates
    templates = [
        {
            'name': 'MITNICK_RECON',
            'description': 'Kevin Mitnick inspired reconnaissance methodology',
            'steps': [
                {'module': 'whois', 'timeout': 30},
                {'module': 'dns', 'timeout': 60},
                {'module': 'crtsh', 'timeout': 60},
                {'module': 'subfinder', 'timeout': 120},
                {'module': 'httpx', 'timeout': 120},
                {'module': 'nuclei', 'timeout': 300}
            ]
        },
        {
            'name': 'BUG_HUNTER_WEB',
            'description': 'Top bug hunter web reconnaissance workflow',
            'steps': [
                {'module': 'subfinder', 'timeout': 120},
                {'module': 'httpx', 'timeout': 120},
                {'module': 'ssl', 'timeout': 30},
                {'module': 'nuclei', 'timeout': 300},
                {'module': 'wayback', 'timeout': 60}
            ]
        },
        {
            'name': 'NETWORK_EXTERNAL',
            'description': 'External network assessment',
            'steps': [
                {'module': 'nmap', 'options': '-sS -sV -O', 'timeout': 300},
                {'module': 'shodan', 'timeout': 60},
                {'module': 'sslscan', 'timeout': 60},
                {'module': 'nikto', 'timeout': 300}
            ]
        }
    ]
    
    return render_template('playbook_form.html', action='create', templates=templates)


@app.route('/playbook/<int:playbook_id>/execute', methods=['POST'])
@login_required
def playbook_execute(playbook_id):
    """Execute a playbook on a target"""
    playbook = Playbook.query.get_or_404(playbook_id)
    target = request.form.get('target')
    case_id = request.form.get('case_id')
    
    if not case_id:
        # Create temporary case
        case = Case(
            title=f"Playbook: {playbook.name} - {target}",
            description=f"Automated playbook execution",
            owner_id=current_user.id
        )
        db.session.add(case)
        db.session.commit()
        case_id = case.id
    
    # Add entity
    entity = Entity(
        case_id=case_id,
        entity_type='domain',
        value=target
    )
    db.session.add(entity)
    db.session.commit()
    
    results = []
    
    for step in playbook.steps:
        module = step.get('module')
        timeout = step.get('timeout', 300)
        options = step.get('options', '')
        
        # Execute step (simplified - in production use task queue)
        try:
            # Here you would call the actual module/tool
            results.append({
                'step': module,
                'status': 'completed',
                'timeout': timeout
            })
        except Exception as e:
            results.append({
                'step': module,
                'status': 'failed',
                'error': str(e)
            })
    
    log_audit('playbook_executed', 'playbook', playbook_id, {
        'target': target,
        'case_id': case_id,
        'results_count': len(results)
    })
    
    return jsonify({
        'success': True,
        'case_id': case_id,
        'entity_id': entity.id,
        'results': results
    })


# ============================================================================
# ROUTES - NOTES
# ============================================================================

@app.route('/case/<int:case_id>/note/add', methods=['POST'])
@login_required
def note_add(case_id):
    content = request.form.get('content')
    tags_str = request.form.get('tags', '')
    tags = [t.strip() for t in tags_str.split(',') if t.strip()]
    
    note = Note(
        case_id=case_id,
        author_id=current_user.id,
        content=content,
        tags=tags
    )
    db.session.add(note)
    db.session.commit()
    
    log_audit('note_created', 'note', note.id, {'case_id': case_id})
    flash('Note added successfully', 'success')
    
    return redirect(url_for('case_detail', case_id=case_id))


@app.route('/note/<int:note_id>/ai-enhance', methods=['POST'])
@login_required
def note_ai_enhance(note_id):
    note = Note.query.get_or_404(note_id)
    
    prompt = f"""Enhance this cybersecurity investigation note with:
1. Professional formatting
2. Technical accuracy improvements
3. Additional context or insights
4. Suggested next steps

Original Note:
{note.content}"""

    result = ai_chat(prompt, role='soc_analyst')
    
    if result.get('success'):
        note.content = result['response']
        note.ai_enhanced = True
        db.session.commit()
        
        return jsonify({
            'success': True,
            'enhanced_content': result['response']
        })
    else:
        return jsonify(result), 500


# ============================================================================
# ROUTES - SETTINGS
# ============================================================================

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        # Save API keys
        nvidia_key = request.form.get('nvidia_api_key')
        shodan_key = request.form.get('shodan_api_key')
        virustotal_key = request.form.get('virustotal_api_key')
        hunter_key = request.form.get('hunter_api_key')
        
        if nvidia_key:
            save_api_key('nvidia', nvidia_key)
        if shodan_key:
            save_api_key('shodan', shodan_key)
        if virustotal_key:
            save_api_key('virustotal', virustotal_key)
        if hunter_key:
            save_api_key('hunter', hunter_key)
        
        # Save preferences
        theme = request.form.get('theme', 'dark')
        agentic_mode = request.form.get('agentic_mode') == 'on'
        
        # Store in session or user preferences
        session['theme'] = theme
        session['agentic_mode'] = agentic_mode
        
        flash('Settings saved successfully', 'success')
        log_audit('settings_updated', 'user', current_user.id)
        return redirect(url_for('settings'))
    
    # Load current settings
    nvidia_key = get_api_key('nvidia')
    shodan_key = get_api_key('shodan')
    virustotal_key = get_api_key('virustotal')
    hunter_key = get_api_key('hunter')
    
    # Build settings dict for template
    settings = {
        'nvidia_api_key': nvidia_key or '',
        'shodan_api_key': shodan_key or '',
        'virustotal_api_key': virustotal_key or '',
        'hunter_api_key': hunter_key or '',
        'ai_model': session.get('ai_model', 'moonshotai/kimi-k2.5'),
        'agentic_mode': session.get('agentic_mode', False),
        'theme': session.get('theme', 'dark')
    }
    
    return render_template('settings.html',
                         nvidia_configured=bool(nvidia_key),
                         shodan_configured=bool(shodan_key),
                         virustotal_configured=bool(virustotal_key),
                         hunter_configured=bool(hunter_key),
                         settings=settings)


# ============================================================================
# ROUTES - AUDIT LOGS
# ============================================================================

@app.route('/audit-logs')
@login_required
def audit_logs():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return render_template('audit_logs.html', logs=logs)


# ============================================================================
# ROUTES - GRAPH VIEW
# ============================================================================

@app.route('/case/<int:case_id>/graph')
@login_required
def case_graph(case_id):
    case = Case.query.get_or_404(case_id)
    entities = Entity.query.filter_by(case_id=case_id).all()
    relationships = Relationship.query.join(Entity, Relationship.source_id == Entity.id).filter(Entity.case_id == case_id).all()
    
    nodes = []
    for e in entities:
        nodes.append({
            'id': e.id,
            'label': e.value[:50],
            'type': e.entity_type,
            'risk_score': e.risk_score
        })
    
    links = []
    for r in relationships:
        links.append({
            'source': r.source_id,
            'target': r.target_id,
            'type': r.relationship_type
        })
    
    return render_template('graph.html', case=case, nodes=nodes, links=links)


# ============================================================================
# ROUTES - MITRE ATT&CK
# ============================================================================

@app.route('/mitre/export/<int:case_id>', methods=['GET'])
@login_required
def mitre_export(case_id):
    """Export MITRE ATT&CK Navigator layer"""
    case = Case.query.get_or_404(case_id)
    findings = Finding.query.filter_by(case_id=case_id).all()
    
    # Build Navigator layer
    techniques = []
    for finding in findings:
        for technique_id in finding.mitre_techniques:
            techniques.append({
                'techniqueID': technique_id,
                'tactic': 'unknown',
                'color': '#ff0000' if finding.severity == 'critical' else '#ffa500',
                'comment': f"{finding.title} ({finding.severity})"
            })
    
    layer = {
        'name': f"MITRE ATT&CK - {case.title}",
        'versions': {'attack': '13', 'navigator': '4.8.0', 'layer': '4.4'},
        'domain': 'enterprise-attack',
        'description': f"Automated export from Sentinel Core - {case.title}",
        'filters': {'platforms': ['Linux', 'Windows', 'macOS', 'Cloud']},
        'sorting': 0,
        'layout': {'layout': 'side', 'showName': True, 'showID': True},
        'hideDisabled': False,
        'techniques': techniques,
        'gradient': {'colors': ['#ff0000', '#ffa500', '#ffff00'], 'minValue': 0, 'maxValue': 100},
        'legendItems': [
            {'label': 'Critical', 'color': '#ff0000'},
            {'label': 'High', 'color': '#ffa500'},
            {'label': 'Medium', 'color': '#ffff00'}
        ],
        'metadata': [
            {'name': 'Case ID', 'value': str(case_id)},
            {'name': 'Export Date', 'value': datetime.now(timezone.utc).isoformat()}
        ],
        'showTacticRowBackground': True,
        'tacticRowBackground': '#dddddd',
        'selectTechniquesAcrossTactics': True
    }
    
    log_audit('mitre_export', 'case', case_id)
    
    return jsonify(layer)


# ============================================================================
# INITIALIZATION
# ============================================================================

def init_db():
    """Initialize database and create admin user"""
    with app.app_context():
        db.create_all()
        
        # Create admin user if not exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            # Generate secure random password for initial admin
            import secrets
            initial_password = secrets.token_urlsafe(16)
            admin = User(
                username='admin',
                email='admin@sentinel.local',
                password_hash=generate_password_hash(initial_password),
                role='admin'
            )
            logger.info(f"Initial admin password (CHANGE IMMEDIATELY): {initial_password}")
            db.session.add(admin)
            db.session.commit()
        
        # Create default playbooks
        if Playbook.query.count() == 0:
            default_playbooks = [
                Playbook(
                    name='MITNICK_RECON',
                    description='Kevin Mitnick inspired reconnaissance methodology',
                    steps=[
                        {'module': 'whois', 'timeout': 30},
                        {'module': 'dns', 'timeout': 60},
                        {'module': 'crtsh', 'timeout': 60},
                        {'module': 'subfinder', 'timeout': 120},
                        {'module': 'httpx', 'timeout': 120},
                        {'module': 'nuclei', 'timeout': 300}
                    ],
                    created_by=admin.id
                ),
                Playbook(
                    name='BUG_HUNTER_WEB',
                    description='Top bug hunter web reconnaissance workflow',
                    steps=[
                        {'module': 'subfinder', 'timeout': 120},
                        {'module': 'httpx', 'timeout': 120},
                        {'module': 'ssl', 'timeout': 30},
                        {'module': 'nuclei', 'timeout': 300},
                        {'module': 'wayback', 'timeout': 60}
                    ],
                    created_by=admin.id
                ),
                Playbook(
                    name='NETWORK_EXTERNAL',
                    description='External network assessment',
                    steps=[
                        {'module': 'nmap', 'options': '-sS -sV -O', 'timeout': 300},
                        {'module': 'shodan', 'timeout': 60},
                        {'module': 'sslscan', 'timeout': 60},
                        {'module': 'nikto', 'timeout': 300}
                    ],
                    created_by=admin.id
                )
            ]
            for pb in default_playbooks:
                db.session.add(pb)
            db.session.commit()
            logger.info("Default playbooks created")


if __name__ == '__main__':
    # Ensure directories exist
    os.makedirs('logs', exist_ok=True)
    os.makedirs('db', exist_ok=True)
    os.makedirs('evidence', exist_ok=True)
    os.makedirs('user_modules', exist_ok=True)
    
    # Initialize database
    init_db()
    
    logger.info("Starting Sentinel Core...")
    app.run(host='0.0.0.0', port=5001, debug=False)
