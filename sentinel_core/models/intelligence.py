"""
Sentinel Core - Data Models for Intelligence Graph
Entities, Relationships, Cases, Scan Results, Notes
"""

import os
import sys
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import bcrypt

# Initialize SQLAlchemy
db = SQLAlchemy()

class User(UserMixin, db.Model):
    """User model with secure password hashing"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='analyst')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    cases = db.relationship('Case', backref='owner', lazy=True)
    notes = db.relationship('Note', backref='author', lazy=True)
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))


class Case(db.Model):
    """Case/Investigation container"""
    __tablename__ = 'cases'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(50), default='active')  # active, closed, archived
    priority = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    entities = db.relationship('Entity', backref='case', lazy=True, cascade='all, delete-orphan')
    notes = db.relationship('Note', backref='case', lazy=True, cascade='all, delete-orphan')
    scan_results = db.relationship('ScanResult', backref='case', lazy=True, cascade='all, delete-orphan')
    playbooks = db.relationship('PlaybookExecution', backref='case', lazy=True)


class Entity(db.Model):
    """Intelligence entities (domains, IPs, emails, etc.)"""
    __tablename__ = 'entities'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False)
    entity_type = db.Column(db.String(50), nullable=False)  # domain, ip, email, url, hash, person, org
    value = db.Column(db.String(500), nullable=False)
    label = db.Column(db.String(200))
    extra_data = db.Column(db.JSON, default=dict)  # Renamed from metadata (reserved word)
    risk_score = db.Column(db.Integer, default=0)  # 0-100
    mitre_techniques = db.Column(db.JSON, default=list)  # Associated MITRE ATT&CK techniques
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    scan_results = db.relationship('ScanResult', backref='entity', lazy=True, cascade='all, delete-orphan')
    notes = db.relationship('Note', backref='entity', lazy=True)
    relationships = db.relationship('Relationship', foreign_keys='Relationship.source_id', backref='source', lazy=True)
    related_to = db.relationship('Relationship', foreign_keys='Relationship.target_id', backref='target', lazy=True)
    
    __table_args__ = (db.UniqueConstraint('case_id', 'value', name='unique_entity_per_case'),)


class Relationship(db.Model):
    """Relationships between entities"""
    __tablename__ = 'relationships'
    
    id = db.Column(db.Integer, primary_key=True)
    source_id = db.Column(db.Integer, db.ForeignKey('entities.id'), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey('entities.id'), nullable=False)
    relationship_type = db.Column(db.String(100), nullable=False)  # resolves_to, hosted_on, owned_by, etc.
    rel_data = db.Column(db.JSON, default=dict)  # Renamed from metadata (reserved word)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ScanResult(db.Model):
    """Results from OSINT scans and tool executions"""
    __tablename__ = 'scan_results'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False)
    entity_id = db.Column(db.Integer, db.ForeignKey('entities.id'), nullable=False)
    tool_name = db.Column(db.String(100), nullable=False)
    tool_category = db.Column(db.String(50))  # recon, web, network, vuln, forensics
    status = db.Column(db.String(20), default='completed')  # pending, running, completed, failed
    input_data = db.Column(db.String(500))  # The target that was scanned
    result_data = db.Column(db.JSON, default=list)  # Actual scan results
    findings_count = db.Column(db.Integer, default=0)
    risk_indicators = db.Column(db.JSON, default=list)  # Detected risks
    mitre_mapping = db.Column(db.JSON, default=list)  # MITRE ATT&CK mappings
    executed_at = db.Column(db.DateTime, default=datetime.utcnow)
    execution_time = db.Column(db.Float)  # Seconds
    
    # AI analysis
    ai_analysis = db.Column(db.Text)
    ai_role = db.Column(db.String(100))


class Note(db.Model):
    """Notes with AI enhancement capabilities"""
    __tablename__ = 'notes'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False)
    entity_id = db.Column(db.Integer, db.ForeignKey('entities.id'), nullable=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    tags = db.Column(db.JSON, default=list)
    ai_enhanced = db.Column(db.Boolean, default=False)
    ai_suggestions = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CustomTool(db.Model):
    """User-created custom tools/scripts"""
    __tablename__ = 'custom_tools'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(50), default='custom')
    command_template = db.Column(db.Text, nullable=False)  # With {{target}} placeholder
    parameters = db.Column(db.JSON, default=dict)
    language = db.Column(db.String(20), default='bash')  # bash, python, php, nodejs
    is_active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Playbook(db.Model):
    """Automated playbook definitions"""
    __tablename__ = 'playbooks'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False)
    description = db.Column(db.Text)
    steps = db.Column(db.JSON, nullable=False)  # List of tool executions with conditions
    category = db.Column(db.String(50))  # recon, bug_hunt, incident_response
    author = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class PlaybookExecution(db.Model):
    """Executed playbook instances"""
    __tablename__ = 'playbook_executions'
    
    id = db.Column(db.Integer, primary_key=True)
    playbook_id = db.Column(db.Integer, db.ForeignKey('playbooks.id'), nullable=False)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False)
    status = db.Column(db.String(20), default='running')  # running, completed, failed, stopped
    current_step = db.Column(db.Integer, default=0)
    total_steps = db.Column(db.Integer)
    results = db.Column(db.JSON, default=list)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)


class AuditLog(db.Model):
    """Audit trail for all actions"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50))
    resource_id = db.Column(db.Integer)
    details = db.Column(db.JSON, default=dict)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class AIPrompt(db.Model):
    """AI conversation history and context storage"""
    __tablename__ = 'ai_prompts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=True)
    role = db.Column(db.String(100))  # AI role used
    prompt = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text)
    tokens_used = db.Column(db.Integer, default=0)
    context_data = db.Column(db.JSON, default=dict)  # Injected case/entity/scan data
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


def init_db():
    """Initialize database tables"""
    from app import app
    with app.app_context():
        db.create_all()
        
        # Create default admin user if not exists.
        # Never seed a known default password — require env or one-time generate.
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            import secrets
            initial_password = os.environ.get('SHADOWSEYE_ADMIN_PASSWORD')
            generated = False
            if not initial_password:
                initial_password = secrets.token_urlsafe(16)
                generated = True
            admin = User(username='admin', role='admin')
            admin.set_password(initial_password)
            db.session.add(admin)
            db.session.commit()
            if generated:
                print(
                    "\n*** FIRST BOOT: admin password was auto-generated ***\n"
                    "    Username: admin\n"
                    f"    Password: {initial_password}\n"
                    "    Set SHADOWSEYE_ADMIN_PASSWORD to supply your own on first boot.\n"
                    "    Change immediately after login. Never commit this value.\n"
                )
            else:
                print(
                    "\n*** FIRST BOOT: admin user created from SHADOWSEYE_ADMIN_PASSWORD ***\n"
                    "    Username: admin\n"
                    "    Password: (taken from environment — not printed)\n"
                )
            
        # Seed default playbooks
        seed_playbooks()


def seed_playbooks():
    """Seed default playbooks"""
    playbooks_data = [
        {
            'name': 'MITNICK_RECON',
            'description': 'Kevin Mitnick inspired reconnaissance methodology',
            'category': 'recon',
            'author': 'Sentinel Core',
            'steps': [
                {'order': 1, 'tool': 'WHOIS Lookup', 'timeout': 30},
                {'order': 2, 'tool': 'DNS Enumeration', 'timeout': 60},
                {'order': 3, 'tool': 'Subdomain Discovery', 'timeout': 120},
                {'order': 4, 'tool': 'HTTP Probe', 'timeout': 30},
                {'order': 5, 'tool': 'Tech Stack Detection', 'timeout': 30}
            ]
        },
        {
            'name': 'BUG_HUNTER_WEB',
            'description': 'Top bug hunter web reconnaissance workflow',
            'category': 'bug_hunt',
            'author': 'Sentinel Core',
            'steps': [
                {'order': 1, 'tool': 'Subdomain Discovery', 'timeout': 120},
                {'order': 2, 'tool': 'HTTP Probe', 'timeout': 30},
                {'order': 3, 'tool': 'SSL Check', 'timeout': 30},
                {'order': 4, 'tool': 'Nuclei Scan', 'timeout': 300}
            ]
        },
        {
            'name': 'NETWORK_EXTERNAL',
            'description': 'Elite external network assessment',
            'category': 'network',
            'author': 'Sentinel Core',
            'steps': [
                {'order': 1, 'tool': 'Port Scan', 'timeout': 180},
                {'order': 2, 'tool': 'Service Enumeration', 'timeout': 120},
                {'order': 3, 'tool': 'Vulnerability Scan', 'timeout': 300},
                {'order': 4, 'tool': 'GeoIP Lookup', 'timeout': 30}
            ]
        },
        {
            'name': 'INCIDENT_TRIAGE',
            'description': 'Incident responder triage workflow',
            'category': 'incident_response',
            'author': 'Sentinel Core',
            'steps': [
                {'order': 1, 'tool': 'VirusTotal Analysis', 'timeout': 60},
                {'order': 2, 'tool': 'Hash Analysis', 'timeout': 30},
                {'order': 3, 'tool': 'Email Breach Check', 'timeout': 60},
                {'order': 4, 'tool': 'OSINT Gathering', 'timeout': 120}
            ]
        }
    ]
    
    for pb_data in playbooks_data:
        existing = Playbook.query.filter_by(name=pb_data['name']).first()
        if not existing:
            playbook = Playbook(**pb_data)
            db.session.add(playbook)
    
    db.session.commit()
