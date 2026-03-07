#!/usr/bin/env python3
"""
Module Registry - Central registry for all OSINT modules
Manages module metadata, input/output schemas, and required secrets
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum


class ModuleStatus(Enum):
    AVAILABLE = "available"
    DISABLED = "disabled"
    REQUIRES_SECRET = "requires_secret"


class ModuleMetadata:
    """Metadata for a registered module"""
    
    def __init__(self, module_id: str, name: str, description: str, version: str,
                 author: str = "Sentinel Core", category: str = "recon"):
        self.module_id = module_id
        self.name = name
        self.description = description
        self.version = version
        self.author = author
        self.category = category
        self.input_schema = {}
        self.output_schema = {}
        self.required_secrets = []
        self.timeout = 60
        self.retries = 3
        self.rate_limit = None
        self.status = ModuleStatus.AVAILABLE
    
    def set_input_schema(self, schema: Dict[str, Any]):
        """Define expected input parameters"""
        self.input_schema = schema
        return self
    
    def set_output_schema(self, schema: Dict[str, Any]):
        """Define expected output structure"""
        self.output_schema = schema
        return self
    
    def require_secrets(self, secrets: List[str]):
        """List required secret keys"""
        self.required_secrets = secrets
        if secrets:
            self.status = ModuleStatus.REQUIRES_SECRET
        return self
    
    def set_timeout(self, seconds: int):
        """Set execution timeout"""
        self.timeout = seconds
        return self
    
    def set_retries(self, count: int):
        """Set retry count on failure"""
        self.retries = count
        return self
    
    def set_rate_limit(self, requests_per_minute: int):
        """Set rate limiting"""
        self.rate_limit = requests_per_minute
        return self
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
        return {
            'module_id': self.module_id,
            'name': self.name,
            'description': self.description,
            'version': self.version,
            'author': self.author,
            'category': self.category,
            'input_schema': self.input_schema,
            'output_schema': self.output_schema,
            'required_secrets': self.required_secrets,
            'timeout': self.timeout,
            'retries': self.retries,
            'rate_limit': self.rate_limit,
            'status': self.status.value
        }


class ModuleRegistry:
    """Central registry for all OSINT modules"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.modules = {}
            cls._instance.secrets = {}
            cls._instance.execution_log = []
        return cls._instance
    
    def register(self, metadata: ModuleMetadata, executor_func=None):
        """Register a module with its metadata and optional executor"""
        self.modules[metadata.module_id] = {
            'metadata': metadata,
            'executor': executor_func,
            'registered_at': datetime.now().isoformat()
        }
        return self
    
    def get_module(self, module_id: str) -> Optional[Dict[str, Any]]:
        """Get module by ID"""
        return self.modules.get(module_id)
    
    def list_modules(self, category: str = None) -> List[Dict[str, Any]]:
        """List all registered modules, optionally filtered by category"""
        modules = []
        for mod in self.modules.values():
            if category is None or mod['metadata'].category == category:
                modules.append(mod['metadata'].to_dict())
        return modules
    
    def set_secret(self, key: str, value: str):
        """Store a secret for module use"""
        self.secrets[key] = value
    
    def get_secret(self, key: str) -> Optional[str]:
        """Retrieve a secret by key"""
        return self.secrets.get(key)
    
    def has_required_secrets(self, module_id: str) -> bool:
        """Check if all required secrets for a module are available"""
        module = self.get_module(module_id)
        if not module:
            return False
        
        for secret in module['metadata'].required_secrets:
            if secret not in self.secrets:
                return False
        return True
    
    def log_execution(self, module_id: str, target: str, status: str, 
                     duration: float, run_id: str = None):
        """Log module execution for provenance tracking"""
        self.execution_log.append({
            'run_id': run_id or f"run_{datetime.now().timestamp()}",
            'module_id': module_id,
            'target': target,
            'status': status,
            'duration': duration,
            'timestamp': datetime.now().isoformat()
        })
    
    def get_execution_history(self, module_id: str = None, limit: int = 100) -> List[Dict]:
        """Get execution history"""
        logs = self.execution_log
        if module_id:
            logs = [l for l in logs if l['module_id'] == module_id]
        return logs[-limit:]


# Global registry instance
registry = ModuleRegistry()


def register_builtin_modules():
    """Register all built-in modules including advanced OSINT sources"""
    import sys
    import os
    
    # Get the base path for modules
    base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    modules_path = os.path.join(base_path, 'modules')
    
    if modules_path not in sys.path:
        sys.path.insert(0, base_path)
    
    try:
        from modules import dns_module, whois_module, ssl_module, crtsh_module
    except ImportError:
        # Fallback: try relative import
        from ..modules import dns_module, whois_module, ssl_module, crtsh_module
    
    # DNS Module
    dns_meta = ModuleMetadata(
        module_id='dns',
        name='DNS Enumeration',
        description='DNS records and subdomain discovery',
        version='2.1.0',
        author='Syed Abrar (Cyb3rvolt3x)',
        category='recon'
    ).set_input_schema({
        'target': {'type': 'string', 'required': True, 'description': 'Domain name'}
    }).set_output_schema({
        'records': {'type': 'object'},
        'subdomains': {'type': 'array'},
        'reverse_dns': {'type': 'string'}
    }).set_timeout(30).set_retries(2)
    
    registry.register(dns_meta, dns_module.run_dns_enumeration)
    
    # WHOIS Module
    whois_meta = ModuleMetadata(
        module_id='whois',
        name='WHOIS Lookup',
        description='Domain registration information',
        version='2.0.0',
        author='Syed Abrar (Cyb3rvolt3x)',
        category='recon'
    ).set_input_schema({
        'target': {'type': 'string', 'required': True, 'description': 'Domain name'}
    }).set_output_schema({
        'registrar': {'type': 'string'},
        'creation_date': {'type': 'string'},
        'expiration_date': {'type': 'string'}
    }).set_timeout(30).set_retries(2)
    
    registry.register(whois_meta, whois_module.run_whois)
    
    # SSL Module
    ssl_meta = ModuleMetadata(
        module_id='ssl',
        name='SSL Certificate Analysis',
        description='Certificate details and validity',
        version='2.0.0',
        author='Syed Abrar (Cyb3rvolt3x)',
        category='recon'
    ).set_input_schema({
        'target': {'type': 'string', 'required': True, 'description': 'Domain or URL'}
    }).set_output_schema({
        'subject': {'type': 'object'},
        'issuer': {'type': 'object'},
        'validity': {'type': 'object'}
    }).set_timeout(20).set_retries(2)
    
    registry.register(ssl_meta, ssl_module.analyze_ssl)
    
    # CRTSH Module
    crtsh_meta = ModuleMetadata(
        module_id='crtsh',
        name='Certificate Transparency',
        description='Subdomain discovery via CT logs',
        version='2.0.0',
        author='Syed Abrar (Cyb3rvolt3x)',
        category='recon'
    ).set_input_schema({
        'target': {'type': 'string', 'required': True, 'description': 'Domain name'}
    }).set_output_schema({
        'subdomains': {'type': 'array'},
        'total_found': {'type': 'integer'}
    }).set_timeout(60).set_retries(3)
    
    registry.register(crtsh_meta, crtsh_module.search_crtsh)
    
    # Shodan Module (Optional - requires API key)
    try:
        from modules import shodan_module
        shodan_meta = ModuleMetadata(
            module_id='shodan',
            name='Shodan Search',
            description='IoT device and service discovery via Shodan',
            version='2.0.0',
            author='Syed Abrar (Cyb3rvolt3x)',
            category='recon'
        ).set_input_schema({
            'target': {'type': 'string', 'required': True, 'description': 'IP, domain, or search query'}
        }).set_output_schema({
            'results': {'type': 'array'},
            'total': {'type': 'integer'}
        }).require_secrets(['SHODAN_API_KEY']).set_timeout(60).set_retries(2)
        
        registry.register(shodan_meta, shodan_module.run_shodan_search)
    except ImportError:
        pass
    
    # VirusTotal Module (Optional - requires API key)
    try:
        from modules import virustotal_module
        vt_meta = ModuleMetadata(
            module_id='virustotal',
            name='VirusTotal Analysis',
            description='Malware and URL reputation checking',
            version='2.0.0',
            author='Syed Abrar (Cyb3rvolt3x)',
            category='threat_intel'
        ).set_input_schema({
            'target': {'type': 'string', 'required': True, 'description': 'File hash, URL, domain, or IP'}
        }).set_output_schema({
            'detections': {'type': 'integer'},
            'total_engines': {'type': 'integer'},
            'report': {'type': 'object'}
        }).require_secrets(['VIRUSTOTAL_API_KEY']).set_timeout(45).set_retries(3)
        
        registry.register(vt_meta, virustotal_module.run_virustotal_scan)
    except ImportError:
        pass
    
    # Wayback Machine Module
    try:
        from modules import wayback_module
        wayback_meta = ModuleMetadata(
            module_id='wayback',
            name='Wayback Machine Archive',
            description='Historical website snapshots and subdomains',
            version='2.0.0',
            author='Syed Abrar (Cyb3rvolt3x)',
            category='recon'
        ).set_input_schema({
            'target': {'type': 'string', 'required': True, 'description': 'Domain name'}
        }).set_output_schema({
            'snapshots': {'type': 'array'},
            'subdomains': {'type': 'array'}
        }).set_timeout(90).set_retries(2)
        
        registry.register(wayback_meta, wayback_module.search_wayback_machine)
    except ImportError:
        pass
    
    # Hunter.io Module (Optional - requires API key)
    try:
        from modules import hunter_module
        hunter_meta = ModuleMetadata(
            module_id='hunter',
            name='Hunter.io Email Finder',
            description='Professional email address discovery',
            version='2.0.0',
            author='Syed Abrar (Cyb3rvolt3x)',
            category='recon'
        ).set_input_schema({
            'target': {'type': 'string', 'required': True, 'description': 'Domain name'}
        }).set_output_schema({
            'emails': {'type': 'array'},
            'sources': {'type': 'array'}
        }).require_secrets(['HUNTER_API_KEY']).set_timeout(60).set_retries(2)
        
        registry.register(hunter_meta, hunter_module.run_hunter_search)
    except ImportError:
        pass
    
    print(f"[*] Registered {len(registry.modules)} built-in modules: {', '.join(registry.modules.keys())}")


if __name__ == '__main__':
    register_builtin_modules()
    print(json.dumps(registry.list_modules(), indent=2))
