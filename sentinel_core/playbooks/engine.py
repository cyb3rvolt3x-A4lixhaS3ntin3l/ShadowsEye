#!/usr/bin/env python3
"""
Automated Playbook Engine - Elite Pentesting Automation
Implements tactics from Kevin Mitnick, top bug hunters, and elite pentesters
Automates reconnaissance chains based on target type and findings
"""

import json
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum


class PlaybookStage(Enum):
    """Stages in a playbook"""
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


@dataclass
class PlaybookStep:
    """A single step in a playbook"""
    id: str
    name: str
    description: str
    module_id: str
    stage: PlaybookStage
    parameters: Dict[str, Any] = field(default_factory=dict)
    condition: Optional[str] = None  # Condition to execute (e.g., "port 80 open")
    timeout: int = 60
    critical: bool = False  # If fails, stop playbook
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'module_id': self.module_id,
            'stage': self.stage.value,
            'parameters': self.parameters,
            'condition': self.condition,
            'timeout': self.timeout,
            'critical': self.critical
        }


@dataclass
class Playbook:
    """Complete automated playbook"""
    id: str
    name: str
    description: str
    author: str
    target_type: str  # domain, ip, network
    stages: List[PlaybookStage]
    steps: List[PlaybookStep]
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'author': self.author,
            'target_type': self.target_type,
            'stages': [s.value for s in self.stages],
            'steps': [s.to_dict() for s in self.steps],
            'created_at': self.created_at,
            'tags': self.tags
        }


class PlaybookEngine:
    """
    Automated Playbook Engine
    Implements elite pentesting methodologies from:
    - Kevin Mitnick (Social Engineering focus)
    - OWASP Testing Guide
    - PTES (Penetration Testing Execution Standard)
    - NIST SP 800-115
    - Top bug hunter methodologies
    """
    
    def __init__(self):
        self.playbooks: Dict[str, Playbook] = {}
        self.execution_history: List[Dict] = []
        self._register_builtin_playbooks()
    
    def _register_builtin_playbooks(self):
        """Register built-in elite playbooks"""
        
        # MITNICK Method - Comprehensive Recon (inspired by Kevin Mitnick's approach)
        mitnick_recon = Playbook(
            id='mitnick_recon',
            name='Mitnick Comprehensive Recon',
            description='Deep reconnaissance methodology inspired by Kevin Mitnick\'s social engineering and technical recon approach',
            author='Kevin Mitnick (adapted)',
            target_type='domain',
            stages=[PlaybookStage.RECONNAISSANCE, PlaybookStage.ENUMERATION],
            steps=[
                PlaybookStep('m1', 'Passive DNS Recon', 'Gather DNS records passively', 'dns_passive', PlaybookStage.RECONNAISSANCE),
                PlaybookStep('m2', 'Subdomain Enumeration', 'Find all subdomains', 'subdomain_enum', PlaybookStage.RECONNAISSANCE),
                PlaybookStep('m3', 'WHOIS Analysis', 'Analyze domain registration', 'whois_lookup', PlaybookStage.RECONNAISSANCE, 
                            condition='has_whois'),
                PlaybookStep('m4', 'SSL Certificate Analysis', 'Extract info from SSL certs', 'ssl_analysis', PlaybookStage.RECONNAISSANCE),
                PlaybookStep('m5', 'Wayback Machine', 'Historical website analysis', 'wayback_lookup', PlaybookStage.RECONNAISSANCE),
                PlaybookStep('m6', 'Email Enumeration', 'Find associated emails', 'email_enum', PlaybookStage.ENUMERATION),
                PlaybookStep('m7', 'Shodan Recon', 'Search Shodan for exposed services', 'shodan_search', PlaybookStage.ENUMERATION),
                PlaybookStep('m8', 'VirusTotal Check', 'Check VT for existing intel', 'virustotal_scan', PlaybookStage.ENUMERATION),
            ],
            tags=['recon', 'passive', 'mitnick', 'osint']
        )
        
        # Bug Hunter's Web App Playbook
        bug_hunter_web = Playbook(
            id='bug_hunter_web',
            name='Bug Hunter Web Assessment',
            description='Web application assessment playbook used by top bug bounty hunters',
            author='Top Bug Hunters Collective',
            target_type='domain',
            stages=[PlaybookStage.RECONNAISSANCE, PlaybookStage.VULNERABILITY_ASSESSMENT],
            steps=[
                PlaybookStep('bh1', 'Technology Stack Detection', 'Identify web technologies', 'tech_detect', PlaybookStage.RECONNAISSANCE),
                PlaybookStep('bh2', 'Directory Bruteforce', 'Find hidden directories', 'dir_bruteforce', PlaybookStage.RECONNAISSANCE),
                PlaybookStep('bh3', 'Parameter Discovery', 'Find URL parameters', 'param_discover', PlaybookStage.RECONNAISSANCE),
                PlaybookStep('bh4', 'OWASP Top 10 Scan', 'Scan for common vulns', 'owasp_scan', PlaybookStage.VULNERABILITY_ASSESSMENT),
                PlaybookStep('bh5', 'SQL Injection Test', 'Test for SQLi', 'sqli_test', PlaybookStage.VULNERABILITY_ASSESSMENT, critical=True),
                PlaybookStep('bh6', 'XSS Detection', 'Test for XSS', 'xss_detect', PlaybookStage.VULNERABILITY_ASSESSMENT),
                PlaybookStep('bh7', 'SSRF Testing', 'Test for SSRF', 'ssrf_test', PlaybookStage.VULNERABILITY_ASSESSMENT),
                PlaybookStep('bh8', 'API Security Check', 'Test API endpoints', 'api_security', PlaybookStage.VULNERABILITY_ASSESSMENT),
            ],
            tags=['web', 'bug-bounty', 'owasp', 'vulnerability']
        )
        
        # Network Pentester's External Assessment
        network_external = Playbook(
            id='network_external',
            name='External Network Assessment',
            description='External network penetration testing methodology',
            author='Elite Network Pentesters',
            target_type='ip',
            stages=[PlaybookStage.RECONNAISSANCE, PlaybookStage.VULNERABILITY_ASSESSMENT],
            steps=[
                PlaybookStep('ne1', 'Port Scan', 'Full TCP port scan', 'port_scan_full', PlaybookStage.RECONNAISSANCE, 
                            parameters={'ports': '1-65535'}),
                PlaybookStep('ne2', 'Service Detection', 'Identify running services', 'service_detect', PlaybookStage.RECONNAISSANCE),
                PlaybookStep('ne3', 'OS Fingerprinting', 'Determine operating system', 'os_fingerprint', PlaybookStage.RECONNAISSANCE),
                PlaybookStep('ne4', 'Vulnerability Scan', 'Scan for known vulns', 'vuln_scan', PlaybookStage.VULNERABILITY_ASSESSMENT),
                PlaybookStep('ne5', 'SMB Enumeration', 'Check SMB shares', 'smb_enum', PlaybookStage.VULNERABILITY_ASSESSMENT,
                            condition='port 445 open'),
                PlaybookStep('ne6', 'SNMP Check', 'Query SNMP if available', 'snmp_check', PlaybookStage.VULNERABILITY_ASSESSMENT,
                            condition='port 161 open'),
                PlaybookStep('ne7', 'RDP Analysis', 'Analyze RDP service', 'rdp_analyze', PlaybookStage.VULNERABILITY_ASSESSMENT,
                            condition='port 3389 open'),
            ],
            tags=['network', 'external', 'infrastructure']
        )
        
        # Rapid Response Incident Triage
        incident_triage = Playbook(
            id='incident_triage',
            name='Incident Response Triage',
            description='Rapid triage playbook for incident response scenarios',
            author='IR Specialists',
            target_type='ip',
            stages=[PlaybookStage.RECONNAISSANCE, PlaybookStage.ENUMERATION],
            steps=[
                PlaybookStep('ir1', 'Quick Port Scan', 'Fast scan of common ports', 'port_scan_fast', PlaybookStage.RECONNAISSANCE,
                            parameters={'ports': '21,22,23,25,53,80,110,139,143,443,445,993,995,3306,3389,5432,8080'}),
                PlaybookStep('ir2', 'Service Grab', 'Banner grabbing', 'service_grab', PlaybookStage.RECONNAISSANCE),
                PlaybookStep('ir3', 'Malware Indicators', 'Check for malware IOCs', 'malware_ioc', PlaybookStage.ENUMERATION),
                PlaybookStep('ir4', 'C2 Detection', 'Look for C2 communication', 'c2_detect', PlaybookStage.ENUMERATION),
                PlaybookStep('ir5', 'Data Exfil Check', 'Check for data exfiltration', 'exfil_detect', PlaybookStage.ENUMERATION),
            ],
            tags=['incident-response', 'triage', 'rapid']
        )
        
        # Register all playbooks
        for pb in [mitnick_recon, bug_hunter_web, network_external, incident_triage]:
            self.playbooks[pb.id] = pb
    
    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        """Get a playbook by ID"""
        return self.playbooks.get(playbook_id)
    
    def list_playbooks(self, target_type: Optional[str] = None, 
                      tag: Optional[str] = None) -> List[Dict]:
        """List available playbooks with optional filters"""
        results = []
        for pb in self.playbooks.values():
            if target_type and pb.target_type != target_type:
                continue
            if tag and tag not in pb.tags:
                continue
            results.append(pb.to_dict())
        return results
    
    def execute_playbook(self, playbook_id: str, target: str, 
                        case_id: int, user_id: int,
                        executor_callback: Callable = None) -> Dict[str, Any]:
        """
        Execute a playbook against a target
        
        Args:
            playbook_id: ID of playbook to execute
            target: Target domain/IP
            case_id: Case ID for tracking
            user_id: User ID executing
            executor_callback: Function to execute individual modules
        
        Returns:
            Execution results
        """
        playbook = self.get_playbook(playbook_id)
        if not playbook:
            return {'success': False, 'error': 'Playbook not found'}
        
        execution_id = f"{playbook_id}_{target}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        results = {
            'execution_id': execution_id,
            'playbook': playbook.to_dict(),
            'target': target,
            'started_at': datetime.now().isoformat(),
            'steps_results': [],
            'status': 'running'
        }
        
        for step in playbook.steps:
            step_result = {
                'step_id': step.id,
                'step_name': step.name,
                'status': 'pending',
                'started_at': None,
                'completed_at': None,
                'result': None,
                'error': None,
                'skipped': False
            }
            
            # Check condition
            if step.condition and not self._evaluate_condition(step.condition, results):
                step_result['skipped'] = True
                step_result['status'] = 'skipped'
                step_result['error'] = f'Condition not met: {step.condition}'
                results['steps_results'].append(step_result)
                continue
            
            # Execute step
            step_result['started_at'] = datetime.now().isoformat()
            step_result['status'] = 'running'
            
            try:
                if executor_callback:
                    result = executor_callback(step.module_id, target, step.parameters, step.timeout)
                    step_result['result'] = result
                    step_result['status'] = 'success'
                else:
                    step_result['error'] = 'No executor provided'
                    step_result['status'] = 'failed'
                    
            except Exception as e:
                step_result['error'] = str(e)
                step_result['status'] = 'failed'
                
                if step.critical:
                    results['status'] = 'failed'
                    results['steps_results'].append(step_result)
                    break
            
            step_result['completed_at'] = datetime.now().isoformat()
            results['steps_results'].append(step_result)
        
        results['completed_at'] = datetime.now().isoformat()
        results['status'] = 'completed' if results['status'] != 'failed' else 'failed'
        
        # Store execution history
        self.execution_history.append(results)
        
        return results
    
    def _evaluate_condition(self, condition: str, results: Dict) -> bool:
        """Evaluate a step condition"""
        # Simple condition evaluation (can be extended)
        if condition == 'has_whois':
            # Check if WHOIS data exists from previous steps
            for step_result in results['steps_results']:
                if step_result['result'] and 'whois' in str(step_result['result']).lower():
                    return True
            return False
        
        if 'port' in condition.lower() and 'open' in condition.lower():
            # Parse "port X open"
            parts = condition.split()
            if len(parts) >= 3:
                port = parts[1]
                # Check if any previous step found this port open
                for step_result in results['steps_results']:
                    if step_result['result']:
                        result_str = str(step_result['result'])
                        if port in result_str and 'open' in result_str.lower():
                            return True
            return False
        
        return True  # Default to true if condition unknown
    
    def get_execution_history(self, limit: int = 10) -> List[Dict]:
        """Get recent execution history"""
        return self.execution_history[-limit:]
    
    def export_playbook(self, playbook_id: str) -> Optional[Dict]:
        """Export a playbook to JSON"""
        playbook = self.get_playbook(playbook_id)
        if playbook:
            return playbook.to_dict()
        return None
    
    def import_playbook(self, playbook_data: Dict) -> bool:
        """Import a playbook from JSON"""
        try:
            # Validate required fields
            required = ['id', 'name', 'target_type', 'steps']
            if not all(k in playbook_data for k in required):
                return False
            
            # Create Playbook object
            stages = [PlaybookStage(s) for s in playbook_data.get('stages', ['reconnaissance'])]
            steps = []
            for step_data in playbook_data['steps']:
                step = PlaybookStep(
                    id=step_data['id'],
                    name=step_data['name'],
                    description=step_data['description'],
                    module_id=step_data['module_id'],
                    stage=PlaybookStage(step_data['stage']),
                    parameters=step_data.get('parameters', {}),
                    condition=step_data.get('condition'),
                    timeout=step_data.get('timeout', 60),
                    critical=step_data.get('critical', False)
                )
                steps.append(step)
            
            playbook = Playbook(
                id=playbook_data['id'],
                name=playbook_data['name'],
                description=playbook_data.get('description', ''),
                author=playbook_data.get('author', 'Unknown'),
                target_type=playbook_data['target_type'],
                stages=stages,
                steps=steps,
                tags=playbook_data.get('tags', [])
            )
            
            self.playbooks[playbook.id] = playbook
            return True
            
        except Exception as e:
            print(f"Error importing playbook: {e}")
            return False


# Global instance
playbook_engine = PlaybookEngine()


def get_playbook_engine() -> PlaybookEngine:
    """Get the global playbook engine instance"""
    return playbook_engine
