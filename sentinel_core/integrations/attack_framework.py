#!/usr/bin/env python3
"""
MITRE ATT&CK Framework Integration
Maps findings to ATT&CK techniques, tactics, and procedures (TTPs)
"""

import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


class Tactic(Enum):
    """ATT&CK Tactics"""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class Technique:
    """ATT&CK Technique"""
    id: str
    name: str
    description: str
    tactic: Tactic
    subtechnique_of: Optional[str] = None
    data_sources: List[str] = None
    platforms: List[str] = None
    permissions_required: List[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'tactic': self.tactic.value,
            'subtechnique_of': self.subtechnique_of,
            'data_sources': self.data_sources or [],
            'platforms': self.platforms or [],
            'permissions_required': self.permissions_required or []
        }


class ATTCKMapper:
    """
    MITRE ATT&CK Framework Mapper
    Maps OSINT and pentesting findings to ATT&CK techniques
    """
    
    # Comprehensive technique database (subset for demonstration)
    TECHNIQUES = {
        # Reconnaissance
        'T1592': Technique('T1592', 'Gather Victim Host Information', 
                          "Adversaries may gather information about the victim's hosts", 
                          Tactic.RECONNAISSANCE),
        'T1592.001': Technique('T1592.001', 'Active Scanning', 
                               'Scan IP addresses or domains', 
                               Tactic.RECONNAISSANCE, 'T1592'),
        'T1592.002': Technique('T1592.002', 'Website', 
                               'Gather info from victim websites', 
                               Tactic.RECONNAISSANCE, 'T1592'),
        'T1590': Technique('T1590', 'Gather Victim Network Information', 
                          "Adversaries may gather information about the victim's networks", 
                          Tactic.RECONNAISSANCE),
        'T1590.001': Technique('T1590.001', 'Domain Properties', 
                               'Gather info from domain registration', 
                               Tactic.RECONNAISSANCE, 'T1590'),
        'T1590.002': Technique('T1590.002', 'DNS', 
                               'Gather info from DNS records', 
                               Tactic.RECONNAISSANCE, 'T1590'),
        
        # Resource Development
        'T1583': Technique('T1583', 'Acquire Infrastructure', 
                          'Adversaries may acquire infrastructure for operations', 
                          Tactic.RESOURCE_DEVELOPMENT),
        'T1583.003': Technique('T1583.003', 'Virtual Private Server', 
                               'Acquire VPS infrastructure', 
                               Tactic.RESOURCE_DEVELOPMENT, 'T1583'),
        'T1584': Technique('T1584', 'Compromise Infrastructure', 
                          'Compromise third-party infrastructure', 
                          Tactic.RESOURCE_DEVELOPMENT),
        
        # Initial Access
        'T1190': Technique('T1190', 'Exploit Public-Facing Application', 
                          'Exploit vulnerabilities in public-facing apps', 
                          Tactic.INITIAL_ACCESS),
        'T1133': Technique('T1133', 'External Remote Services', 
                          'Use external remote services to gain access', 
                          Tactic.INITIAL_ACCESS),
        'T1566': Technique('T1566', 'Phishing', 
                          'Send phishing messages', 
                          Tactic.INITIAL_ACCESS),
        
        # Discovery
        'T1046': Technique('T1046', 'Network Service Scanning', 
                          'Scan for open ports and services', 
                          Tactic.DISCOVERY),
        'T1082': Technique('T1082', 'System Information Discovery', 
                          'Gather system information', 
                          Tactic.DISCOVERY),
        'T1087': Technique('T1087', 'Account Discovery', 
                          'Discover local and domain accounts', 
                          Tactic.DISCOVERY),
        
        # Credential Access
        'T1110': Technique('T1110', 'Brute Force', 
                          'Brute force password guessing', 
                          Tactic.CREDENTIAL_ACCESS),
        'T1110.001': Technique('T1110.001', 'Password Guessing', 
                               'Guess passwords for accounts', 
                               Tactic.CREDENTIAL_ACCESS, 'T1110'),
        'T1110.003': Technique('T1110.003', 'Password Spraying', 
                               'Spray passwords across many accounts', 
                               Tactic.CREDENTIAL_ACCESS, 'T1110'),
        
        # Lateral Movement
        'T1021': Technique('T1021', 'Remote Services', 
                          'Use remote services to move laterally', 
                          Tactic.LATERAL_MOVEMENT),
        'T1021.001': Technique('T1021.001', 'Remote Desktop Protocol', 
                               'Use RDP for lateral movement', 
                               Tactic.LATERAL_MOVEMENT, 'T1021'),
        
        # Impact
        'T1489': Technique('T1489', 'Service Stop', 
                          'Stop services to impact availability', 
                          Tactic.IMPACT),
        'T1499': Technique('T1499', 'Endpoint Denial of Service', 
                          'DoS against endpoints', 
                          Tactic.IMPACT),
    }
    
    # Mapping from common findings to ATT&CK techniques
    FINDING_MAPPINGS = {
        'subdomain_enumeration': ['T1592.002', 'T1590.002'],
        'port_scan': ['T1592.001', 'T1046'],
        'vulnerability_scan': ['T1592.001'],
        'ssl_cert_analysis': ['T1592.002'],
        'whois_lookup': ['T1590.001'],
        'dns_enumeration': ['T1590.002'],
        'web_crawl': ['T1592.002'],
        'email_enumeration': ['T1590.001'],
        'brute_force': ['T1110', 'T1110.001'],
        'password_spray': ['T1110.003'],
        'exploit_attempt': ['T1190'],
        'credential_leak': ['T1110'],
    }
    
    def __init__(self):
        self.mapped_findings: List[Dict] = []
    
    def map_finding(self, finding_type: str, finding_data: Dict) -> List[Technique]:
        """Map a finding to ATT&CK techniques"""
        techniques = []
        
        # Check direct mappings
        technique_ids = self.FINDING_MAPPINGS.get(finding_type, [])
        
        # Also check metadata for CVE/vuln patterns
        metadata = finding_data.get('metadata', {})
        if 'cve' in metadata:
            # CVEs often relate to T1190
            technique_ids.append('T1190')
        
        if 'open_ports' in metadata:
            technique_ids.extend(['T1046', 'T1592.001'])
        
        if 'subdomains' in metadata:
            technique_ids.extend(['T1592.002', 'T1590.002'])
        
        # Get unique technique IDs
        technique_ids = list(set(technique_ids))
        
        for tech_id in technique_ids:
            if tech_id in self.TECHNIQUES:
                techniques.append(self.TECHNIQUES[tech_id])
        
        # Store mapping
        if techniques:
            self.mapped_findings.append({
                'finding': finding_data,
                'techniques': [t.to_dict() for t in techniques]
            })
        
        return techniques
    
    def get_technique(self, technique_id: str) -> Optional[Technique]:
        """Get technique by ID"""
        return self.TECHNIQUES.get(technique_id)
    
    def get_techniques_by_tactic(self, tactic: Tactic) -> List[Technique]:
        """Get all techniques for a tactic"""
        return [t for t in self.TECHNIQUES.values() if t.tactic == tactic]
    
    def get_attack_matrix(self) -> Dict[str, List[Dict]]:
        """Get full ATT&CK matrix organized by tactic"""
        matrix = {}
        for tactic in Tactic:
            matrix[tactic.value] = [
                t.to_dict() for t in self.get_techniques_by_tactic(tactic)
            ]
        return matrix
    
    def generate_attack_navigator_layer(self) -> Dict:
        """Generate MITRE ATT&CK Navigator layer JSON"""
        layer = {
            'name': 'Sentinel Core - Detected Techniques',
            'version': '4.5',
            'domain': 'mitre-enterprise',
            'description': 'ATT&CK techniques detected during assessment',
            'filters': {
                'platforms': ['Linux', 'Windows', 'macOS', 'Cloud', 'Network']
            },
            'sorting': 0,
            'layout': {
                'layout': 'side',
                'showID': True,
                'showName': True
            },
            'hideDisabled': False,
            'techniques': [],
            'gradient': {
                'colors': ['#ffffff', '#ff6666']
            },
            'legendItems': [],
            'metadata': [],
            'links': [],
            'showTacticRowBackground': True,
            'tacticRowBackground': '#204e8a',
            'selectTechniquesAcrossTactics': True
        }
        
        # Add detected techniques with scores
        technique_scores = {}
        for mapping in self.mapped_findings:
            for tech in mapping['techniques']:
                tech_id = tech['id']
                if tech_id not in technique_scores:
                    technique_scores[tech_id] = {
                        'techniqueID': tech_id,
                        'score': 0,
                        'color': '',
                        'comment': tech['name']
                    }
                technique_scores[tech_id]['score'] += 1
        
        layer['techniques'] = list(technique_scores.values())
        
        return layer
    
    def export_mappings(self) -> List[Dict]:
        """Export all mappings"""
        return self.mapped_findings
    
    def clear_mappings(self):
        """Clear all stored mappings"""
        self.mapped_findings.clear()


# Global instance
attck_mapper = ATTCKMapper()


def get_attck_mapper() -> ATTCKMapper:
    """Get the global ATT&CK mapper instance"""
    return attck_mapper
