#!/usr/bin/env python3
"""
Advanced Correlation Engine - Elite Threat Intelligence Correlation
Correlates findings across multiple sources to identify attack patterns, campaigns, and sophisticated threats
"""

import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum


class CorrelationType(Enum):
    """Types of correlations"""
    IP_INFRASTRUCTURE = "ip_infrastructure"
    DOMAIN_CLUSTER = "domain_cluster"
    SSL_CERTIFICATE = "ssl_certificate"
    WHOIS_PATTERN = "whois_pattern"
    VULNERABILITY_CHAIN = "vulnerability_chain"
    ATTACK_CAMPAIGN = "attack_campaign"
    THREAT_ACTOR = "threat_actor"
    INFRASTRUCTURE_REUSE = "infrastructure_reuse"


@dataclass
class CorrelatedFinding:
    """Represents a correlated finding"""
    id: str
    correlation_type: CorrelationType
    confidence: float  # 0-100
    entities: List[str]
    evidence: List[Dict]
    description: str
    severity: str  # low, medium, high, critical
    mitre_attack: List[str]  # ATT&CK technique IDs
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'correlation_type': self.correlation_type.value,
            'confidence': self.confidence,
            'entities': self.entities,
            'evidence': self.evidence,
            'description': self.description,
            'severity': self.severity,
            'mitre_attack': self.mitre_attack,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }


class CorrelationEngine:
    """
    Advanced correlation engine for threat intelligence
    Implements tactics from elite hackers and threat hunters
    """
    
    def __init__(self):
        self.findings: List[Dict] = []
        self.correlations: Dict[str, CorrelatedFinding] = {}
        self.ip_clusters: Dict[str, Set[str]] = defaultdict(set)
        self.domain_clusters: Dict[str, Set[str]] = defaultdict(set)
        self.ssl_cert_map: Dict[str, Set[str]] = defaultdict(set)
        self.whois_email_map: Dict[str, Set[str]] = defaultdict(set)
        self.vuln_patterns: Dict[str, List[Dict]] = defaultdict(list)
        
    def add_finding(self, finding: Dict):
        """Add a finding for correlation analysis"""
        self.findings.append(finding)
        self._index_finding(finding)
        
        # Trigger correlation analysis
        self._run_correlations()
    
    def _index_finding(self, finding: Dict):
        """Index finding for fast correlation lookups"""
        finding_type = finding.get('type', '')
        value = finding.get('value', '')
        metadata = finding.get('metadata', {})
        
        # Index IPs by subnet /24
        if finding_type == 'ip' or (finding_type == 'scan_result' and 'ip' in value.lower()):
            parts = value.split('.')
            if len(parts) == 4:
                subnet = '.'.join(parts[:3]) + '.0/24'
                self.ip_clusters[subnet].add(value)
        
        # Index domains by root domain
        if finding_type == 'domain' or 'domain' in finding_type.lower():
            root_domain = self._extract_root_domain(value)
            if root_domain:
                self.domain_clusters[root_domain].add(value)
        
        # Index SSL certificates
        if 'ssl' in finding_type.lower() or 'certificate' in metadata:
            cert_hash = metadata.get('cert_hash', metadata.get('fingerprint', ''))
            if cert_hash:
                self.ssl_cert_map[cert_hash].add(value)
        
        # Index WHOIS emails
        whois_data = metadata.get('whois', {})
        if isinstance(whois_data, dict):
            emails = whois_data.get('emails', [])
            if isinstance(emails, str):
                emails = [emails]
            for email in emails:
                if email:
                    self.whois_email_map[email].add(value)
        
        # Index vulnerabilities
        if finding_type == 'vulnerability' or 'cve' in metadata:
            cve = metadata.get('cve', metadata.get('vuln_id', ''))
            if cve:
                self.vuln_patterns[cve].append(finding)
    
    def _extract_root_domain(self, domain: str) -> Optional[str]:
        """Extract root domain from FQDN"""
        parts = domain.split('.')
        if len(parts) >= 2:
            # Handle common TLDs
            if len(parts) >= 3 and parts[-1] in ['co.uk', 'com.au', 'co.jp', 'gov.uk']:
                return '.'.join(parts[-3:])
            return '.'.join(parts[-2:])
        return domain
    
    def _generate_correlation_id(self, correlation_type: CorrelationType, entities: List[str]) -> str:
        """Generate unique ID for correlation"""
        data = f"{correlation_type.value}:{','.join(sorted(entities))}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def _run_correlations(self):
        """Run all correlation analyses"""
        self._correlate_ip_infrastructure()
        self._correlate_domain_clusters()
        self._correlate_ssl_certificates()
        self._correlate_whois_patterns()
        self._correlate_vulnerability_chains()
        self._detect_attack_campaigns()
    
    def _correlate_ip_infrastructure(self):
        """Correlate IPs in same subnet (potential infrastructure)"""
        for subnet, ips in self.ip_clusters.items():
            if len(ips) >= 2:
                corr_id = self._generate_correlation_id(
                    CorrelationType.IP_INFRASTRUCTURE, 
                    list(ips)
                )
                
                if corr_id not in self.correlations:
                    self.correlations[corr_id] = CorrelatedFinding(
                        id=corr_id,
                        correlation_type=CorrelationType.IP_INFRASTRUCTURE,
                        confidence=min(85 + len(ips) * 2, 98),
                        entities=list(ips),
                        evidence=[{'subnet': subnet, 'ip_count': len(ips)}],
                        description=f"Multiple hosts detected in {subnet} subnet - potential coordinated infrastructure",
                        severity='medium' if len(ips) < 5 else 'high',
                        mitre_attack=['T1583.003', 'T1584.003']  # Acquire/Compromise Infrastructure
                    )
    
    def _correlate_domain_clusters(self):
        """Correlate subdomains belonging to same root domain"""
        for root_domain, domains in self.domain_clusters.items():
            if len(domains) >= 3:
                corr_id = self._generate_correlation_id(
                    CorrelationType.DOMAIN_CLUSTER,
                    list(domains)
                )
                
                if corr_id not in self.correlations:
                    self.correlations[corr_id] = CorrelatedFinding(
                        id=corr_id,
                        correlation_type=CorrelationType.DOMAIN_CLUSTER,
                        confidence=min(80 + len(domains) * 3, 95),
                        entities=list(domains),
                        evidence=[{'root_domain': root_domain, 'subdomain_count': len(domains)}],
                        description=f"Large attack surface detected: {len(domains)} subdomains under {root_domain}",
                        severity='medium',
                        mitre_attack=['T1592', 'T1590']  # Gather Victim Info
                    )
    
    def _correlate_ssl_certificates(self):
        """Correlate domains sharing SSL certificates"""
        for cert_hash, domains in self.ssl_cert_map.items():
            if len(domains) >= 2:
                corr_id = self._generate_correlation_id(
                    CorrelationType.SSL_CERTIFICATE,
                    list(domains)
                )
                
                if corr_id not in self.correlations:
                    self.correlations[corr_id] = CorrelatedFinding(
                        id=corr_id,
                        correlation_type=CorrelationType.SSL_CERTIFICATE,
                        confidence=90,
                        entities=list(domains),
                        evidence=[{'cert_hash': cert_hash, 'shared_by': len(domains)}],
                        description=f"Domains sharing SSL certificate - likely same organization",
                        severity='low',
                        mitre_attack=['T1592.002']  # Website
                    )
    
    def _correlate_whois_patterns(self):
        """Correlate domains with same WHOIS registration"""
        for email, domains in self.whois_email_map.items():
            if len(domains) >= 2:
                corr_id = self._generate_correlation_id(
                    CorrelationType.WHOIS_PATTERN,
                    list(domains)
                )
                
                if corr_id not in self.correlations:
                    self.correlations[corr_id] = CorrelatedFinding(
                        id=corr_id,
                        correlation_type=CorrelationType.WHOIS_PATTERN,
                        confidence=85,
                        entities=list(domains),
                        evidence=[{'registrant_email': email, 'domain_count': len(domains)}],
                        description=f"Domains registered with same email - ownership correlation",
                        severity='low',
                        mitre_attack=['T1590.002']  # Domain Properties
                    )
    
    def _correlate_vulnerability_chains(self):
        """Identify potential vulnerability chains"""
        # Group vulns by target
        target_vulns: Dict[str, List[Dict]] = defaultdict(list)
        for cve, findings in self.vuln_patterns.items():
            for finding in findings:
                target = finding.get('target', 'unknown')
                target_vulns[target].append({
                    'cve': cve,
                    'severity': finding.get('metadata', {}).get('severity', 'unknown'),
                    'type': finding.get('type', 'vulnerability')
                })
        
        # Look for chains (multiple vulns on same target)
        for target, vulns in target_vulns.items():
            if len(vulns) >= 2:
                corr_id = self._generate_correlation_id(
                    CorrelationType.VULNERABILITY_CHAIN,
                    [target] + [v['cve'] for v in vulns]
                )
                
                if corr_id not in self.correlations:
                    high_severity = sum(1 for v in vulns if v['severity'] in ['high', 'critical'])
                    
                    self.correlations[corr_id] = CorrelatedFinding(
                        id=corr_id,
                        correlation_type=CorrelationType.VULNERABILITY_CHAIN,
                        confidence=min(70 + high_severity * 10, 95),
                        entities=[target] + [v['cve'] for v in vulns],
                        evidence=vulns,
                        description=f"Vulnerability chain detected on {target}: {len(vulns)} CVEs identified",
                        severity='critical' if high_severity >= 2 else 'high',
                        mitre_attack=['T1190', 'T1210']  # Exploit Public-Facing App, Exploitation of Remote Services
                    )
    
    def _detect_attack_campaigns(self):
        """Detect potential attack campaigns based on patterns"""
        # Look for patterns indicating coordinated activity
        campaign_indicators = []
        
        # Multiple high-severity vulns across related infrastructure
        high_sev_correlations = [
            c for c in self.correlations.values()
            if c.severity in ['high', 'critical']
        ]
        
        if len(high_sev_correlations) >= 3:
            all_entities = set()
            for corr in high_sev_correlations:
                all_entities.update(corr.entities)
            
            corr_id = self._generate_correlation_id(
                CorrelationType.ATTACK_CAMPAIGN,
                list(all_entities)
            )
            
            if corr_id not in self.correlations:
                self.correlations[corr_id] = CorrelatedFinding(
                    id=corr_id,
                    correlation_type=CorrelationType.ATTACK_CAMPAIGN,
                    confidence=75,
                    entities=list(all_entities),
                    evidence=[{'high_severity_findings': len(high_sev_correlations)}],
                    description=f"Potential attack campaign: {len(high_sev_correlations)} high-severity correlations detected",
                    severity='critical',
                    mitre_attack=['T1587.001', 'T1588.001']  # Malware, Tool acquisition
                )
    
    def get_correlations(self, filter_type: Optional[CorrelationType] = None,
                        min_confidence: float = 0) -> List[Dict]:
        """Get all correlations, optionally filtered"""
        results = []
        for corr in self.correlations.values():
            if filter_type and corr.correlation_type != filter_type:
                continue
            if corr.confidence < min_confidence:
                continue
            results.append(corr.to_dict())
        
        return sorted(results, key=lambda x: x['confidence'], reverse=True)
    
    def get_correlation_summary(self) -> Dict[str, Any]:
        """Get summary of all correlations"""
        by_type = defaultdict(int)
        by_severity = defaultdict(int)
        
        for corr in self.correlations.values():
            by_type[corr.correlation_type.value] += 1
            by_severity[corr.severity] += 1
        
        return {
            'total_correlations': len(self.correlations),
            'by_type': dict(by_type),
            'by_severity': dict(by_severity),
            'average_confidence': sum(c.confidence for c in self.correlations.values()) / max(len(self.correlations), 1)
        }
    
    def export_to_stix(self) -> Dict:
        """Export correlations to STIX 2.1 format"""
        bundle = {
            'type': 'bundle',
            'id': f"bundle--{hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:32]}",
            'objects': []
        }
        
        for corr in self.correlations.values():
            # Create indicator
            indicator = {
                'type': 'indicator',
                'spec_version': '2.1',
                'id': f"indicator--{corr.id}",
                'created': corr.created_at,
                'modified': corr.updated_at,
                'name': f"Correlation: {corr.correlation_type.value}",
                'description': corr.description,
                'pattern': f"[ipv4-addr:value IN ({','.join(corr.entities)})]",
                'pattern_type': 'stix',
                'valid_from': corr.created_at,
                'confidence': corr.confidence,
                'labels': [corr.correlation_type.value, corr.severity],
                'external_references': [
                    {'source_name': 'mitre-attack', 'external_id': tech}
                    for tech in corr.mitre_attack
                ]
            }
            bundle['objects'].append(indicator)
        
        return bundle


# Global instance
correlation_engine = CorrelationEngine()


def get_correlation_engine() -> CorrelationEngine:
    """Get the global correlation engine instance"""
    return correlation_engine
