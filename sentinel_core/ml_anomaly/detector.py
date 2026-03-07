#!/usr/bin/env python3
"""
ML-Based Anomaly Detection Engine
Uses statistical methods and heuristics to detect anomalies in scan results
"""

import json
import math
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class Anomaly:
    """Represents a detected anomaly"""
    id: str
    type: str
    severity: str  # low, medium, high, critical
    description: str
    affected_entities: List[str]
    confidence: float  # 0-100
    evidence: Dict[str, Any]
    recommendation: str
    detected_at: str = None
    
    def __post_init__(self):
        if self.detected_at is None:
            self.detected_at = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'type': self.type,
            'severity': self.severity,
            'description': self.description,
            'affected_entities': self.affected_entities,
            'confidence': self.confidence,
            'evidence': self.evidence,
            'recommendation': self.recommendation,
            'detected_at': self.detected_at
        }


class AnomalyDetector:
    """
    ML-based anomaly detection for security findings
    Uses statistical analysis, pattern recognition, and heuristics
    """
    
    def __init__(self):
        self.findings_history: List[Dict] = []
        self.baseline_stats: Dict[str, Any] = {}
        self.anomalies: List[Anomaly] = []
        
    def add_finding(self, finding: Dict):
        """Add a finding for analysis"""
        self.findings_history.append(finding)
        self._analyze_finding(finding)
    
    def _analyze_finding(self, finding: Dict):
        """Analyze a single finding for anomalies"""
        finding_type = finding.get('type', '')
        value = finding.get('value', '')
        metadata = finding.get('metadata', {})
        
        # Check for various anomaly types
        self._check_port_anomalies(finding, metadata)
        self._check_subdomain_anomalies(finding, metadata)
        self._check_vulnerability_anomalies(finding, metadata)
        self._check_traffic_anomalies(finding, metadata)
        self._check_certificate_anomalies(finding, metadata)
    
    def _check_port_anomalies(self, finding: Dict, metadata: Dict):
        """Detect unusual port configurations"""
        open_ports = metadata.get('open_ports', [])
        if not open_ports:
            return
        
        # Unusual high ports
        high_ports = [p for p in open_ports if p > 10000]
        if len(high_ports) >= 3:
            self._add_anomaly(
                anomaly_type='unusual_high_ports',
                severity='medium',
                description=f'Unusual number of high-numbered ports open: {high_ports}',
                affected_entities=[finding.get('value', '')],
                confidence=min(60 + len(high_ports) * 5, 90),
                evidence={'high_ports': high_ports, 'total_open': len(open_ports)},
                recommendation='Investigate services running on high ports - may indicate backdoors or custom services'
            )
        
        # Dangerous port combinations
        dangerous_combos = [
            ([21, 22], 'FTP+SSH exposed together'),
            ([3306, 22], 'MySQL+SSH exposed'),
            ([5432, 22], 'PostgreSQL+SSH exposed'),
            ([27017], 'MongoDB exposed (often unsecured)'),
            ([6379], 'Redis exposed (often unsecured)'),
        ]
        
        for ports, desc in dangerous_combos:
            if all(p in open_ports for p in ports):
                self._add_anomaly(
                    anomaly_type='dangerous_port_combo',
                    severity='high',
                    description=desc,
                    affected_entities=[finding.get('value', '')],
                    confidence=85,
                    evidence={'ports': ports, 'all_open_ports': open_ports},
                    recommendation=f'Secure or restrict access to these services: {desc}'
                )
    
    def _check_subdomain_anomalies(self, finding: Dict, metadata: Dict):
        """Detect unusual subdomain patterns"""
        subdomains = metadata.get('subdomains', [])
        if not subdomains:
            return
        
        # Sudden large number of subdomains
        if len(subdomains) > 50:
            self._add_anomaly(
                anomaly_type='subdomain_spray',
                severity='medium',
                description=f'Unusually large number of subdomains detected: {len(subdomains)}',
                affected_entities=[finding.get('value', '')],
                confidence=70,
                evidence={'subdomain_count': len(subdomains), 'sample': subdomains[:10]},
                recommendation='Review subdomains for shadow IT, compromised assets, or typosquatting'
            )
        
        # Suspicious subdomain patterns
        suspicious_patterns = ['dev', 'staging', 'test', 'admin', 'backup', 'db', 'internal']
        found_suspicious = [s for s in subdomains if any(p in s.lower() for p in suspicious_patterns)]
        
        if found_suspicious:
            self._add_anomaly(
                anomaly_type='sensitive_subdomains',
                severity='high',
                description=f'Sensitive subdomains exposed: {found_suspicious[:5]}',
                affected_entities=[finding.get('value', '')] + found_suspicious[:5],
                confidence=80,
                evidence={'sensitive_subdomains': found_suspicious},
                recommendation='Ensure sensitive subdomains are properly secured and not publicly accessible'
            )
    
    def _check_vulnerability_anomalies(self, finding: Dict, metadata: Dict):
        """Detect vulnerability-related anomalies"""
        vulns = metadata.get('vulnerabilities', [])
        cves = metadata.get('cve', [])
        
        if isinstance(cves, str):
            cves = [cves]
        
        # Critical CVEs
        critical_cves = [c for c in cves if any(x in c.upper() for x in ['CVE-2021-44228', 'CVE-2017-0144', 'CVE-2019-0708'])]
        if critical_cves:
            self._add_anomaly(
                anomaly_type='critical_cve',
                severity='critical',
                description=f'Critical CVEs detected: {critical_cves}',
                affected_entities=[finding.get('value', '')],
                confidence=95,
                evidence={'critical_cves': critical_cves},
                recommendation='IMMEDIATE ACTION REQUIRED: Patch these critical vulnerabilities immediately'
            )
        
        # Multiple vulnerabilities on same host
        if len(vulns) >= 5:
            self._add_anomaly(
                anomaly_type='vulnerability_cluster',
                severity='high',
                description=f'Multiple vulnerabilities on single host: {len(vulns)}',
                affected_entities=[finding.get('value', '')],
                confidence=85,
                evidence={'vuln_count': len(vulns), 'vulns': vulns[:10]},
                recommendation='Prioritize remediation - this host is highly vulnerable'
            )
    
    def _check_traffic_anomalies(self, finding: Dict, metadata: Dict):
        """Detect traffic pattern anomalies"""
        # This would integrate with actual traffic data in production
        response_times = metadata.get('response_times', [])
        if response_times:
            avg_time = sum(response_times) / len(response_times)
            if avg_time > 5000:  # > 5 seconds
                self._add_anomaly(
                    anomaly_type='slow_response',
                    severity='low',
                    description=f'Abnormally slow response times: {avg_time:.2f}ms average',
                    affected_entities=[finding.get('value', '')],
                    confidence=60,
                    evidence={'avg_response_ms': avg_time, 'samples': len(response_times)},
                    recommendation='Investigate performance issues or potential DoS conditions'
                )
    
    def _check_certificate_anomalies(self, finding: Dict, metadata: Dict):
        """Detect SSL/TLS certificate anomalies"""
        cert_info = metadata.get('certificate', metadata.get('ssl', {}))
        if not cert_info:
            return
        
        # Self-signed certificates
        if cert_info.get('self_signed', False):
            self._add_anomaly(
                anomaly_type='self_signed_cert',
                severity='medium',
                description='Self-signed SSL certificate detected',
                affected_entities=[finding.get('value', '')],
                confidence=90,
                evidence={'cert_info': cert_info},
                recommendation='Replace with certificate from trusted CA for production systems'
            )
        
        # Expiring soon
        days_until_expiry = cert_info.get('days_until_expiry', 999)
        if days_until_expiry < 30:
            severity = 'critical' if days_until_expiry < 7 else 'medium'
            self._add_anomaly(
                anomaly_type='cert_expiring',
                severity=severity,
                description=f'SSL certificate expiring in {days_until_expiry} days',
                affected_entities=[finding.get('value', '')],
                confidence=95,
                evidence={'days_until_expiry': days_until_expiry, 'expiry_date': cert_info.get('expiry_date')},
                recommendation='Renew SSL certificate immediately to prevent service disruption'
            )
        
        # Weak cipher suites
        weak_ciphers = cert_info.get('weak_ciphers', [])
        if weak_ciphers:
            self._add_anomaly(
                anomaly_type='weak_ssl_ciphers',
                severity='high',
                description=f'Weak SSL/TLS cipher suites enabled: {weak_ciphers}',
                affected_entities=[finding.get('value', '')],
                confidence=85,
                evidence={'weak_ciphers': weak_ciphers},
                recommendation='Disable weak cipher suites and enable only TLS 1.2+ with strong ciphers'
            )
    
    def _add_anomaly(self, anomaly_type: str, severity: str, description: str,
                    affected_entities: List[str], confidence: float,
                    evidence: Dict, recommendation: str):
        """Add a detected anomaly"""
        anomaly_id = f"{anomaly_type}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{len(self.anomalies)}"
        
        anomaly = Anomaly(
            id=anomaly_id,
            type=anomaly_type,
            severity=severity,
            description=description,
            affected_entities=affected_entities,
            confidence=confidence,
            evidence=evidence,
            recommendation=recommendation
        )
        
        self.anomalies.append(anomaly)
    
    def get_anomalies(self, severity_filter: Optional[str] = None,
                     min_confidence: float = 0) -> List[Dict]:
        """Get detected anomalies with optional filters"""
        results = []
        for anomaly in self.anomalies:
            if severity_filter and anomaly.severity != severity_filter:
                continue
            if anomaly.confidence < min_confidence:
                continue
            results.append(anomaly.to_dict())
        
        return sorted(results, key=lambda x: (
            {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(x['severity'], 4),
            -x['confidence']
        ))
    
    def get_anomaly_summary(self) -> Dict[str, Any]:
        """Get summary of detected anomalies"""
        by_severity = defaultdict(int)
        by_type = defaultdict(int)
        
        for anomaly in self.anomalies:
            by_severity[anomaly.severity] += 1
            by_type[anomaly.type] += 1
        
        return {
            'total_anomalies': len(self.anomalies),
            'by_severity': dict(by_severity),
            'by_type': dict(by_type),
            'average_confidence': sum(a.confidence for a in self.anomalies) / max(len(self.anomalies), 1),
            'critical_count': by_severity.get('critical', 0),
            'high_count': by_severity.get('high', 0)
        }
    
    def calculate_risk_score(self) -> float:
        """Calculate overall risk score based on anomalies"""
        if not self.anomalies:
            return 0.0
        
        severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 1
        }
        
        total_weight = sum(
            severity_weights.get(a.severity, 1) * (a.confidence / 100)
            for a in self.anomalies
        )
        
        # Normalize to 0-100
        max_possible = len(self.anomalies) * 10
        return min((total_weight / max_possible) * 100, 100) if max_possible > 0 else 0
    
    def clear_anomalies(self):
        """Clear all detected anomalies"""
        self.anomalies.clear()
    
    def export_report(self) -> Dict[str, Any]:
        """Export anomaly detection report"""
        return {
            'generated_at': datetime.now().isoformat(),
            'summary': self.get_anomaly_summary(),
            'risk_score': self.calculate_risk_score(),
            'anomalies': self.get_anomalies(),
            'findings_analyzed': len(self.findings_history)
        }


# Global instance
anomaly_detector = AnomalyDetector()


def get_anomaly_detector() -> AnomalyDetector:
    """Get the global anomaly detector instance"""
    return anomaly_detector
