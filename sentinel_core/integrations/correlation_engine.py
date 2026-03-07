"""
Advanced Correlation Engine
IP Infrastructure Correlation, Domain Clustering, SSL Certificate Correlation
WHOIS Pattern Matching, Vulnerability Chain Detection, Attack Campaign Detection
STIX 2.1 Export
"""

import json
from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Any


class CorrelationEngine:
    """Advanced correlation engine for threat intelligence"""
    
    def __init__(self):
        self.ip_subnets = defaultdict(list)
        self.domain_clusters = defaultdict(list)
        self.ssl_certificates = {}
        self.whois_patterns = defaultdict(list)
        
    def correlate_ip_infrastructure(self, ips: List[str]) -> Dict:
        """Cluster IPs by subnet (/24)"""
        result = {
            'timestamp': datetime.utcnow().isoformat(),
            'total_ips': len(ips),
            'subnets': {},
            'clusters': []
        }
        
        for ip in ips:
            parts = ip.split('.')
            if len(parts) == 4:
                subnet = '.'.join(parts[:3]) + '.0/24'
                self.ip_subnets[subnet].append(ip)
        
        for subnet, subnet_ips in self.ip_subnets.items():
            if len(subnet_ips) > 1:
                result['subnets'][subnet] = {
                    'count': len(subnet_ips),
                    'ips': subnet_ips,
                    'risk_indicator': 'high' if len(subnet_ips) > 5 else 'medium'
                }
                result['clusters'].append({
                    'type': 'subnet',
                    'value': subnet,
                    'members': subnet_ips,
                    'confidence': min(100, len(subnet_ips) * 20)
                })
        
        return result
    
    def correlate_domains(self, domains: List[str]) -> Dict:
        """Cluster domains by parent domain and patterns"""
        result = {
            'timestamp': datetime.utcnow().isoformat(),
            'total_domains': len(domains),
            'clusters': [],
            'patterns': {}
        }
        
        # Group by parent domain
        parent_domains = defaultdict(list)
        for domain in domains:
            parts = domain.split('.')
            if len(parts) >= 2:
                parent = '.'.join(parts[-2:])
                parent_domains[parent].append(domain)
        
        for parent, children in parent_domains.items():
            if len(children) > 1:
                cluster = {
                    'type': 'parent_domain',
                    'parent': parent,
                    'subdomains': children,
                    'count': len(children),
                    'confidence': min(100, len(children) * 15)
                }
                result['clusters'].append(cluster)
                
                # Detect subdomain spray patterns
                prefixes = ['.'.join(c.split('.')[:-2]) for c in children]
                numeric_prefixes = [p for p in prefixes if any(char.isdigit() for char in p)]
                if len(numeric_prefixes) > 3:
                    result['patterns']['subdomain_spray'] = {
                        'detected': True,
                        'pattern': 'numeric_sequential',
                        'examples': numeric_prefixes[:5],
                        'risk_level': 'high'
                    }
        
        return result
    
    def correlate_ssl_certificates(self, cert_data: List[Dict]) -> Dict:
        """Find relationships via SSL certificate attributes"""
        result = {
            'timestamp': datetime.utcnow().isoformat(),
            'certificates_analyzed': len(cert_data),
            'shared_issuers': [],
            'shared_subjects': [],
            'san_overlaps': []
        }
        
        issuer_map = defaultdict(list)
        subject_map = defaultdict(list)
        
        for cert in cert_data:
            if isinstance(cert, dict):
                issuer = cert.get('issuer', {}).get('CN', cert.get('issuer_name', 'unknown'))
                subject = cert.get('subject', {}).get('CN', cert.get('common_name', 'unknown'))
                
                if issuer:
                    issuer_map[issuer].append(cert)
                if subject:
                    subject_map[subject].append(cert)
        
        # Find shared issuers
        for issuer, certs in issuer_map.items():
            if len(certs) > 1:
                result['shared_issuers'].append({
                    'issuer': issuer,
                    'certificate_count': len(certs),
                    'domains': [c.get('domain', 'unknown') for c in certs]
                })
        
        # Find shared subjects
        for subject, certs in subject_map.items():
            if len(certs) > 1:
                result['shared_subjects'].append({
                    'subject': subject,
                    'certificate_count': len(certs),
                    'domains': [c.get('domain', 'unknown') for c in certs]
                })
        
        return result
    
    def correlate_whois(self, whois_data: List[Dict]) -> Dict:
        """Find patterns in WHOIS data"""
        result = {
            'timestamp': datetime.utcnow().isoformat(),
            'records_analyzed': len(whois_data),
            'shared_registrars': [],
            'shared_emails': [],
            'shared_nameservers': [],
            'temporal_clusters': []
        }
        
        registrar_map = defaultdict(list)
        email_map = defaultdict(list)
        nameserver_map = defaultdict(list)
        creation_date_map = defaultdict(list)
        
        for record in whois_data:
            if isinstance(record, dict):
                domain = record.get('domain', 'unknown')
                
                if record.get('registrar'):
                    registrar_map[record['registrar']].append(domain)
                
                for email in record.get('emails', []):
                    email_map[email].append(domain)
                
                for ns in record.get('nameservers', []):
                    nameserver_map[ns].append(domain)
                
                creation = record.get('creation_date', 'unknown')
                if creation != 'N/A':
                    # Group by month
                    try:
                        date_str = str(creation)[:7]  # YYYY-MM
                        creation_date_map[date_str].append(domain)
                    except:
                        pass
        
        # Shared registrars
        for registrar, domains in registrar_map.items():
            if len(domains) > 1:
                result['shared_registrars'].append({
                    'registrar': registrar,
                    'domain_count': len(domains),
                    'domains': domains
                })
        
        # Shared emails
        for email, domains in email_map.items():
            if len(domains) > 1:
                result['shared_emails'].append({
                    'email': email,
                    'domain_count': len(domains),
                    'domains': domains,
                    'risk_indicator': 'high' if len(domains) > 3 else 'medium'
                })
        
        # Shared nameservers
        for ns, domains in nameserver_map.items():
            if len(domains) > 1:
                result['shared_nameservers'].append({
                    'nameserver': ns,
                    'domain_count': len(domains),
                    'domains': domains
                })
        
        # Temporal clusters (domains created around same time)
        for date, domains in creation_date_map.items():
            if len(domains) > 2:
                result['temporal_clusters'].append({
                    'period': date,
                    'domain_count': len(domains),
                    'domains': domains,
                    'risk_indicator': 'medium' if len(domains) > 5 else 'low'
                })
        
        return result
    
    def detect_vulnerability_chains(self, findings: List[Dict]) -> Dict:
        """Detect chains of related vulnerabilities"""
        result = {
            'timestamp': datetime.utcnow().isoformat(),
            'findings_analyzed': len(findings),
            'chains_detected': [],
            'attack_paths': []
        }
        
        # Group by host/domain
        host_findings = defaultdict(list)
        for finding in findings:
            if isinstance(finding, dict):
                host = finding.get('host', finding.get('domain', finding.get('ip', 'unknown')))
                host_findings[host].append(finding)
        
        # Detect chains
        for host, host_finds in host_findings.items():
            if len(host_finds) > 2:
                # Check for common attack chains
                severities = [f.get('severity', 'low') for f in host_finds]
                
                chain = {
                    'host': host,
                    'finding_count': len(host_finds),
                    'severities': severities,
                    'chain_type': 'multi-stage' if 'critical' in severities or 'high' in severities else 'sequential',
                    'findings': host_finds,
                    'risk_score': min(100, len(host_finds) * 15 + (20 if 'critical' in severities else 0))
                }
                result['chains_detected'].append(chain)
        
        return result
    
    def detect_attack_campaigns(self, entities: List[Dict], findings: List[Dict]) -> Dict:
        """Detect potential coordinated attack campaigns"""
        result = {
            'timestamp': datetime.utcnow().isoformat(),
            'indicators': [],
            'campaigns_detected': [],
            'confidence': 0
        }
        
        campaign_indicators = {
            'multiple_targets_same_technique': 0,
            'coordinated_timing': 0,
            'shared_infrastructure': 0,
            'similar_ttps': 0
        }
        
        # Analyze MITRE ATT&CK techniques
        technique_counts = defaultdict(list)
        for finding in findings:
            if isinstance(finding, dict):
                mitre = finding.get('mitre_mapping', [])
                for tech in mitre:
                    technique_counts[tech].append(finding)
        
        for technique, tech_findings in technique_counts.items():
            if len(tech_findings) > 2:
                campaign_indicators['multiple_targets_same_technique'] += 1
                result['indicators'].append({
                    'type': 'technique_reuse',
                    'technique': technique,
                    'occurrences': len(tech_findings),
                    'targets': list(set(f.get('target', 'unknown') for f in tech_findings))
                })
        
        # Calculate confidence
        total_indicators = sum(campaign_indicators.values())
        result['confidence'] = min(100, total_indicators * 25)
        
        if total_indicators > 2:
            result['campaigns_detected'].append({
                'campaign_id': f'CAMP-{datetime.now().strftime("%Y%m%d")}-001',
                'indicators': campaign_indicators,
                'confidence': result['confidence'],
                'recommendation': 'Escalate to threat intelligence team'
            })
        
        return result
    
    def export_stix21(self, entities: List[Dict], findings: List[Dict], case_name: str) -> Dict:
        """Export intelligence in STIX 2.1 format"""
        stix_bundle = {
            'type': 'bundle',
            'id': f'bundle--{datetime.now().strftime("%Y%m%d%H%M%S")}',
            'objects': []
        }
        
        # Add identity
        identity = {
            'type': 'identity',
            'id': f'identity--{datetime.now().strftime("%Y%m%d%H%M%S")}',
            'created': datetime.utcnow().isoformat() + 'Z',
            'modified': datetime.utcnow().isoformat() + 'Z',
            'name': 'Sentinel Core',
            'identity_class': 'system'
        }
        stix_bundle['objects'].append(identity)
        
        # Add indicators from findings
        for finding in findings:
            if isinstance(finding, dict):
                indicator = {
                    'type': 'indicator',
                    'id': f"indicator--{datetime.now().strftime('%Y%m%d%H%M%S%f')}",
                    'created': datetime.utcnow().isoformat() + 'Z',
                    'modified': datetime.utcnow().isoformat() + 'Z',
                    'name': finding.get('tool_name', 'Unknown Finding'),
                    'description': json.dumps(finding.get('result_data', {}))[:500],
                    'pattern': f"[file:hashes.MD5 = '{finding.get('input_data', 'unknown')}']",
                    'pattern_type': 'stix',
                    'valid_from': datetime.utcnow().isoformat() + 'Z',
                    'labels': [finding.get('tool_category', 'osint')]
                }
                stix_bundle['objects'].append(indicator)
        
        return stix_bundle
    
    def run_full_correlation(self, entities: List[Dict], findings: List[Dict]) -> Dict:
        """Run complete correlation analysis"""
        # Extract data types
        ips = [e.get('value') for e in entities if e.get('entity_type') == 'ip']
        domains = [e.get('value') for e in entities if e.get('entity_type') == 'domain']
        
        # Run correlations
        ip_correlation = self.correlate_ip_infrastructure(ips) if ips else {}
        domain_correlation = self.correlate_domains(domains) if domains else {}
        vuln_chains = self.detect_vulnerability_chains(findings)
        campaign_detection = self.detect_attack_campaigns(entities, findings)
        
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'ip_infrastructure': ip_correlation,
            'domain_clusters': domain_correlation,
            'vulnerability_chains': vuln_chains,
            'attack_campaigns': campaign_detection,
            'summary': {
                'ip_clusters': len(ip_correlation.get('clusters', [])),
                'domain_clusters': len(domain_correlation.get('clusters', [])),
                'vuln_chains': len(vuln_chains.get('chains_detected', [])),
                'campaigns_detected': len(campaign_detection.get('campaigns_detected', []))
            }
        }
