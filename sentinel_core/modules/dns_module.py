#!/usr/bin/env python3
"""
DNS Enumeration Module - DNS records and subdomain discovery
Uses dig, nslookup, and public APIs for comprehensive DNS analysis
"""

import subprocess
import json
import dns.resolver
import dns.reversename

def run_dns_enumeration(target):
    """
    Perform comprehensive DNS enumeration
    Returns A, AAAA, MX, NS, TXT, SOA, CNAME records
    """
    results = {
        'target': target,
        'records': {},
        'subdomains': [],
        'reverse_dns': None
    }
    
    # Standard record types to query
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR']
    
    for rtype in record_types:
        try:
            records = query_dns(target, rtype)
            if records:
                results['records'][rtype] = records
        except Exception as e:
            results['records'][rtype] = {'error': str(e)}
    
    # Try reverse DNS for IP addresses
    a_records = results['records'].get('A', [])
    if isinstance(a_records, list) and len(a_records) > 0:
        ip = a_records[0] if isinstance(a_records[0], str) else a_records[0].to_text()
        try:
            rev_name = dns.reversename.from_address(ip)
            ptr_records = query_dns(str(rev_name), 'PTR')
            if ptr_records:
                results['reverse_dns'] = ptr_records
        except:
            pass
    
    # Subdomain enumeration using common wordlist
    results['subdomains'] = enumerate_subdomains(target)
    
    return {
        'status': 'success',
        'data': results
    }

def query_dns(target, record_type):
    """Query DNS for specific record type"""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        # Use public DNS servers
        resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
        
        answers = resolver.resolve(target, record_type)
        return [r.to_text() for r in answers]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
    except Exception as e:
        return [{'error': str(e)}]

def enumerate_subdomains(domain, limit=20):
    """Enumerate subdomains using common wordlist"""
    common_subdomains = [
        'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 
        'api', 'app', 'blog', 'shop', 'store', 'portal', 'web',
        'mobile', 'm', 'beta', 'alpha', 'prod', 'production',
        'server', 'ns1', 'ns2', 'dns1', 'dns2', 'cdn', 'static',
        'assets', 'img', 'images', 'files', 'docs', 'support',
        'help', 'status', 'monitor', 'analytics', 'dashboard'
    ]
    
    found = []
    for sub in common_subdomains[:limit]:
        fqdn = f"{sub}.{domain}"
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            resolver.nameservers = ['8.8.8.8']
            
            answers = resolver.resolve(fqdn, 'A')
            if answers:
                found.append({
                    'subdomain': fqdn,
                    'ip': [r.to_text() for r in answers]
                })
        except:
            continue
    
    return found

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        result = run_dns_enumeration(sys.argv[1])
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python dns_module.py <domain>")
