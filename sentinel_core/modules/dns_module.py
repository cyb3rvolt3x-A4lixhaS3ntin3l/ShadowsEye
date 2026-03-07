#!/usr/bin/env python3
"""
DNS Enumeration Module - DNS records and subdomain discovery
Uses dig, nslookup, and public APIs for comprehensive DNS analysis
Integrates with Kali/Parrot OS tools: amass, assetfinder, sublist3r
"""

import subprocess
import json
import socket
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
    """Query DNS for specific record type with robust error handling"""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        # Use public DNS servers
        resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
        
        answers = resolver.resolve(target, record_type)
        results = []
        for r in answers:
            try:
                results.append(r.to_text())
            except Exception as e:
                # Skip records that can't be converted to text
                continue
        return results
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoNameservers:
        return []
    except dns.exception.Timeout:
        return []
    except Exception as e:
        # Return empty list instead of error dict to maintain consistent return type
        return []

def enumerate_subdomains(domain, limit=50, wordlist_file=None):
    """
    Enumerate subdomains using common wordlist or custom file
    Uses dnspython by default, can fall back to system tools
    """
    # Try to use Kali/Parrot OS tools first (amass, sublist3r, assetfinder)
    found = _enumerate_with_external_tools(domain)
    if found:
        return found
    
    # Fallback to built-in enumeration
    if wordlist_file:
        return _enumerate_from_file(domain, wordlist_file, limit)
    
    return _enumerate_builtin(domain, limit)


def _enumerate_with_external_tools(domain):
    """Try external tools available in Kali/Parrot OS"""
    import subprocess
    
    # Try amass (most comprehensive)
    try:
        result = subprocess.run(
            ['amass', 'enum', '-d', domain, '-timeout', '2'],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            subdomains = []
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if line and domain in line:
                    try:
                        ip = socket.gethostbyname(line)
                        subdomains.append({'subdomain': line, 'ip': [ip], 'source': 'amass'})
                    except:
                        pass
            if subdomains:
                return subdomains
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    
    # Try assetfinder (fast)
    try:
        result = subprocess.run(
            ['assetfinder', '--subs-only', domain],
            capture_output=True, text=True, timeout=20
        )
        if result.returncode == 0 and result.stdout.strip():
            subdomains = []
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if line and domain in line:
                    try:
                        ip = socket.gethostbyname(line)
                        subdomains.append({'subdomain': line, 'ip': [ip], 'source': 'assetfinder'})
                    except:
                        pass
            if subdomains:
                return subdomains
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    
    # Try sublist3r
    try:
        result = subprocess.run(
            ['sublist3r', '-d', domain, '-t', '5'],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0 and result.stdout.strip():
            subdomains = []
            in_list = False
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if line.startswith('-' * 50):
                    in_list = True
                    continue
                if in_list and line and domain in line:
                    try:
                        ip = socket.gethostbyname(line)
                        subdomains.append({'subdomain': line, 'ip': [ip], 'source': 'sublist3r'})
                    except:
                        pass
            if subdomains:
                return subdomains
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    
    return None


def _enumerate_from_file(domain, wordlist_file, limit):
    """Enumerate subdomains from a custom wordlist file"""
    found = []
    try:
        with open(wordlist_file, 'r') as f:
            words = [line.strip() for line in f if line.strip()][:limit]
        
        for sub in words:
            fqdn = f"{sub}.{domain}"
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 1
                resolver.lifetime = 1
                answers = resolver.resolve(fqdn, 'A')
                if answers:
                    found.append({
                        'subdomain': fqdn,
                        'ip': [r.to_text() for r in answers],
                        'source': 'wordlist'
                    })
            except:
                continue
    except FileNotFoundError:
        pass
    
    return found


def _enumerate_builtin(domain, limit=50):
    """Built-in subdomain enumeration with common wordlist"""
    common_subdomains = [
        'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging',
        'api', 'app', 'blog', 'shop', 'store', 'portal', 'web',
        'mobile', 'm', 'beta', 'alpha', 'prod', 'production',
        'server', 'ns1', 'ns2', 'dns1', 'dns2', 'cdn', 'static',
        'assets', 'img', 'images', 'files', 'docs', 'support',
        'help', 'status', 'monitor', 'analytics', 'dashboard',
        'git', 'vpn', 'remote', 'cloud', 'db', 'database',
        'jenkins', 'ci', 'cd', 'build', 'deploy', 'staging',
        'uat', 'qa', 'preprod', 'internal', 'intranet', 'extranet',
        'devops', 'ops', 'sec', 'security', 'admin2', 'backup'
    ]
    
    found = []
    for sub in common_subdomains[:limit]:
        fqdn = f"{sub}.{domain}"
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 1
            resolver.lifetime = 1
            answers = resolver.resolve(fqdn, 'A')
            if answers:
                found.append({
                    'subdomain': fqdn,
                    'ip': [r.to_text() for r in answers],
                    'source': 'builtin'
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
