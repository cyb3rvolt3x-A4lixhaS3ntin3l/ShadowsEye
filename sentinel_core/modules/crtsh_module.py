#!/usr/bin/env python3
"""
Certificate Transparency Module - Subdomain discovery via CT logs
Uses public Certificate Transparency logs to find subdomains
"""

import requests
import json
import re
from urllib.parse import urlparse

def search_crtsh(target):
    """
    Search Certificate Transparency logs for subdomains
    Uses the public crt.sh API
    """
    try:
        # Clean target - extract domain
        if target.startswith('http'):
            parsed = urlparse(target)
            domain = parsed.netloc.split(':')[0]
        else:
            domain = target
        
        # Remove leading www. if present
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Query crt.sh API
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=30, headers={
            'User-Agent': 'Sentinel-Core-OSINT/1.0'
        })
        
        if response.status_code != 200:
            return {'status': 'error', 'target': domain, 'error': 'API request failed'}
        
        data = response.json()
        
        # Extract unique subdomains
        subdomains = set()
        for entry in data:
            name = entry.get('name_value', '')
            # Split by newlines (crt.sh returns multiple names)
            for line in name.split('\n'):
                line = line.strip()
                if line and '*' not in line:  # Skip wildcards
                    subdomains.add(line.lower())
        
        # Organize results
        results = {
            'domain': domain,
            'total_found': len(subdomains),
            'subdomains': sorted(list(subdomains)),
            'statistics': {
                'unique_count': len(subdomains),
                'with_wildcard': sum(1 for e in data if '*' in e.get('name_value', ''))
            }
        }
        
        return {
            'status': 'success',
            'target': domain,
            'data': results
        }
    
    except requests.Timeout:
        return {'status': 'error', 'target': target, 'error': 'Request timed out'}
    except Exception as e:
        return {'status': 'error', 'target': target, 'error': str(e)}

def get_cert_details(cert_id):
    """Get detailed certificate information by ID"""
    try:
        url = f"https://crt.sh/?id={cert_id}&output=json"
        response = requests.get(url, timeout=15)
        
        if response.status_code == 200:
            return {'status': 'success', 'data': response.json()}
        return {'status': 'error', 'error': 'Certificate not found'}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        result = search_crtsh(sys.argv[1])
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python crtsh_module.py <domain>")
