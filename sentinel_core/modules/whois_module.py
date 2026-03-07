#!/usr/bin/env python3
"""
WHOIS Module - Domain registration information lookup
Uses built-in whois library or subprocess for free WHOIS data
"""

import subprocess
import json
import re
from datetime import datetime

def run_whois(target):
    """
    Perform WHOIS lookup on a domain
    Returns registration details, nameservers, and important dates
    """
    try:
        # Try using whois command (available on most Linux systems)
        result = subprocess.run(['whois', target], capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            return {'error': 'WHOIS lookup failed', 'details': result.stderr}
        
        # Parse common WHOIS fields
        whois_data = parse_whois(result.stdout)
        
        return {
            'status': 'success',
            'target': target,
            'data': whois_data,
            'raw': result.stdout[:5000]  # Limit raw output
        }
    
    except subprocess.TimeoutExpired:
        return {'error': 'WHOIS lookup timed out'}
    except FileNotFoundError:
        return {'error': 'whois command not found. Install with: apt-get install whois'}
    except Exception as e:
        return {'error': str(e)}

def parse_whois(raw_data):
    """Parse raw WHOIS output into structured data"""
    parsed = {}
    
    # Common patterns to extract
    patterns = {
        'domain_name': r'Domain Name:\s*(.+)',
        'registrar': r'Registrar:\s*(.+)',
        'creation_date': r'Creation Date:\s*(.+)',
        'expiration_date': r'Registry Expiry Date:\s*(.+)',
        'updated_date': r'Updated Date:\s*(.+)',
        'name_servers': r'Name Server:\s*(.+)',
        'registrant_org': r'Registrant Organization:\s*(.+)',
        'registrant_country': r'Registrant Country:\s*(.+)',
        'admin_email': r'Admin Email:\s*(.+)',
        'tech_email': r'Tech Email:\s*(.+)',
        'status': r'Status:\s*(.+)',
        'dnssec': r'DNSSEC:\s*(.+)'
    }
    
    for key, pattern in patterns.items():
        matches = re.findall(pattern, raw_data, re.IGNORECASE)
        if matches:
            if key == 'name_servers' or key == 'status':
                parsed[key] = list(set(matches))  # Remove duplicates
            else:
                parsed[key] = matches[0].strip()
    
    return parsed

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        result = run_whois(sys.argv[1])
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python whois_module.py <domain>")
