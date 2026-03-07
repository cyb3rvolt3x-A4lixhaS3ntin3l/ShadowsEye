"""
Certificate Transparency Module - Subdomain discovery via CT logs
Uses crt.sh API to find subdomains from certificate transparency logs
"""

import requests
from datetime import datetime


def query_crtsh(domain):
    """
    Query Certificate Transparency logs via crt.sh
    Returns all subdomains found in CT certificates
    """
    result = {
        'domain': domain,
        'timestamp': datetime.utcnow().isoformat(),
        'subdomains': [],
        'certificates': []
    }
    
    try:
        # Query crt.sh API
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=30, headers={'User-Agent': 'Sentinel-Core/1.0'})
        
        if response.status_code == 200:
            data = response.json()
            
            seen_subdomains = set()
            cert_ids = set()
            
            for entry in data:
                # Extract name_value which contains all SANs
                name_value = entry.get('name_value', '')
                
                # Split by newline to get individual domains
                for name in name_value.split('\n'):
                    name = name.strip().lower()
                    if name and '*' not in name and name.endswith(domain.lower()):
                        if name not in seen_subdomains:
                            seen_subdomains.add(name)
                            result['subdomains'].append({
                                'subdomain': name,
                                'source': 'certificate_transparency',
                                'discovered_at': datetime.utcnow().isoformat()
                            })
                
                # Track unique certificates
                cert_id = entry.get('id')
                if cert_id and cert_id not in cert_ids:
                    cert_ids.add(cert_id)
                    result['certificates'].append({
                        'cert_id': cert_id,
                        'issuer_name': entry.get('issuer_name', 'N/A'),
                        'not_before': entry.get('not_before', 'N/A'),
                        'not_after': entry.get('not_after', 'N/A'),
                        'common_name': entry.get('common_name', 'N/A')
                    })
            
            result['subdomains_count'] = len(seen_subdomains)
            result['certificates_count'] = len(cert_ids)
            
        else:
            result['error'] = f'API returned status code: {response.status_code}'
            
    except requests.exceptions.Timeout:
        result['error'] = 'Request timeout'
    except requests.exceptions.RequestException as e:
        result['error'] = f'Request failed: {str(e)}'
    except Exception as e:
        result['error'] = str(e)
    
    return result
