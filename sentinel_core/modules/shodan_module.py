#!/usr/bin/env python3
"""
Shodan Module - IoT and Service Discovery
Developed by Syed Abrar (Cyb3rvolt3x)
© SentinelReign.com
"""

import os
import json
import requests
from typing import Dict, List, Any


def run_shodan_search(target: str, api_key: str = None) -> Dict[str, Any]:
    """
    Search Shodan for devices, services, and vulnerabilities
    
    Args:
        target: IP, domain, or search query
        api_key: Shodan API key (or use SHODAN_API_KEY env var)
    
    Returns:
        Dictionary with search results
    """
    if not api_key:
        api_key = os.environ.get('SHODAN_API_KEY')
    
    if not api_key:
        return {
            'status': 'error',
            'message': 'Shodan API key required. Set SHODAN_API_KEY environment variable.',
            'results': [],
            'total': 0
        }
    
    try:
        # Try host lookup first (for IPs/domains)
        api_url = f"https://api.shodan.io/shodan/host/{target}"
        params = {'key': api_key}
        
        response = requests.get(api_url, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            # Parse host information
            results = []
            ports = data.get('ports', [])
            vulns = data.get('vulns', [])
            
            for port in ports:
                results.append({
                    'port': port,
                    'protocol': 'tcp',
                    'service': 'unknown'
                })
            
            return {
                'status': 'success',
                'ip': data.get('ip_str'),
                'organization': data.get('org'),
                'country': data.get('country_name'),
                'city': data.get('city'),
                'ports': ports,
                'vulnerabilities': vulns,
                'domains': data.get('domains', []),
                'hostnames': data.get('hostnames', []),
                'results': results,
                'total': len(results)
            }
        
        # If host lookup fails, try search query
        elif response.status_code == 404:
            search_url = "https://api.shodan.io/shodan/host/search"
            params = {'query': target, 'key': api_key}
            
            response = requests.get(search_url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                matches = data.get('matches', [])
                
                results = []
                for match in matches[:50]:  # Limit to 50 results
                    results.append({
                        'ip': match.get('ip_str'),
                        'port': match.get('port'),
                        'product': match.get('product'),
                        'version': match.get('version'),
                        'country': match.get('country_name')
                    })
                
                return {
                    'status': 'success',
                    'query': target,
                    'total': data.get('total', 0),
                    'results': results,
                    'facets': data.get('facets', {})
                }
        
        return {
            'status': 'error',
            'message': f'Shodan API error: {response.status_code}',
            'results': [],
            'total': 0
        }
    
    except requests.exceptions.RequestException as e:
        return {
            'status': 'error',
            'message': f'Request failed: {str(e)}',
            'results': [],
            'total': 0
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Unexpected error: {str(e)}',
            'results': [],
            'total': 0
        }


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        result = run_shodan_search(sys.argv[1])
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python shodan_module.py <target>")
