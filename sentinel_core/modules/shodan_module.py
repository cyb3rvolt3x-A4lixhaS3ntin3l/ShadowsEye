"""
Shodan Module - IoT device and service discovery
Requires Shodan API key (free tier available)
"""

import requests
from datetime import datetime


def search_shodan(query, api_key, pages=1):
    """
    Search Shodan for devices/services
    Returns host information, vulnerabilities, open ports
    """
    result = {
        'query': query,
        'timestamp': datetime.utcnow().isoformat(),
        'total_results': 0,
        'hosts': [],
        'vulns': {},
        'ports': {}
    }
    
    if not api_key:
        result['error'] = 'Shodan API key required'
        return result
    
    try:
        base_url = 'https://api.shodan.io/shodan/host/'
        
        # If query is an IP, get host info directly
        import re
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        
        if re.match(ip_pattern, query):
            url = f"{base_url}{query}"
            params = {'key': api_key}
            
            response = requests.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                result['host_info'] = {
                    'ip': data.get('ip_str'),
                    'city': data.get('city'),
                    'country': data.get('country_name'),
                    'org': data.get('org'),
                    'isp': data.get('isp'),
                    'os': data.get('os'),
                    'hostnames': data.get('hostnames', []),
                    'domains': data.get('domains', []),
                    'last_update': data.get('last_update')
                }
                
                # Extract ports and services
                ports = {}
                for banner in data.get('data', []):
                    port = banner.get('port')
                    service = banner.get('product', '') + ' ' + banner.get('version', '')
                    ports[port] = service.strip()
                
                result['ports'] = ports
                result['total_results'] = len(ports)
                
                # Vulnerabilities
                vulns = data.get('vuln_list', [])
                if vulns:
                    result['vulnerabilities'] = vulns
                
            else:
                result['error'] = f'Shodan API error: {response.status_code}'
        
        else:
            # Search query
            search_url = 'https://api.shodan.io/shodan/host/search'
            params = {
                'key': api_key,
                'query': query,
                'page': 1
            }
            
            for page in range(1, pages + 1):
                params['page'] = page
                response = requests.get(search_url, params=params, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if page == 1:
                        result['total_results'] = data.get('total', 0)
                    
                    for match in data.get('matches', []):
                        host_data = match.get('ip_str')
                        if host_data and host_data not in [h['ip'] for h in result['hosts']]:
                            result['hosts'].append({
                                'ip': host_data,
                                'port': match.get('port'),
                                'product': match.get('product'),
                                'version': match.get('version'),
                                'transport': match.get('transport'),
                                'timestamp': match.get('timestamp'),
                                'city': match.get('location', {}).get('city'),
                                'country': match.get('location', {}).get('country_name')
                            })
                else:
                    break
                    
    except requests.exceptions.Timeout:
        result['error'] = 'Request timeout'
    except requests.exceptions.RequestException as e:
        result['error'] = f'Request failed: {str(e)}'
    except Exception as e:
        result['error'] = str(e)
    
    return result


def shodan_host_lookup(ip, api_key):
    """Direct host lookup by IP"""
    return search_shodan(ip, api_key)
