#!/usr/bin/env python3
"""
Wayback Machine Module - Historical Website Archive Analysis
Developed by Syed Abrar (Cyb3rvolt3x)
© SentinelReign.com
"""

import json
import requests
from typing import Dict, List, Any
from datetime import datetime


def search_wayback_machine(target: str) -> Dict[str, Any]:
    """
    Search Wayback Machine for historical snapshots and subdomains
    
    Args:
        target: Domain name to search
    
    Returns:
        Dictionary with snapshots and discovered subdomains
    """
    if not target:
        return {
            'status': 'error',
            'message': 'Target domain required',
            'snapshots': [],
            'subdomains': []
        }
    
    try:
        # Get availability info from Wayback CDX API
        cdx_url = "https://web.archive.org/cdx/search/cdx"
        params = {
            'url': f'{target}/*',
            'output': 'json',
            'fl': 'original,timestamp,statuscode,mimetype',
            'collapse': 'digest',
            'filter': 'statuscode:200',
            'limit': 1000
        }
        
        response = requests.get(cdx_url, params=params, timeout=60)
        
        if response.status_code != 200:
            return {
                'status': 'error',
                'message': f'Wayback API error: {response.status_code}',
                'snapshots': [],
                'subdomains': []
            }
        
        data = response.json()
        
        if len(data) <= 1:  # Only headers, no results
            return {
                'status': 'success',
                'message': 'No snapshots found',
                'snapshots': [],
                'subdomains': [],
                'total_snapshots': 0
            }
        
        # Parse results (skip header row)
        snapshots = []
        subdomains = set()
        
        for row in data[1:]:
            if len(row) >= 4:
                url = row[0]
                timestamp = row[1]
                
                # Extract subdomain from URL
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    hostname = parsed.netloc or parsed.path.split('/')[0]
                    
                    # Remove port if present
                    hostname = hostname.split(':')[0]
                    
                    # Check if it's a subdomain
                    if hostname.endswith(target):
                        subdomains.add(hostname)
                except:
                    pass
                
                # Parse timestamp
                try:
                    dt = datetime.strptime(timestamp, '%Y%m%d%H%M%S')
                    formatted_date = dt.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    formatted_date = timestamp
                
                snapshots.append({
                    'url': url,
                    'timestamp': timestamp,
                    'date': formatted_date,
                    'archive_url': f'https://web.archive.org/web/{timestamp}/{url}'
                })
        
        # Sort snapshots by date
        snapshots.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Limit to 500 most recent snapshots
        snapshots = snapshots[:500]
        
        return {
            'status': 'success',
            'target': target,
            'snapshots': snapshots,
            'subdomains': list(subdomains),
            'total_snapshots': len(snapshots),
            'unique_subdomains': len(subdomains)
        }
    
    except requests.exceptions.RequestException as e:
        return {
            'status': 'error',
            'message': f'Request failed: {str(e)}',
            'snapshots': [],
            'subdomains': []
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Unexpected error: {str(e)}',
            'snapshots': [],
            'subdomains': []
        }


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        result = search_wayback_machine(sys.argv[1])
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python wayback_module.py <domain>")
