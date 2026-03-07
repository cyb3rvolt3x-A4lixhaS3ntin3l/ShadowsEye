#!/usr/bin/env python3
"""
VirusTotal Module - Malware and URL Reputation Analysis
Developed by Syed Abrar (Cyb3rvolt3x)
© SentinelReign.com
"""

import os
import json
import requests
import hashlib
from typing import Dict, List, Any


def run_virustotal_scan(target: str, api_key: str = None) -> Dict[str, Any]:
    """
    Scan file hash, URL, domain, or IP on VirusTotal
    
    Args:
        target: File hash (MD5/SHA1/SHA256), URL, domain, or IP
        api_key: VirusTotal API key (or use VIRUSTOTAL_API_KEY env var)
    
    Returns:
        Dictionary with scan results
    """
    if not api_key:
        api_key = os.environ.get('VIRUSTOTAL_API_KEY')
    
    if not api_key:
        return {
            'status': 'error',
            'message': 'VirusTotal API key required. Set VIRUSTOTAL_API_KEY environment variable.',
            'detections': 0,
            'total_engines': 0,
            'report': {}
        }
    
    try:
        # Determine target type
        is_hash = len(target) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in target)
        is_url = target.startswith('http://') or target.startswith('https://')
        
        if is_hash:
            # File hash report
            url = "https://www.virustotal.com/api/v3/files/" + target
            headers = {'x-apikey': api_key}
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                last_analysis = attributes.get('last_analysis_stats', {})
                
                return {
                    'status': 'success',
                    'type': 'file_hash',
                    'hash': target,
                    'detections': last_analysis.get('malicious', 0),
                    'total_engines': sum(last_analysis.values()),
                    'report': {
                        'malicious': last_analysis.get('malicious', 0),
                        'suspicious': last_analysis.get('suspicious', 0),
                        'undetected': last_analysis.get('undetected', 0),
                        'harmless': last_analysis.get('harmless', 0),
                        'first_seen': attributes.get('first_submission_date'),
                        'last_seen': attributes.get('last_analysis_date'),
                        'tags': attributes.get('tags', []),
                        'names': attributes.get('names', [])
                    }
                }
            elif response.status_code == 404:
                return {
                    'status': 'not_found',
                    'message': 'Hash not found in VirusTotal database',
                    'detections': 0,
                    'total_engines': 0,
                    'report': {}
                }
        
        elif is_url:
            # URL analysis
            # First, submit URL for scanning
            url = "https://www.virustotal.com/api/v3/urls"
            headers = {'x-apikey': api_key}
            data = {'url': target}
            
            response = requests.post(url, headers=headers, data=data, timeout=30)
            
            if response.status_code in [200, 201]:
                url_id = response.json().get('data', {}).get('id')
                
                # Get analysis report
                if url_id:
                    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
                    response = requests.get(analysis_url, headers=headers, timeout=30)
                    
                    if response.status_code == 200:
                        analysis_data = response.json()
                        stats = analysis_data.get('data', {}).get('attributes', {}).get('stats', {})
                        
                        return {
                            'status': 'success',
                            'type': 'url',
                            'url': target,
                            'detections': stats.get('malicious', 0),
                            'total_engines': sum(stats.values()),
                            'report': stats
                        }
            
            # Alternative: get URL report directly
            url_report = "https://www.virustotal.com/api/v3/urls/" + target.replace('/', '%2F')
            response = requests.get(url_report, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                return {
                    'status': 'success',
                    'type': 'url',
                    'url': target,
                    'detections': stats.get('malicious', 0),
                    'total_engines': sum(stats.values()),
                    'report': stats
                }
        
        else:
            # Domain or IP analysis
            url = f"https://www.virustotal.com/api/v3/domains/{target}"
            headers = {'x-apikey': api_key}
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                last_analysis = attributes.get('last_analysis_stats', {})
                
                return {
                    'status': 'success',
                    'type': 'domain',
                    'domain': target,
                    'detections': last_analysis.get('malicious', 0),
                    'total_engines': sum(last_analysis.values()),
                    'report': {
                        'malicious': last_analysis.get('malicious', 0),
                        'suspicious': last_analysis.get('suspicious', 0),
                        'undetected': last_analysis.get('undetected', 0),
                        'harmless': last_analysis.get('harmless', 0),
                        'categories': attributes.get('categories', {}),
                        'registrar': attributes.get('registrar'),
                        'reputation': attributes.get('reputation', 0)
                    }
                }
        
        return {
            'status': 'error',
            'message': f'VirusTotal API error: {response.status_code}',
            'detections': 0,
            'total_engines': 0,
            'report': {}
        }
    
    except requests.exceptions.RequestException as e:
        return {
            'status': 'error',
            'message': f'Request failed: {str(e)}',
            'detections': 0,
            'total_engines': 0,
            'report': {}
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Unexpected error: {str(e)}',
            'detections': 0,
            'total_engines': 0,
            'report': {}
        }


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        result = run_virustotal_scan(sys.argv[1])
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python virustotal_module.py <hash|url|domain>")
