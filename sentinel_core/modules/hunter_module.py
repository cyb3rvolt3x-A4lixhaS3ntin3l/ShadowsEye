#!/usr/bin/env python3
"""
Hunter.io Module - Professional Email Discovery
Developed by Syed Abrar (Cyb3rvolt3x)
© SentinelReign.com
"""

import os
import json
import requests
from typing import Dict, List, Any


def run_hunter_search(target: str, api_key: str = None) -> Dict[str, Any]:
    """
    Search Hunter.io for email addresses associated with a domain
    
    Args:
        target: Domain name to search
        api_key: Hunter.io API key (or use HUNTER_API_KEY env var)
    
    Returns:
        Dictionary with discovered emails and sources
    """
    if not api_key:
        api_key = os.environ.get('HUNTER_API_KEY')
    
    if not api_key:
        return {
            'status': 'error',
            'message': 'Hunter.io API key required. Set HUNTER_API_KEY environment variable.',
            'emails': [],
            'sources': []
        }
    
    try:
        # Domain search endpoint
        url = "https://api.hunter.io/v2/domain-search"
        params = {
            'domain': target,
            'api_key': api_key,
            'limit': 100
        }
        
        response = requests.get(url, params=params, timeout=60)
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('data', {}).get('meta', {}).get('total', 0) == 0:
                return {
                    'status': 'success',
                    'message': 'No emails found',
                    'domain': target,
                    'emails': [],
                    'sources': [],
                    'total': 0
                }
            
            emails_data = data.get('data', {}).get('emails', [])
            
            emails = []
            sources = set()
            
            for email_info in emails_data:
                email = email_info.get('value')
                if email:
                    emails.append({
                        'email': email,
                        'first_name': email_info.get('first_name'),
                        'last_name': email_info.get('last_name'),
                        'full_name': email_info.get('full_name'),
                        'position': email_info.get('position'),
                        'department': email_info.get('department'),
                        'type': email_info.get('type'),
                        'confidence': email_info.get('score', 0),
                        'verification': email_info.get('verification', {}),
                        'sources_count': email_info.get('sources_count', 0)
                    })
                    
                    # Collect sources
                    for source in email_info.get('sources', []):
                        uri = source.get('uri')
                        if uri:
                            sources.add(uri)
            
            return {
                'status': 'success',
                'domain': target,
                'organization': data.get('data', {}).get('organization'),
                'country': data.get('data', {}).get('country'),
                'emails': emails,
                'sources': list(sources),
                'total': len(emails),
                'accept_all': data.get('data', {}).get('accept_all', False),
                'pattern': data.get('data', {}).get('pattern'),
                'disposable': data.get('data', {}).get('disposable', False),
                'webmail': data.get('data', {}).get('webmail', False)
            }
        
        elif response.status_code == 401:
            return {
                'status': 'error',
                'message': 'Invalid Hunter.io API key',
                'emails': [],
                'sources': []
            }
        
        elif response.status_code == 429:
            return {
                'status': 'error',
                'message': 'Rate limit exceeded',
                'emails': [],
                'sources': []
            }
        
        else:
            return {
                'status': 'error',
                'message': f'Hunter.io API error: {response.status_code}',
                'emails': [],
                'sources': []
            }
    
    except requests.exceptions.RequestException as e:
        return {
            'status': 'error',
            'message': f'Request failed: {str(e)}',
            'emails': [],
            'sources': []
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Unexpected error: {str(e)}',
            'emails': [],
            'sources': []
        }


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        result = run_hunter_search(sys.argv[1])
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python hunter_module.py <domain>")
