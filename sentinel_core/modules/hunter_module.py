"""
Hunter.io Module - Professional email discovery
Requires Hunter.io API key (free tier: 25 searches/month)
"""

import requests
from datetime import datetime


def domain_search(domain, api_key):
    """
    Search for emails associated with a domain using Hunter.io
    Returns professional email addresses found
    """
    result = {
        'domain': domain,
        'timestamp': datetime.utcnow().isoformat(),
        'emails': [],
        'total': 0,
        'organization': None
    }
    
    if not api_key:
        result['error'] = 'Hunter.io API key required'
        return result
    
    try:
        url = 'https://api.hunter.io/v2/domain-search'
        params = {
            'domain': domain,
            'api_key': api_key,
            'limit': 50
        }
        
        response = requests.get(url, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('data'):
                result['total'] = data['data'].get('total', 0)
                result['organization'] = data['data'].get('organization')
                result['website_url'] = data['data'].get('website_url')
                result['accept_all'] = data['data'].get('accept_all')
                result['pattern'] = data['data'].get('pattern')
                
                for email_data in data['data'].get('emails', []):
                    result['emails'].append({
                        'email': email_data.get('value'),
                        'first_name': email_data.get('first_name'),
                        'last_name': email_data.get('last_name'),
                        'position': email_data.get('position'),
                        'department': email_data.get('department'),
                        'type': email_data.get('type'),
                        'verification': {
                            'date': email_data.get('verification', {}).get('date'),
                            'status': email_data.get('verification', {}).get('status')
                        },
                        'sources': [
                            {'uri': s.get('uri'), 'extracted_on': s.get('extracted_on')}
                            for s in email_data.get('sources', [])[:3]
                        ]
                    })
                    
        elif response.status_code == 401:
            result['error'] = 'Invalid Hunter.io API key'
        elif response.status_code == 429:
            result['error'] = 'API rate limit exceeded'
        else:
            result['error'] = f'Hunter.io API error: {response.status_code}'
            
    except requests.exceptions.Timeout:
        result['error'] = 'Request timeout'
    except requests.exceptions.RequestException as e:
        result['error'] = f'Request failed: {str(e)}'
    except Exception as e:
        result['error'] = str(e)
    
    return result


def email_finder(first_name, last_name, domain, api_key):
    """
    Find a specific person's email address
    """
    result = {
        'first_name': first_name,
        'last_name': last_name,
        'domain': domain,
        'timestamp': datetime.utcnow().isoformat()
    }
    
    if not api_key:
        result['error'] = 'Hunter.io API key required'
        return result
    
    try:
        url = 'https://api.hunter.io/v2/email-finder'
        params = {
            'first_name': first_name,
            'last_name': last_name,
            'domain': domain,
            'api_key': api_key
        }
        
        response = requests.get(url, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('data'):
                email_data = data['data']
                result['email'] = email_data.get('email')
                result['score'] = email_data.get('score')
                result['position'] = email_data.get('position')
                result['department'] = email_data.get('department')
                result['type'] = email_data.get('type')
                result['verification'] = email_data.get('verification')
                result['sources'] = email_data.get('sources', [])
            else:
                result['found'] = False
                result['message'] = 'Email not found'
                
        elif response.status_code == 404:
            result['found'] = False
            result['message'] = 'Email not found'
        else:
            result['error'] = f'Hunter.io API error: {response.status_code}'
            
    except Exception as e:
        result['error'] = str(e)
    
    return result


def email_verify(email, api_key):
    """
    Verify if an email address is valid
    """
    result = {
        'email': email,
        'timestamp': datetime.utcnow().isoformat()
    }
    
    if not api_key:
        result['error'] = 'Hunter.io API key required'
        return result
    
    try:
        url = 'https://api.hunter.io/v2/email-verifier'
        params = {
            'email': email,
            'api_key': api_key
        }
        
        response = requests.get(url, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('data'):
                verify_data = data['data']
                result['status'] = verify_data.get('status')  # valid, invalid, catch-all, unknown
                result['result'] = verify_data.get('result')  # deliverable, undeliverable, risky, unknown
                result['score'] = verify_data.get('score')
                result['regexp'] = verify_data.get('regexp')  # Format check
                result['gibberish'] = verify_data.get('gibberish')
                result['disposable'] = verify_data.get('disposable')
                result['webmail'] = verify_data.get('webmail')
                result['mx_records'] = verify_data.get('mx_records')
                result['smtp_server'] = verify_data.get('smtp_server')
                result['smtp_check'] = verify_data.get('smtp_check')
                result['accept_all'] = verify_data.get('accept_all')
                result['block'] = verify_data.get('block')
                result['sources'] = verify_data.get('sources', [])
                
                # Risk assessment
                if result['status'] == 'valid' and result['result'] == 'deliverable':
                    result['risk_level'] = 'low'
                elif result['status'] == 'catch-all':
                    result['risk_level'] = 'medium'
                else:
                    result['risk_level'] = 'high'
            else:
                result['error'] = 'Verification failed'
        else:
            result['error'] = f'Hunter.io API error: {response.status_code}'
            
    except Exception as e:
        result['error'] = str(e)
    
    return result
