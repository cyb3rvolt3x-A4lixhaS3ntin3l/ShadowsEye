"""
VirusTotal Module - Malware and URL reputation analysis
Requires VirusTotal API key (free tier available)
"""

import requests
from datetime import datetime
import hashlib


def analyze_url(url, api_key):
    """
    Analyze a URL with VirusTotal
    Returns detection results from multiple engines
    """
    result = {
        'url': url,
        'timestamp': datetime.utcnow().isoformat(),
        'detections': {},
        'categories': [],
        'reputation': 0
    }
    
    if not api_key:
        result['error'] = 'VirusTotal API key required'
        return result
    
    try:
        # First, submit the URL for analysis
        scan_url = 'https://www.virustotal.com/api/v3/urls'
        
        # URL needs to be base64 encoded without padding
        import base64
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        
        headers = {
            'x-apikey': api_key,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = f'url={url}'
        
        # Submit URL
        response = requests.post(scan_url, headers=headers, data=data, timeout=30)
        
        if response.status_code in [200, 201]:
            scan_data = response.json()
            analysis_id = scan_data['data']['id']
            
            # Get analysis results
            analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
            analysis_response = requests.get(analysis_url, headers=headers, timeout=30)
            
            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                stats = analysis_data['data']['attributes']['stats']
                
                result['scan_id'] = analysis_id
                result['stats'] = {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'harmless': stats.get('harmless', 0),
                    'timeout': stats.get('timeout', 0)
                }
                
                # Calculate reputation score (0-100)
                total = sum(result['stats'].values())
                if total > 0:
                    result['reputation'] = max(0, 100 - int((result['stats']['malicious'] + result['stats']['suspicious']) / total * 100))
                
                result['risk_level'] = 'critical' if result['stats']['malicious'] > 5 else (
                    'high' if result['stats']['malicious'] > 0 else (
                        'medium' if result['stats']['suspicious'] > 0 else 'low'
                    )
                )
                
        elif response.status_code == 404:
            # URL not found, might need to wait or never submitted
            result['status'] = 'not_analyzed'
        else:
            result['error'] = f'VirusTotal API error: {response.status_code}'
            
    except requests.exceptions.Timeout:
        result['error'] = 'Request timeout'
    except requests.exceptions.RequestException as e:
        result['error'] = f'Request failed: {str(e)}'
    except Exception as e:
        result['error'] = str(e)
    
    return result


def analyze_hash(file_hash, api_key):
    """
    Analyze a file hash (MD5, SHA1, SHA256) with VirusTotal
    """
    result = {
        'hash': file_hash,
        'timestamp': datetime.utcnow().isoformat(),
        'detections': {}
    }
    
    if not api_key:
        result['error'] = 'VirusTotal API key required'
        return result
    
    try:
        headers = {'x-apikey': api_key}
        
        # Determine hash type
        hash_length = len(file_hash)
        if hash_length == 32:
            hash_type = 'md5'
        elif hash_length == 40:
            hash_type = 'sha1'
        elif hash_length == 64:
            hash_type = 'sha256'
        else:
            result['error'] = 'Invalid hash format'
            return result
        
        # Get file report
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data['data']['attributes']
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            
            result['stats'] = {
                'malicious': last_analysis_stats.get('malicious', 0),
                'suspicious': last_analysis_stats.get('suspicious', 0),
                'undetected': last_analysis_stats.get('undetected', 0),
                'harmless': last_analysis_stats.get('harmless', 0)
            }
            
            result['first_seen'] = attributes.get('first_submission_date')
            result['last_seen'] = attributes.get('last_analysis_date')
            result['times_submitted'] = attributes.get('times_submitted', 0)
            
            # Get detection names
            detections = []
            for engine, details in attributes.get('last_analysis_results', {}).items():
                if details.get('category') in ['malicious', 'suspicious']:
                    detections.append({
                        'engine': engine,
                        'result': details.get('result'),
                        'category': details.get('category')
                    })
            
            result['detections'] = detections[:20]  # Limit to top 20
            
            # Risk assessment
            result['risk_level'] = 'critical' if result['stats']['malicious'] > 10 else (
                'high' if result['stats']['malicious'] > 0 else (
                    'medium' if result['stats']['suspicious'] > 0 else 'low'
                )
            )
            
        elif response.status_code == 404:
            result['status'] = 'not_analyzed'
        else:
            result['error'] = f'VirusTotal API error: {response.status_code}'
            
    except Exception as e:
        result['error'] = str(e)
    
    return result


def analyze_domain(domain, api_key):
    """Analyze a domain with VirusTotal"""
    result = {
        'domain': domain,
        'timestamp': datetime.utcnow().isoformat()
    }
    
    if not api_key:
        result['error'] = 'VirusTotal API key required'
        return result
    
    try:
        headers = {'x-apikey': api_key}
        url = f'https://www.virustotal.com/api/v3/domains/{domain}'
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data['data']['attributes']
            
            result['registrar'] = attributes.get('registrar')
            result['whois'] = attributes.get('whois')
            result['creation_date'] = attributes.get('creation_date')
            
            stats = attributes.get('last_analysis_stats', {})
            result['stats'] = {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0)
            }
            
            # Categories
            result['categories'] = attributes.get('categories', [])
            
            # Reputation
            result['reputation'] = attributes.get('reputation', 0)
            
            # Resolutions (IP history)
            resolutions = attributes.get('resolutions', [])[:10]
            result['ip_resolutions'] = [
                {'ip': r.get('ip_address'), 'date': r.get('date')} 
                for r in resolutions
            ]
            
        else:
            result['error'] = f'VirusTotal API error: {response.status_code}'
            
    except Exception as e:
        result['error'] = str(e)
    
    return result
