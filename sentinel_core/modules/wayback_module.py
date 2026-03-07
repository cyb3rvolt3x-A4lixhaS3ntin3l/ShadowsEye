"""
Wayback Machine Module - Historical web archives
Returns historical snapshots and URLs
"""

import requests
from datetime import datetime
from urllib.parse import urlparse


def get_wayback_snapshots(url):
    """
    Get historical snapshots from Wayback Machine
    Returns available snapshots and capture dates
    """
    result = {
        'url': url,
        'timestamp': datetime.utcnow().isoformat(),
        'snapshots': [],
        'first_capture': None,
        'last_capture': None,
        'total_captures': 0
    }
    
    try:
        # Use Wayback CDX API
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        
        cdx_url = f'http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original,timestamp,statuscode'
        
        response = requests.get(cdx_url, timeout=30, headers={'User-Agent': 'Sentinel-Core/1.0'})
        
        if response.status_code == 200:
            data = response.json()
            
            # Skip header row
            if len(data) > 1:
                captures = {}
                
                for row in data[1:]:
                    if len(row) >= 3:
                        original_url = row[0]
                        timestamp = row[1]
                        status_code = row[2]
                        
                        # Group by date (YYYYMMDD)
                        date = timestamp[:8]
                        if date not in captures:
                            captures[date] = {
                                'date': date,
                                'year': date[:4],
                                'month': date[4:6],
                                'day': date[6:8],
                                'urls': [],
                                'count': 0
                            }
                        
                        if len(captures[date]['urls']) < 5:  # Limit URLs per day
                            captures[date]['urls'].append({
                                'url': original_url,
                                'timestamp': timestamp,
                                'status': status_code,
                                'archive_url': f'https://web.archive.org/web/{timestamp}/{original_url}'
                            })
                        
                        captures[date]['count'] += 1
                
                # Convert to list and sort
                snapshot_list = sorted(captures.values(), key=lambda x: x['date'])
                result['snapshots'] = snapshot_list
                result['total_captures'] = sum(s['count'] for s in snapshot_list)
                
                if snapshot_list:
                    result['first_capture'] = snapshot_list[0]['date']
                    result['last_capture'] = snapshot_list[-1]['date']
                    
                    # Calculate timespan
                    first = datetime.strptime(result['first_capture'], '%Y%m%d')
                    last = datetime.strptime(result['last_capture'], '%Y%m%d')
                    result['timespan_days'] = (last - first).days
                    
        else:
            result['error'] = f'Wayback API returned status code: {response.status_code}'
            
    except requests.exceptions.Timeout:
        result['error'] = 'Request timeout'
    except requests.exceptions.RequestException as e:
        result['error'] = f'Request failed: {str(e)}'
    except Exception as e:
        result['error'] = str(e)
    
    return result


def get_specific_snapshot(url, date=None):
    """
    Get a specific snapshot or closest available
    date format: YYYYMMDDHHMMSS
    """
    result = {
        'url': url,
        'requested_date': date,
        'timestamp': datetime.utcnow().isoformat()
    }
    
    try:
        # Use availability API
        avail_url = 'http://web.archive.org/cdx/search/cdx'
        params = {
            'url': url,
            'output': 'json',
            'limit': 1,
            'closest': date or 'now',
            'filter': 'statuscode:200'
        }
        
        response = requests.get(avail_url, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            if len(data) > 1:
                row = data[1]
                timestamp = row[1]
                
                result['found'] = True
                result['snapshot'] = {
                    'url': row[0],
                    'timestamp': timestamp,
                    'status': row[2],
                    'archive_url': f'https://web.archive.org/web/{timestamp}/{row[0]}'
                }
            else:
                result['found'] = False
                result['message'] = 'No snapshot found'
        else:
            result['error'] = f'API error: {response.status_code}'
            
    except Exception as e:
        result['error'] = str(e)
    
    return result
