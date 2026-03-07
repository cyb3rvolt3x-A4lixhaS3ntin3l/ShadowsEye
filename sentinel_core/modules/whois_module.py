"""
WHOIS Lookup Module - Real WHOIS queries using python-whois
Returns domain registration information
"""

import whois
from datetime import datetime


def lookup_whois(domain):
    """
    Perform WHOIS lookup on a domain
    Returns registration details, nameservers, dates
    """
    try:
        w = whois.whois(domain)
        
        result = {
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'registrar': w.registrar or 'N/A',
            'organization': w.org or w.name or 'N/A',
            'registrant_country': w.country or 'N/A',
            'creation_date': str(w.creation_date) if w.creation_date else 'N/A',
            'expiration_date': str(w.expiration_date) if w.expiration_date else 'N/A',
            'updated_date': str(w.updated_date) if w.updated_date else 'N/A',
            'nameservers': w.name_servers if w.name_servers else [],
            'status': w.status if w.status else [],
            'emails': w.emails if w.emails else [],
            'dnssec': w.dnssec if hasattr(w, 'dnssec') else 'N/A'
        }
        
        # Calculate domain age
        if w.creation_date:
            try:
                creation = w.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                age_days = (datetime.utcnow() - creation).days
                result['age_days'] = age_days
                result['age_category'] = 'new' if age_days < 90 else ('recent' if age_days < 365 else 'established')
            except:
                pass
        
        return result
        
    except Exception as e:
        return {
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e),
            'available': True  # Domain might be available for registration
        }
