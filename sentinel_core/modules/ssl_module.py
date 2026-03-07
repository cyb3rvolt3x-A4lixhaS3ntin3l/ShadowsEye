#!/usr/bin/env python3
"""
SSL Certificate Analysis Module
Extracts certificate details, validity, issuer, and subject information
"""

import ssl
import socket
import json
from datetime import datetime
from urllib.parse import urlparse

def analyze_ssl(target):
    """
    Analyze SSL/TLS certificate for a domain
    Returns certificate details, validity period, issuer, and security info
    """
    try:
        # Parse URL if provided
        if target.startswith('http'):
            parsed = urlparse(target)
            hostname = parsed.netloc.split(':')[0]
            port = 443
        else:
            hostname = target
            port = 443
        
        # Create SSL context
        context = ssl.create_default_context()
        
        # Connect and get certificate
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                
                # Extract certificate information
                cert_info = {
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'version': cert.get('version'),
                    'serial_number': cert.get('serialNumber'),
                    'not_before': cert.get('notBefore'),
                    'not_after': cert.get('notAfter'),
                    'subject_alt_name': cert.get('subjectAltName', []),
                    'signature_algorithm': cert.get('signatureAlgorithm'),
                }
                
                # Calculate validity
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_remaining = (not_after - datetime.now()).days
                
                cert_info['validity'] = {
                    'not_before': not_before.isoformat(),
                    'not_after': not_after.isoformat(),
                    'days_remaining': days_remaining,
                    'is_valid': days_remaining > 0,
                    'is_expiring_soon': 0 < days_remaining <= 30
                }
                
                # Cipher information
                cert_info['cipher'] = {
                    'name': cipher[0],
                    'version': cipher[1],
                    'bits': cipher[2]
                }
                
                return {
                    'status': 'success',
                    'target': hostname,
                    'port': port,
                    'data': cert_info
                }
    
    except ssl.SSLCertVerificationError as e:
        return {
            'status': 'error',
            'target': target,
            'error': 'Certificate verification failed',
            'details': str(e)
        }
    except socket.timeout:
        return {'status': 'error', 'target': target, 'error': 'Connection timed out'}
    except socket.gaierror:
        return {'status': 'error', 'target': target, 'error': 'DNS resolution failed'}
    except Exception as e:
        return {'status': 'error', 'target': target, 'error': str(e)}

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        result = analyze_ssl(sys.argv[1])
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python ssl_module.py <domain or url>")
