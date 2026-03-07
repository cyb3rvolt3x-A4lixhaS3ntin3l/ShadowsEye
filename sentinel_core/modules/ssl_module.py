"""
SSL/TLS Certificate Analysis Module
Returns certificate details, validity, issuer, subject
"""

import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse


def analyze_ssl(target):
    """
    Analyze SSL/TLS certificate for a domain or URL
    Returns certificate details and security assessment
    """
    # Extract hostname from URL if provided
    if target.startswith('http'):
        parsed = urlparse(target)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    else:
        hostname = target
        port = 443
    
    result = {
        'target': target,
        'hostname': hostname,
        'port': port,
        'timestamp': datetime.utcnow().isoformat()
    }
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                
                # Certificate details
                result['certificate'] = {
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'version': cert.get('version'),
                    'serial_number': cert.get('serialNumber'),
                    'not_before': cert.get('notBefore'),
                    'not_after': cert.get('notAfter'),
                    'signature_algorithm': cert.get('signatureAlgorithm'),
                    'san': cert.get('subjectAltName', [])
                }
                
                # Cipher info
                result['cipher'] = {
                    'name': cipher[0],
                    'version': cipher[1],
                    'bits': cipher[2]
                }
                
                # Protocol version
                result['protocol'] = ssock.version()
                
                # Validity check
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                now = datetime.utcnow()
                
                result['validity'] = {
                    'is_valid': not_before <= now <= not_after,
                    'days_until_expiry': (not_after - now).days,
                    'expired': now > not_after,
                    'not_yet_valid': now < not_before
                }
                
                # Security assessment
                issues = []
                if result['validity']['days_until_expiry'] < 30:
                    issues.append('Certificate expires soon')
                if cipher[2] < 128:
                    issues.append('Weak cipher strength')
                if 'TLSv1.0' in str(ssock.version()) or 'TLSv1.1' in str(ssock.version()):
                    issues.append('Deprecated TLS version')
                if 'RC4' in cipher[0] or 'DES' in cipher[0] or 'MD5' in cipher[0]:
                    issues.append('Weak cipher algorithm')
                
                result['security_issues'] = issues
                result['risk_level'] = 'high' if len(issues) > 2 else ('medium' if issues else 'low')
                
    except ssl.SSLCertVerificationError as e:
        result['error'] = f'SSL verification failed: {str(e)}'
        result['risk_level'] = 'critical'
    except socket.timeout:
        result['error'] = 'Connection timeout'
        result['risk_level'] = 'unknown'
    except socket.gaierror:
        result['error'] = 'Hostname resolution failed'
        result['risk_level'] = 'unknown'
    except Exception as e:
        result['error'] = str(e)
        result['risk_level'] = 'unknown'
    
    return result
