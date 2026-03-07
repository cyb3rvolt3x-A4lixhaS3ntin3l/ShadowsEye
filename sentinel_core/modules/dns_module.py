"""
DNS Enumeration Module - Real DNS queries using dnspython
Returns A, AAAA, MX, NS, TXT, CNAME, SOA records
"""

import dns.resolver
import dns.reversename
from datetime import datetime


def enumerate_dns(domain):
    """
    Perform comprehensive DNS enumeration on a domain
    Returns all DNS record types
    """
    results = {
        'domain': domain,
        'timestamp': datetime.utcnow().isoformat(),
        'records': {}
    }
    
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA']
    
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records = []
            
            for rdata in answers:
                if rtype == 'MX':
                    records.append({
                        'priority': rdata.preference,
                        'exchange': str(rdata.exchange).rstrip('.')
                    })
                elif rtype == 'SOA':
                    records.append({
                        'mname': str(rdata.mname).rstrip('.'),
                        'rname': str(rdata.rname).rstrip('.'),
                        'serial': rdata.serial,
                        'refresh': rdata.refresh,
                        'retry': rdata.retry,
                        'expire': rdata.expire,
                        'minimum': rdata.minimum
                    })
                else:
                    records.append(str(rdata))
            
            if records:
                results['records'][rtype] = records
                
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            results['error'] = 'Domain does not exist'
            break
        except dns.resolver.NoNameservers:
            results['error'] = 'No nameservers available'
            break
        except Exception as e:
            results['records'][rtype] = f'Error: {str(e)}'
    
    # Reverse DNS for A records
    if 'A' in results.get('records', {}):
        reverse_dns = []
        for ip in results['records']['A']:
            if isinstance(ip, str) and '.' in ip:
                try:
                    rev_name = dns.reversename.from_address(ip)
                    ptr = dns.resolver.resolve(rev_name, 'PTR')
                    reverse_dns.append({'ip': ip, 'ptr': str(ptr[0]).rstrip('.')})
                except:
                    pass
        if reverse_dns:
            results['reverse_dns'] = reverse_dns
    
    return results


def discover_subdomains(domain, limit=50):
    """
    Discover subdomains via DNS brute-forcing
    Uses common subdomain wordlist
    """
    common_subdomains = [
        'www', 'mail', 'ftp', 'admin', 'webmail', 'smtp', 'pop', 'imap',
        'ns1', 'ns2', 'dns1', 'dns2', 'blog', 'shop', 'store', 'api',
        'dev', 'staging', 'prod', 'test', 'demo', 'portal', 'app',
        'mobile', 'm', 'cdn', 'static', 'assets', 'images', 'img',
        'video', 'media', 'files', 'docs', 'support', 'help', 'faq',
        'forum', 'community', 'wiki', 'kb', 'status', 'monitor',
        'vpn', 'remote', 'gateway', 'proxy', 'cache', 'db', 'database',
        'sql', 'mysql', 'postgres', 'redis', 'elastic', 'kibana',
        'jenkins', 'git', 'gitlab', 'github', 'bitbucket', 'jira',
        'confluence', 'slack', 'teams', 'zoom', 'meet', 'chat',
        'crm', 'erp', 'hr', 'finance', 'sales', 'marketing',
        'cloud', 'aws', 'azure', 'gcp', 's3', 'storage', 'backup'
    ]
    
    found = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    
    for sub in common_subdomains[:limit]:
        fqdn = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(fqdn, 'A')
            ips = [str(rdata) for rdata in answers]
            found.append({
                'subdomain': fqdn,
                'ips': ips,
                'discovered_at': datetime.utcnow().isoformat()
            })
        except:
            continue
    
    return {
        'domain': domain,
        'subdomains_found': len(found),
        'subdomains': found,
        'timestamp': datetime.utcnow().isoformat()
    }
