#!/usr/bin/env python3
"""
Kali/Parrot OS Tools Integration
Leverages pre-installed security tools for enhanced reconnaissance
"""

import subprocess
import json
import shutil
from typing import Dict, List, Any, Optional


class KaliToolsIntegration:
    """Integration with Kali/Parrot OS security tools"""
    
    def __init__(self):
        self.available_tools = self._detect_tools()
    
    def _detect_tools(self) -> Dict[str, bool]:
        """Detect which tools are available on the system"""
        tools = {
            'amass': False,
            'sublist3r': False,
            'assetfinder': False,
            'theharvester': False,
            'shuffledns': False,
            'httpx': False,
            'nuclei': False,
            'naabu': False,
            'dnsrecon': False,
            'dig': False,
            'whois': False,
            'curl': False,
            'jq': False
        }
        
        for tool in tools.keys():
            tools[tool] = shutil.which(tool) is not None
        
        return tools
    
    def get_available_tools(self) -> List[str]:
        """Get list of available tools"""
        return [tool for tool, available in self.available_tools.items() if available]
    
    def run_amass_enum(self, domain: str, timeout: int = 120) -> Dict[str, Any]:
        """
        Run OWASP Amass for subdomain enumeration
        Most comprehensive subdomain discovery tool
        """
        if not self.available_tools.get('amass'):
            return {'status': 'error', 'error': 'amass not installed'}
        
        try:
            result = subprocess.run(
                ['amass', 'enum', '-d', domain, '-timeout', str(timeout // 60)],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0:
                subdomains = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                return {
                    'status': 'success',
                    'tool': 'amass',
                    'subdomains': subdomains,
                    'count': len(subdomains)
                }
            else:
                return {'status': 'error', 'error': result.stderr}
        
        except subprocess.TimeoutExpired:
            return {'status': 'error', 'error': 'amass timed out'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def run_assetfinder(self, domain: str, timeout: int = 60) -> Dict[str, Any]:
        """
        Run assetfinder for fast subdomain discovery
        """
        if not self.available_tools.get('assetfinder'):
            return {'status': 'error', 'error': 'assetfinder not installed'}
        
        try:
            result = subprocess.run(
                ['assetfinder', '--subs-only', domain],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0:
                subdomains = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                return {
                    'status': 'success',
                    'tool': 'assetfinder',
                    'subdomains': subdomains,
                    'count': len(subdomains)
                }
            else:
                return {'status': 'error', 'error': result.stderr}
        
        except subprocess.TimeoutExpired:
            return {'status': 'error', 'error': 'assetfinder timed out'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def run_sublist3r(self, domain: str, threads: int = 5, timeout: int = 120) -> Dict[str, Any]:
        """
        Run Sublist3r for subdomain enumeration
        """
        if not self.available_tools.get('sublist3r'):
            return {'status': 'error', 'error': 'sublist3r not installed'}
        
        try:
            result = subprocess.run(
                ['sublist3r', '-d', domain, '-t', str(threads)],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0:
                # Parse output - subdomains appear after a line of dashes
                lines = result.stdout.strip().split('\n')
                subdomains = []
                in_list = False
                
                for line in lines:
                    if line.startswith('-' * 50):
                        in_list = True
                        continue
                    if in_list and line.strip():
                        subdomains.append(line.strip())
                
                return {
                    'status': 'success',
                    'tool': 'sublist3r',
                    'subdomains': subdomains,
                    'count': len(subdomains)
                }
            else:
                return {'status': 'error', 'error': result.stderr}
        
        except subprocess.TimeoutExpired:
            return {'status': 'error', 'error': 'sublist3r timed out'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def run_theharvester(self, domain: str, source: str = 'all', timeout: int = 180) -> Dict[str, Any]:
        """
        Run theHarvester for emails, subdomains, and hosts
        """
        if not self.available_tools.get('theharvester'):
            return {'status': 'error', 'error': 'theHarvester not installed'}
        
        try:
            result = subprocess.run(
                ['theHarvester', '-d', domain, '-b', source, '-f', 'output.json'],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0:
                # Try to read JSON output
                try:
                    with open('output.json', 'r') as f:
                        data = json.load(f)
                    return {
                        'status': 'success',
                        'tool': 'theHarvester',
                        'data': data
                    }
                except:
                    return {
                        'status': 'partial',
                        'tool': 'theHarvester',
                        'stdout': result.stdout[:2000]
                    }
            else:
                return {'status': 'error', 'error': result.stderr}
        
        except subprocess.TimeoutExpired:
            return {'status': 'error', 'error': 'theHarvester timed out'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def run_httpx(self, targets: List[str], timeout: int = 30) -> Dict[str, Any]:
        """
        Run httpx for HTTP probing (status codes, titles, tech detection)
        """
        if not self.available_tools.get('httpx'):
            return {'status': 'error', 'error': 'httpx not installed'}
        
        try:
            # Write targets to temp file
            input_file = '/tmp/httpx_targets.txt'
            with open(input_file, 'w') as f:
                for target in targets:
                    f.write(f"{target}\n")
            
            result = subprocess.run(
                ['httpx', '-l', input_file, '-json', '-timeout', str(timeout)],
                capture_output=True,
                text=True,
                timeout=timeout * len(targets)
            )
            
            if result.returncode == 0:
                results = []
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            results.append(json.loads(line))
                        except:
                            pass
                
                return {
                    'status': 'success',
                    'tool': 'httpx',
                    'results': results
                }
            else:
                return {'status': 'error', 'error': result.stderr}
        
        except subprocess.TimeoutExpired:
            return {'status': 'error', 'error': 'httpx timed out'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def run_nuclei_scan(self, targets: List[str], templates: str = None, 
                       timeout: int = 300) -> Dict[str, Any]:
        """
        Run Nuclei vulnerability scanner
        """
        if not self.available_tools.get('nuclei'):
            return {'status': 'error', 'error': 'nuclei not installed'}
        
        try:
            cmd = ['nuclei', '-json']
            
            if templates:
                cmd.extend(['-t', templates])
            else:
                # Use default templates
                cmd.extend(['-severity', 'critical,high,medium'])
            
            # Write targets to temp file
            input_file = '/tmp/nuclei_targets.txt'
            with open(input_file, 'w') as f:
                for target in targets:
                    f.write(f"{target}\n")
            
            cmd.extend(['-l', input_file])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0:
                findings = []
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            findings.append(json.loads(line))
                        except:
                            pass
                
                return {
                    'status': 'success',
                    'tool': 'nuclei',
                    'findings': findings,
                    'count': len(findings)
                }
            else:
                return {'status': 'error', 'error': result.stderr}
        
        except subprocess.TimeoutExpired:
            return {'status': 'error', 'error': 'nuclei timed out'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def run_naabu_scan(self, target: str, ports: str = None, 
                      timeout: int = 120) -> Dict[str, Any]:
        """
        Run Naabu port scanner (fast)
        """
        if not self.available_tools.get('naabu'):
            return {'status': 'error', 'error': 'naabu not installed'}
        
        try:
            cmd = ['naabu', '-host', target, '-json']
            
            if ports:
                cmd.extend(['-p', ports])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0:
                ports_found = []
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            ports_found.append(json.loads(line))
                        except:
                            pass
                
                return {
                    'status': 'success',
                    'tool': 'naabu',
                    'ports': ports_found
                }
            else:
                return {'status': 'error', 'error': result.stderr}
        
        except subprocess.TimeoutExpired:
            return {'status': 'error', 'error': 'naabu timed out'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def run_dnsrecon(self, domain: str, timeout: int = 120) -> Dict[str, Any]:
        """
        Run DNSRecon for comprehensive DNS enumeration
        """
        if not self.available_tools.get('dnsrecon'):
            return {'status': 'error', 'error': 'dnsrecon not installed'}
        
        try:
            result = subprocess.run(
                ['dnsrecon', '-d', domain, '-j'],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    return {
                        'status': 'success',
                        'tool': 'dnsrecon',
                        'data': data
                    }
                except:
                    return {
                        'status': 'partial',
                        'tool': 'dnsrecon',
                        'stdout': result.stdout[:2000]
                    }
            else:
                return {'status': 'error', 'error': result.stderr}
        
        except subprocess.TimeoutExpired:
            return {'status': 'error', 'error': 'dnsrecon timed out'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def comprehensive_recon(self, domain: str) -> Dict[str, Any]:
        """
        Run comprehensive reconnaissance using all available tools
        Returns aggregated results
        """
        results = {
            'domain': domain,
            'tools_used': [],
            'subdomains': set(),
            'emails': [],
            'vulnerabilities': [],
            'open_ports': [],
            'http_info': []
        }
        
        # Subdomain enumeration with multiple tools
        for tool_func in [self.run_amass_enum, self.run_assetfinder, self.run_sublist3r]:
            tool_name = tool_func.__name__.replace('run_', '').replace('_', '')
            result = tool_func(domain)
            
            if result.get('status') == 'success':
                results['tools_used'].append(tool_name)
                if 'subdomains' in result:
                    results['subdomains'].update(result['subdomains'])
        
        # Convert set to list for JSON serialization
        results['subdomains'] = list(results['subdomains'])
        
        return results


# Global instance
kali_tools = KaliToolsIntegration()


if __name__ == '__main__':
    import sys
    
    integration = KaliToolsIntegration()
    
    print("Available tools:", integration.get_available_tools())
    
    if len(sys.argv) > 1:
        domain = sys.argv[1]
        print(f"\nRunning comprehensive recon on {domain}...")
        results = integration.comprehensive_recon(domain)
        print(json.dumps(results, indent=2))
