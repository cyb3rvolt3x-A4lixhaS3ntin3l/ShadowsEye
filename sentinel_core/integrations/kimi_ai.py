"""
Kimi Moonshot AI Integration via NVIDIA NIM API
Model: moonshotai/kimi-k2.5
Elite Roles: 12+ cybersecurity expert personas
Agentic Capabilities: Command detection, confirmation, autonomous execution
"""

import requests
import json
from datetime import datetime
from typing import Optional, List, Dict, Any


# Elite AI Roles for Cybersecurity
ELITE_ROLES = {
    'ethical_hacker': {
        'name': 'Ethical Hacker',
        'system_prompt': '''You are an elite Ethical Hacker and penetration testing expert. 
Your expertise includes web application security, network penetration testing, privilege escalation, and exploit development.
Provide actionable security assessments, identify vulnerabilities, and suggest remediation steps.
Always follow ethical guidelines and only analyze systems you have permission to test.'''
    },
    'incident_responder': {
        'name': 'Incident Responder',
        'system_prompt': '''You are an expert Incident Responder specializing in digital forensics and incident response (DFIR).
Your expertise includes malware analysis, threat hunting, log analysis, and containment strategies.
Help analyze security incidents, identify attack vectors, and provide step-by-step response procedures.'''
    },
    'osint_specialist': {
        'name': 'OSINT Specialist',
        'system_prompt': '''You are an elite OSINT (Open Source Intelligence) analyst.
Your expertise includes social media intelligence, domain/IP reconnaissance, person profiling, and data correlation.
Help gather and analyze publicly available information for investigations while respecting privacy and legal boundaries.'''
    },
    'red_teamer': {
        'name': 'Red Team Operator',
        'system_prompt': '''You are a Red Team operator with expertise in advanced persistent threat (APT) simulation.
Your skills include social engineering, physical security bypass, lateral movement, and command & control operations.
Provide realistic attack scenarios and help organizations improve their defensive posture.'''
    },
    'threat_hunter': {
        'name': 'Threat Hunter',
        'system_prompt': '''You are a Threat Hunting specialist focused on proactive threat detection.
Your expertise includes behavioral analysis, anomaly detection, MITRE ATT&CK mapping, and IOC development.
Help identify hidden threats and develop hunting hypotheses based on intelligence data.'''
    },
    'cloud_security_expert': {
        'name': 'Cloud Security Expert',
        'system_prompt': '''You are a Cloud Security architect specializing in AWS, Azure, and GCP security.
Your expertise includes IAM, network security, container security, serverless security, and compliance.
Provide cloud security assessments and remediation guidance.'''
    },
    'appsec_expert': {
        'name': 'Application Security Expert',
        'system_prompt': '''You are an Application Security expert specializing in secure SDLC and code review.
Your expertise includes OWASP Top 10, SAST/DAST, threat modeling, and security architecture.
Help identify application vulnerabilities and implement secure coding practices.'''
    },
    'ib_officer': {
        'name': 'Intelligence Bureau Officer',
        'system_prompt': '''You are an Intelligence Bureau officer with expertise in counter-intelligence and national security.
Your skills include signal intelligence, human intelligence, and strategic analysis.
Provide intelligence assessments and threat analysis from a national security perspective.'''
    },
    'mossad_operator': {
        'name': 'Mossad Operator',
        'system_prompt': '''You are a former Mossad operator with expertise in covert operations and strategic intelligence.
Your skills include surveillance, counter-surveillance, risk assessment, and operational security.
Provide strategic insights and operational security guidance.'''
    },
    'raw_analyst': {
        'name': 'RAW Analyst',
        'system_prompt': '''You are a Research and Analysis Wing (RAW) intelligence analyst.
Your expertise includes geopolitical analysis, regional threat assessment, and strategic intelligence.
Provide comprehensive intelligence analysis with focus on South Asian security dynamics.'''
    },
    'malware_analyst': {
        'name': 'Malware Analyst',
        'system_prompt': '''You are a Malware Analysis expert specializing in reverse engineering.
Your expertise includes static/dynamic analysis, unpacking, C2 identification, and YARA rule creation.
Help analyze malicious samples and understand their behavior and capabilities.'''
    },
    'soc_analyst': {
        'name': 'SOC Analyst',
        'system_prompt': '''You are a Security Operations Center (SOC) analyst with expertise in SIEM operations.
Your skills include log correlation, alert triage, playbook development, and incident escalation.
Help analyze security alerts and develop effective monitoring strategies.'''
    },
    'custom': {
        'name': 'Custom Role',
        'system_prompt': 'You are a helpful cybersecurity assistant.'
    }
}


class KimiAIIntegration:
    """Kimi Moonshot AI integration via NVIDIA NIM API"""
    
    def __init__(self, api_key: str, model: str = 'moonshotai/kimi-k2.5'):
        self.api_key = api_key
        self.model = model
        self.base_url = 'https://integrate.api.nvidia.com/v1'
        self.conversation_history = []
        self.token_usage = {'daily_budget': 100000, 'used_today': 0, 'last_reset': datetime.now()}
        
    def _check_token_budget(self) -> bool:
        """Check if we're within daily token budget"""
        now = datetime.now()
        if (now - self.token_usage['last_reset']).days > 0:
            self.token_usage['used_today'] = 0
            self.token_usage['last_reset'] = now
        return self.token_usage['used_today'] < self.token_usage['daily_budget']
    
    def chat(self, 
             prompt: str, 
             role: str = 'ethical_hacker',
             system_prompt: Optional[str] = None,
             context_data: Optional[Dict] = None,
             max_tokens: int = 2048,
             temperature: float = 0.7) -> Dict[str, Any]:
        """
        Send a chat request to Kimi AI via NVIDIA NIM
        
        Args:
            prompt: User's question/prompt
            role: AI role to use (from ELITE_ROLES)
            system_prompt: Custom system prompt (overrides role default)
            context_data: Additional context to inject (case data, scan results, etc.)
            max_tokens: Maximum tokens in response
            temperature: Response creativity (0.0-1.0)
            
        Returns:
            Dictionary with response, tokens_used, and metadata
        """
        result = {
            'success': False,
            'response': None,
            'tokens_used': 0,
            'role': role,
            'timestamp': datetime.utcnow().isoformat(),
            'error': None
        }
        
        if not self.api_key:
            result['error'] = 'API key not configured'
            return result
        
        if not self._check_token_budget():
            result['error'] = 'Daily token budget exceeded'
            return result
        
        # Get system prompt for role
        role_config = ELITE_ROLES.get(role, ELITE_ROLES['custom'])
        sys_prompt = system_prompt or role_config['system_prompt']
        
        # Build messages with context injection
        messages = []
        
        # System message
        if context_data:
            context_str = json.dumps(context_data, indent=2)[:3000]  # Limit context size
            sys_prompt += f"\n\nContext Data:\n{context_str}"
        
        messages.append({
            'role': 'system',
            'content': sys_prompt
        })
        
        # Add conversation history (last 10 messages)
        messages.extend(self.conversation_history[-10:])
        
        # User message
        messages.append({'role': 'user', 'content': prompt})
        
        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            payload = {
                'model': self.model,
                'messages': messages,
                'max_tokens': max_tokens,
                'temperature': temperature,
                'top_p': 0.9,
                'stream': False
            }
            
            response = requests.post(
                f'{self.base_url}/chat/completions',
                headers=headers,
                json=payload,
                timeout=60
            )
            
            if response.status_code == 200:
                data = response.json()
                
                ai_response = data['choices'][0]['message']['content']
                tokens_used = data['usage']['total_tokens']
                
                result['success'] = True
                result['response'] = ai_response
                result['tokens_used'] = tokens_used
                result['finish_reason'] = data['choices'][0].get('finish_reason')
                
                # Update token usage
                self.token_usage['used_today'] += tokens_used
                
                # Store in conversation history
                self.conversation_history.append({'role': 'user', 'content': prompt})
                self.conversation_history.append({'role': 'assistant', 'content': ai_response})
                
                # Limit history size
                if len(self.conversation_history) > 20:
                    self.conversation_history = self.conversation_history[-20:]
                    
            elif response.status_code == 401:
                result['error'] = 'Invalid API key'
            elif response.status_code == 429:
                result['error'] = 'Rate limit exceeded'
            else:
                result['error'] = f'API error: {response.status_code} - {response.text}'
                
        except requests.exceptions.Timeout:
            result['error'] = 'Request timeout'
        except requests.exceptions.RequestException as e:
            result['error'] = f'Request failed: {str(e)}'
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def analyze_scan_results(self, scan_results: List[Dict], role: str = 'ethical_hacker') -> str:
        """Analyze scan results and provide security assessment"""
        prompt = f"""Analyze these cybersecurity scan results and provide:
1. Executive Summary
2. Key Findings
3. Risk Assessment (Critical/High/Medium/Low)
4. MITRE ATT&CK Mapping (if applicable)
5. Recommended Actions

Scan Results:
{json.dumps(scan_results, indent=2)[:4000]}"""
        
        result = self.chat(prompt, role=role)
        return result.get('response', result.get('error', 'Analysis failed'))
    
    def generate_report(self, case_data: Dict, findings: List[Dict], role: str = 'ethical_hacker') -> str:
        """Generate professional security report"""
        prompt = f"""Generate a professional cybersecurity assessment report including:

EXECUTIVE SUMMARY
- Brief overview of assessment scope and key findings

ASSESSMENT SCOPE
- Target systems/domains
- Methodology used
- Timeline

FINDINGS
- Detailed findings with evidence
- Risk ratings for each finding
- Technical details

MITRE ATT&CK MAPPING
- Map findings to relevant techniques

RECOMMENDATIONS
- Prioritized remediation steps
- Short-term and long-term actions

CONCLUSION

Case Data: {json.dumps(case_data, indent=2)[:2000]}
Findings: {json.dumps(findings, indent=2)[:3000]}"""
        
        result = self.chat(prompt, role=role, max_tokens=4096)
        return result.get('response', result.get('error', 'Report generation failed'))
    
    def suggest_next_steps(self, current_findings: List[Dict], role: str = 'threat_hunter') -> List[str]:
        """Suggest next investigation steps based on current findings"""
        prompt = f"""Based on these findings, suggest 5-10 specific next steps for investigation:

Current Findings:
{json.dumps(current_findings, indent=2)[:3000]}

Provide actionable next steps with specific tools or techniques to use."""
        
        result = self.chat(prompt, role=role)
        if result['success']:
            # Parse numbered list
            suggestions = [line.strip() for line in result['response'].split('\n') 
                          if line.strip() and any(line.strip().startswith(str(i)) for i in range(1, 10))]
            return suggestions[:10]
        return []
    
    def detect_commands(self, text: str) -> List[Dict]:
        """Detect potential commands in AI response for agentic execution"""
        import re
        
        commands = []
        
        # Pattern for common security tool commands
        patterns = {
            'nmap': r'nmap\s+(-[^\s]+\s+)*([0-9.]+|[a-zA-Z0-9.-]+)',
            'dig': r'dig\s+(@[^\s]+\s+)?([a-zA-Z0-9.-]+)',
            'whois': r'whois\s+([a-zA-Z0-9.-]+)',
            'curl': r'curl\s+(-[^\s]+\s+)*["\']?([^"\'\s]+)["\']?',
            'wget': r'wget\s+(-[^\s]+\s+)*["\']?([^"\'\s]+)["\']?',
            'grep': r'grep\s+(-[^\s]+\s+)*["\']([^"\']+)["\']',
            'find': r'find\s+([^\s;]+)\s+(-[^\s]+\s+[^\s;]+)+',
        }
        
        for tool, pattern in patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                commands.append({
                    'tool': tool,
                    'match': match if isinstance(match, str) else match[-1],
                    'requires_confirmation': True
                })
        
        return commands
    
    def clear_history(self):
        """Clear conversation history"""
        self.conversation_history = []
    
    def get_usage_stats(self) -> Dict:
        """Get token usage statistics"""
        return {
            'daily_budget': self.token_usage['daily_budget'],
            'used_today': self.token_usage['used_today'],
            'remaining': self.token_usage['daily_budget'] - self.token_usage['used_today'],
            'last_reset': self.token_usage['last_reset'].isoformat(),
            'conversation_length': len(self.conversation_history)
        }


def get_available_roles() -> List[Dict]:
    """Get list of available AI roles"""
    return [{'id': k, 'name': v['name']} for k, v in ELITE_ROLES.items()]
