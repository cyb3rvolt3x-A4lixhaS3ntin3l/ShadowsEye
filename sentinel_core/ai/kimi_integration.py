#!/usr/bin/env python3
"""
Kimi Moonshot AI Integration - Elite Hacker Assistant
Integrates Moonshot AI (Kimi) for intelligent analysis, report crafting, and tactical guidance
"""

import os
import json
import requests
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class KimiConfig:
    """Configuration for Kimi AI"""
    api_key: str = ""
    base_url: str = "https://api.moonshot.cn/v1"
    model: str = "moonshot-v1-8k"
    max_tokens: int = 4096
    temperature: float = 0.7
    
    @classmethod
    def from_env(cls) -> 'KimiConfig':
        return cls(
            api_key=os.environ.get('KIMI_API_KEY', ''),
            base_url=os.environ.get('KIMI_BASE_URL', 'https://api.moonshot.cn/v1'),
            model=os.environ.get('KIMI_MODEL', 'moonshot-v1-8k')
        )


class KimiAIAssistant:
    """
    Elite AI Assistant powered by Moonshot AI (Kimi)
    Roles: Hacker, Incident Responder, OSINT Specialist, Report Engineer
    """
    
    SYSTEM_PROMPTS = {
        'hacker': """You are an elite ethical hacker and penetration testing expert. 
Your role is to help security professionals understand vulnerabilities, attack vectors, and remediation strategies.
Provide clear, actionable insights on:
- Vulnerability analysis and exploitation techniques (for authorized testing only)
- Attack chain reconstruction
- Privilege escalation paths
- Lateral movement strategies
- Persistence mechanisms
- Detection evasion techniques (for defensive purposes)
Always emphasize legal and ethical considerations.""",
        
        'incident_responder': """You are a senior incident responder with expertise in:
- Threat hunting and detection
- Forensic analysis
- Malware reverse engineering basics
- IOCs extraction and analysis
- Timeline reconstruction
- Containment and eradication strategies
- Lessons learned documentation
Provide structured, methodical guidance for incident handling.""",
        
        'osint_specialist': """You are an OSINT (Open Source Intelligence) specialist with expertise in:
- Digital footprint analysis
- Social media intelligence (SOCMINT)
- Domain and IP reconnaissance
- Email and phone number lookups
- Dark web monitoring
- Geolocation analysis
- Image metadata analysis
- Link analysis and relationship mapping
Provide comprehensive intelligence gathering strategies.""",
        
        'report_engineer': """You are a professional security report engineer specializing in:
- Executive summaries for C-level stakeholders
- Technical findings with CVSS scoring
- Evidence documentation and chain of custody
- Remediation recommendations prioritized by risk
- ATT&CK framework mapping
- Compliance reporting (PCI-DSS, HIPAA, GDPR, etc.)
- Visual report generation guidance
Create clear, professional, actionable reports."""
    }
    
    def __init__(self, config: Optional[KimiConfig] = None):
        self.config = config or KimiConfig.from_env()
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {self.config.api_key}',
            'Content-Type': 'application/json'
        })
        self.conversation_history: Dict[str, List[Dict]] = {}
    
    def is_configured(self) -> bool:
        """Check if API key is configured"""
        return bool(self.config.api_key)
    
    def _build_messages(self, role: str, user_query: str, context: Optional[Dict] = None) -> List[Dict]:
        """Build message payload for API"""
        system_prompt = self.SYSTEM_PROMPTS.get(role, self.SYSTEM_PROMPTS['hacker'])
        
        messages = [
            {"role": "system", "content": system_prompt}
        ]
        
        # Add context if provided
        if context:
            context_str = json.dumps(context, indent=2)
            messages.append({
                "role": "system",
                "content": f"Context from analysis:\n{context_str}"
            })
        
        # Add conversation history if exists
        conversation_id = f"{role}_conversation"
        if conversation_id in self.conversation_history:
            messages.extend(self.conversation_history[conversation_id][-10:])  # Last 10 messages
        
        # Add user query
        messages.append({"role": "user", "content": user_query})
        
        return messages
    
    def query(self, role: str, query: str, context: Optional[Dict] = None, 
              save_conversation: bool = True) -> Dict[str, Any]:
        """
        Query Kimi AI with specific role and context
        
        Args:
            role: One of 'hacker', 'incident_responder', 'osint_specialist', 'report_engineer'
            query: User's question or request
            context: Optional context data (scan results, findings, etc.)
            save_conversation: Whether to save this exchange
        
        Returns:
            Dict with response and metadata
        """
        if not self.is_configured():
            return {
                'success': False,
                'error': 'Kimi AI not configured. Please set KIMI_API_KEY in settings.',
                'response': None,
                'suggestions': self._generate_local_suggestions(role, query, context)
            }
        
        try:
            messages = self._build_messages(role, query, context)
            
            payload = {
                'model': self.config.model,
                'messages': messages,
                'max_tokens': self.config.max_tokens,
                'temperature': self.config.temperature
            }
            
            response = self.session.post(
                f'{self.config.base_url}/chat/completions',
                json=payload,
                timeout=60
            )
            response.raise_for_status()
            
            result = response.json()
            ai_response = result['choices'][0]['message']['content']
            
            # Save conversation if requested
            if save_conversation:
                conversation_id = f"{role}_conversation"
                if conversation_id not in self.conversation_history:
                    self.conversation_history[conversation_id] = []
                self.conversation_history[conversation_id].append({"role": "user", "content": query})
                self.conversation_history[conversation_id].append({"role": "assistant", "content": ai_response})
            
            return {
                'success': True,
                'response': ai_response,
                'model': self.config.model,
                'usage': result.get('usage', {}),
                'role': role
            }
            
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'API request failed: {str(e)}',
                'response': None,
                'suggestions': self._generate_local_suggestions(role, query, context)
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Unexpected error: {str(e)}',
                'response': None,
                'suggestions': self._generate_local_suggestions(role, query, context)
            }
    
    def _generate_local_suggestions(self, role: str, query: str, context: Optional[Dict]) -> str:
        """Generate basic suggestions without AI when API is unavailable"""
        suggestions = []
        
        if role == 'hacker':
            suggestions.append("🔍 Manual Analysis Steps:")
            suggestions.append("  1. Review scan results for high-severity findings")
            suggestions.append("  2. Check for common vulnerabilities (OWASP Top 10)")
            suggestions.append("  3. Verify findings manually before reporting")
            suggestions.append("  4. Document all steps for reproducibility")
        
        elif role == 'incident_responder':
            suggestions.append("🚨 Immediate Actions:")
            suggestions.append("  1. Isolate affected systems")
            suggestions.append("  2. Preserve evidence (memory dumps, logs)")
            suggestions.append("  3. Identify scope of compromise")
            suggestions.append("  4. Begin timeline reconstruction")
        
        elif role == 'osint_specialist':
            suggestions.append("📊 OSINT Gathering:")
            suggestions.append("  1. Expand subdomain enumeration")
            suggestions.append("  2. Check historical DNS records")
            suggestions.append("  3. Analyze SSL certificates")
            suggestions.append("  4. Search for leaked credentials")
        
        elif role == 'report_engineer':
            suggestions.append("📝 Report Structure:")
            suggestions.append("  1. Executive Summary (non-technical)")
            suggestions.append("  2. Methodology")
            suggestions.append("  3. Findings with CVSS scores")
            suggestions.append("  4. Remediation recommendations")
            suggestions.append("  5. Appendix with raw data")
        
        return "\n".join(suggestions)
    
    def analyze_finding(self, finding: Dict, role: str = 'hacker') -> Dict[str, Any]:
        """Analyze a specific security finding"""
        query = f"""Analyze this security finding and provide:
1. Severity assessment
2. Potential impact
3. Exploitation scenario (for authorized testing)
4. Remediation steps
5. References (CVE, CWE, etc.)

Finding: {json.dumps(finding, indent=2)}"""
        
        return self.query(role, query, context={'finding': finding})
    
    def craft_report_section(self, section_type: str, findings: List[Dict], 
                            target_info: Dict) -> Dict[str, Any]:
        """Craft a specific section of a security report"""
        section_prompts = {
            'executive_summary': "Write an executive summary for C-level stakeholders",
            'technical_findings': "Document technical findings with reproduction steps",
            'remediation': "Provide prioritized remediation recommendations",
            'methodology': "Describe the testing methodology used",
            'conclusion': "Write conclusions and next steps"
        }
        
        query = f"""{section_prompts.get(section_type, 'Document this section')}

Target Information: {json.dumps(target_info, indent=2)}
Findings: {json.dumps(findings, indent=2)}"""
        
        return self.query('report_engineer', query, context={
            'section_type': section_type,
            'target_info': target_info,
            'findings': findings
        })
    
    def suggest_next_steps(self, current_findings: List[Dict], 
                          target: str) -> Dict[str, Any]:
        """Suggest next investigation steps based on current findings"""
        query = f"""Based on these findings for target {target}, suggest:
1. Additional reconnaissance techniques
2. Specific tools to run
3. Potential attack vectors to explore
4. Related assets to investigate

Current Findings: {json.dumps(current_findings, indent=2)}"""
        
        return self.query('hacker', query, context={
            'target': target,
            'findings': current_findings
        })
    
    def explain_vulnerability(self, vuln_name: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        """Explain a vulnerability in detail"""
        query = f"""Explain the vulnerability '{vuln_name}' including:
1. What it is and how it works
2. How to detect it
3. How to exploit it (for authorized testing)
4. How to fix it
5. Real-world examples
6. References and resources"""
        
        return self.query('hacker', query, context=context)
    
    def generate_ioc_extraction(self, raw_data: str) -> Dict[str, Any]:
        """Extract IOCs from raw data"""
        query = f"""Extract all Indicators of Compromise (IOCs) from this data:
- IP addresses
- Domains
- URLs
- Email addresses
- File hashes (MD5, SHA1, SHA256)
- MITRE ATT&CK techniques

Raw Data: {raw_data[:5000]}"""  # Limit to prevent token overflow
        
        return self.query('incident_responder', query)
    
    def clear_conversation(self, role: Optional[str] = None):
        """Clear conversation history"""
        if role:
            conversation_id = f"{role}_conversation"
            if conversation_id in self.conversation_history:
                del self.conversation_history[conversation_id]
        else:
            self.conversation_history.clear()


# Global instance
kimi_assistant = KimiAIAssistant()


def get_kimi_assistant() -> KimiAIAssistant:
    """Get the global Kimi AI assistant instance"""
    return kimi_assistant
