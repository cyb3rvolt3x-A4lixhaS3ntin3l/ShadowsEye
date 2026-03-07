#!/usr/bin/env python3
"""
Kimi Moonshot AI Integration - Elite Hacker Assistant
Integrates Moonshot AI (Kimi K2.5) via NVIDIA NIM for intelligent analysis, 
report crafting, agentic automation, and tactical guidance.

Uses NVIDIA NIM API with streaming support and thinking capabilities.
"""

import os
import json
import time
import requests
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class KimiConfig:
    """Configuration for Kimi AI via NVIDIA NIM"""
    api_key: str = ""
    base_url: str = "https://integrate.api.nvidia.com/v1"
    model: str = "moonshotai/kimi-k2.5"
    max_tokens: int = 16384
    temperature: float = 1.0
    top_p: float = 1.0
    enable_thinking: bool = True
    stream: bool = False
    
    # Agentic capabilities
    enable_agentic: bool = False
    memory_enabled: bool = True
    auto_execute: bool = False  # Only execute if user confirms
    
    # Custom system prompt for agent behavior
    custom_system_prompt: str = ""
    
    @classmethod
    def from_env(cls) -> 'KimiConfig':
        return cls(
            api_key=os.environ.get('NVIDIA_API_KEY', os.environ.get('KIMI_API_KEY', '')),
            base_url=os.environ.get('NVIDIA_BASE_URL', 'https://integrate.api.nvidia.com/v1'),
            model=os.environ.get('KIMI_MODEL', 'moonshotai/kimi-k2.5'),
            enable_thinking=os.environ.get('KIMI_ENABLE_THINKING', 'true').lower() == 'true',
            enable_agentic=os.environ.get('KIMI_ENABLE_AGENTIC', 'false').lower() == 'true',
        )


class KimiAIAssistant:
    """
    Elite AI Assistant powered by Moonshot AI Kimi K2.5 via NVIDIA NIM
    Roles: Ethical Hacker, Incident Responder, OSINT Specialist, Report Engineer
    Features: Agentic capabilities, memory, streaming, thinking mode
    
    Supports custom roles and agentic automation with user confirmation.
    """
    
    # Pre-defined elite security roles
    SYSTEM_PROMPTS = {
        'hacker': """You are an elite ethical hacker and penetration testing expert operating under strict authorization.
Your role is to help security professionals understand vulnerabilities, attack vectors, and remediation strategies.

Provide clear, actionable insights on:
- Vulnerability analysis and exploitation techniques (for AUTHORIZED testing ONLY)
- Attack chain reconstruction and kill chain analysis
- Privilege escalation paths and lateral movement strategies
- Persistence mechanisms and detection evasion (for DEFENSIVE purposes)
- Tool selection and command crafting
- Proof-of-concept development guidance

ALWAYS emphasize:
1. Legal authorization requirements
2. Rules of engagement compliance
3. Ethical considerations
4. Responsible disclosure practices

Think like Kevin Mitnick: focus on the human element combined with technical precision.""",
        
        'incident_responder': """You are a senior incident responder and digital forensics expert.
Your expertise includes:
- Threat hunting and detection engineering
- Forensic acquisition and analysis (memory, disk, network)
- Malware triage and reverse engineering basics
- IOC extraction, enrichment, and sharing (STIX/TAXII)
- Timeline reconstruction and attribution
- Containment, eradication, and recovery strategies
- Post-incident lessons learned and hardening

Provide structured, methodical guidance following NIST SP 800-61 and SANS IR methodologies.
Prioritize evidence preservation and chain of custody.""",
        
        'osint_specialist': """You are an elite OSINT (Open Source Intelligence) specialist.
Your expertise encompasses:
- Digital footprint analysis and attack surface mapping
- Social media intelligence (SOCMINT) and HUMINT integration
- Domain, IP, and ASN reconnaissance
- Email, phone, and username enumeration
- Dark web monitoring and breach data analysis
- Geolocation and chronolocation
- Image/video metadata analysis (EXIF, ELA)
- Link analysis and relationship mapping
- Corporate intelligence and due diligence

Use advanced search operators, alternative data sources, and creative collection techniques.
Always verify sources and assess reliability.""",
        
        'report_engineer': """You are a professional security report engineer and technical writer.
Your specialization includes:
- Executive summaries tailored for C-level/board audiences
- Technical findings with accurate CVSS v3.1/v4.0 scoring
- Evidence documentation maintaining chain of custody
- Risk-prioritized remediation recommendations
- MITRE ATT&CK, D3FEND, and CAPEC mapping
- Compliance reporting (PCI-DSS, HIPAA, GDPR, ISO 27001, SOC 2)
- Visual report elements (graphs, charts, heat maps)
- Developer-friendly fix guidance with code examples

Create clear, professional, actionable reports that drive remediation.
Balance technical accuracy with business context.""",

        # Additional specialized roles
        'red_teamer': """You are an elite red team operator specializing in adversarial simulation.
Focus on:
- Objective-based operations (crown jewels)
- Covert persistence and stealth techniques
- Physical security bypass
- Social engineering campaigns
- Custom tooling and OPSEC
- Purple team collaboration for detection improvement

Emulate real-world threat actors using MITRE ATT&CK frameworks.""",
        
        'threat_hunter': """You are a proactive threat hunter with deep knowledge of adversary TTPs.
Your approach:
- Hypothesis-driven hunting
- Behavioral analytics over signatures
- Baseline establishment and anomaly detection
- Hunting across endpoints, network, and cloud
- Telemetry gap identification
- Detection rule creation (Sigma, YARA, Snort)

Think like the adversary to find what automated tools miss.""",
        
        'cloud_security': """You are a cloud security architect specializing in AWS, Azure, and GCP.
Expertise:
- Cloud misconfiguration assessment
- IAM privilege analysis and escalation paths
- Container and serverless security
- Cloud-native threat detection
- Compliance in cloud environments (CSA STAR, Cloud Control Matrix)
- Infrastructure as Code security (Terraform, CloudFormation)

Understand shared responsibility model and cloud-specific attack vectors.""",
        
        'appsec': """You are an application security expert and secure code reviewer.
Specializations:
- OWASP Top 10 and CWE/SANS Top 25
- SAST, DAST, IAST, and SCA tooling
- Secure SDLC implementation
- Threat modeling (STRIDE, PASTA, LINDDUN)
- API security (OWASP API Top 10)
- DevSecOps pipeline integration
- Code review for common vulnerability patterns

Provide developer-friendly remediation with code examples.""",
        
        'custom': ""  # Will be populated from settings
    }
    
    def __init__(self, config: Optional[KimiConfig] = None):
        self.config = config or KimiConfig.from_env()
        self.session = requests.Session()
        self._update_headers()
        
        # Conversation memory per role and session
        self.conversation_history: Dict[str, List[Dict]] = {}
        
        # Long-term memory for agentic operations
        self.long_term_memory: List[Dict] = []
        
        # Execution callbacks for agentic actions
        self.execution_callback: Optional[Callable] = None
        
        # Context cache for efficiency
        self.context_cache: Dict[str, Any] = {}
    
    def _update_headers(self):
        """Update request headers with current API key"""
        self.session.headers.update({
            'Authorization': f'Bearer {self.config.api_key}',
            'Accept': 'text/event-stream' if self.config.stream else 'application/json',
            'Content-Type': 'application/json'
        })
    
    def configure(self, api_key: str = None, model: str = None, 
                  enable_agentic: bool = None, custom_prompt: str = None,
                  **kwargs):
        """Dynamically configure the assistant from UI settings"""
        if api_key:
            self.config.api_key = api_key
            self._update_headers()
        if model:
            self.config.model = model
        if enable_agentic is not None:
            self.config.enable_agentic = enable_agentic
        if custom_prompt:
            self.config.custom_system_prompt = custom_prompt
            self.SYSTEM_PROMPTS['custom'] = custom_prompt
        
        # Apply any additional kwargs
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
    
    def is_configured(self) -> bool:
        """Check if API key is configured"""
        return bool(self.config.api_key)
    
    def _build_messages(self, role: str, user_query: str, context: Optional[Dict] = None,
                        scan_results: Optional[Dict] = None) -> List[Dict]:
        """Build message payload for NVIDIA NIM API"""
        # Get system prompt for role (support custom roles)
        system_prompt = self.SYSTEM_PROMPTS.get(role, self.SYSTEM_PROMPTS.get('custom', self.SYSTEM_PROMPTS['hacker']))
        
        # Use custom prompt if configured
        if self.config.custom_system_prompt and role == 'custom':
            system_prompt = self.config.custom_system_prompt
        
        messages = [
            {"role": "system", "content": system_prompt}
        ]
        
        # Add scan results context if provided (auto-get context when user clicks)
        if scan_results:
            scan_context = json.dumps(scan_results, indent=2)[:32000]  # Limit context size
            messages.append({
                "role": "system",
                "content": f"CURRENT SCAN RESULTS AND TARGET CONTEXT:\n{scan_context}\n\nUse this context to provide relevant, actionable analysis."
            })
        
        # Add additional context if provided
        if context:
            context_str = json.dumps(context, indent=2)[:16000]
            messages.append({
                "role": "system",
                "content": f"Additional Context:\n{context_str}"
            })
        
        # Add conversation history/memory if enabled
        if self.config.memory_enabled:
            conversation_id = f"{role}_conversation"
            if conversation_id in self.conversation_history:
                # Include last 15 messages for context continuity
                messages.extend(self.conversation_history[conversation_id][-15:])
        
        # Add long-term memory snippets if relevant
        if self.config.memory_enabled and self.long_term_memory:
            # Add most recent relevant memories
            recent_memories = self.long_term_memory[-5:]
            if recent_memories:
                memory_str = "\n".join([f"- {m['content']}" for m in recent_memories])
                messages.append({
                    "role": "system",
                    "content": f"Relevant memories from previous sessions:\n{memory_str}"
                })
        
        # Add user query
        messages.append({"role": "user", "content": user_query})
        
        return messages
    
    def query(self, role: str, query: str, context: Optional[Dict] = None,
              scan_results: Optional[Dict] = None,
              save_conversation: bool = True,
              stream_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """
        Query Kimi AI via NVIDIA NIM API with specific role and context
        
        Args:
            role: AI role ('hacker', 'incident_responder', 'osint_specialist', 'report_engineer', 'custom')
            query: User's question or request
            context: Optional context data (findings, notes, etc.)
            scan_results: Scan results to provide automatic context
            save_conversation: Whether to save this exchange to memory
            stream_callback: Optional callback for streaming responses
        
        Returns:
            Dict with response, metadata, and optional suggestions
        """
        if not self.is_configured():
            return {
                'success': False,
                'error': 'Kimi AI not configured. Please add your NVIDIA API token in Settings.',
                'response': None,
                'fallback': True,
                'suggestions': self._generate_local_suggestions(role, query, context)
            }
        
        try:
            messages = self._build_messages(role, query, context, scan_results)
            
            # Build payload according to NVIDIA NIM API specification
            payload = {
                "model": self.config.model,
                "messages": messages,
                "max_tokens": self.config.max_tokens,
                "temperature": self.config.temperature,
                "top_p": self.config.top_p,
                "stream": self.config.stream and stream_callback is not None,
                "chat_template_kwargs": {
                    "thinking": self.config.enable_thinking
                }
            }
            
            # Make request to NVIDIA NIM API
            invoke_url = f"{self.config.base_url.rstrip('/')}/chat/completions"
            
            if self.config.stream and stream_callback:
                # Streaming mode
                full_response = []
                response = requests.post(
                    invoke_url,
                    headers=self.session.headers,
                    json=payload,
                    stream=True,
                    timeout=120
                )
                response.raise_for_status()
                
                for line in response.iter_lines():
                    if line:
                        line_str = line.decode("utf-8")
                        if line_str.startswith("data: "):
                            data = line_str[6:]
                            if data.strip() == "[DONE]":
                                break
                            try:
                                chunk = json.loads(data)
                                content = chunk.get('choices', [{}])[0].get('delta', {}).get('content', '')
                                if content:
                                    full_response.append(content)
                                    stream_callback(content)
                            except json.JSONDecodeError:
                                continue
                
                ai_response = "".join(full_response)
            else:
                # Non-streaming mode
                response = requests.post(
                    invoke_url,
                    headers=self.session.headers,
                    json=payload,
                    timeout=120
                )
                response.raise_for_status()
                
                result = response.json()
                ai_response = result.get('choices', [{}])[0].get('message', {}).get('content', '')
            
            # Extract thinking process if available
            thinking_process = None
            if isinstance(ai_response, dict) and 'thinking' in ai_response:
                thinking_process = ai_response.get('thinking')
                ai_response = ai_response.get('response', ai_response)
            
            # Save conversation if requested
            if save_conversation and self.config.memory_enabled:
                self._save_to_memory(role, query, ai_response, context)
            
            # Parse for agentic actions if enabled
            agentic_actions = []
            if self.config.enable_agentic:
                agentic_actions = self._parse_agentic_actions(ai_response)
            
            return {
                'success': True,
                'response': ai_response,
                'thinking': thinking_process,
                'model': self.config.model,
                'role': role,
                'agentic_actions': agentic_actions,
                'timestamp': datetime.now().isoformat()
            }
            
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'error': 'API request timed out. The AI is taking longer than expected. Try again.',
                'response': None,
                'fallback': True,
                'suggestions': self._generate_local_suggestions(role, query, context)
            }
        except requests.exceptions.RequestException as e:
            status_code = getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None
            error_msg = f'API request failed'
            if status_code == 401:
                error_msg = 'Invalid API key. Please check your NVIDIA API token in Settings.'
            elif status_code == 429:
                error_msg = 'Rate limit exceeded. Please wait a moment and try again.'
            elif status_code:
                error_msg = f'API error (HTTP {status_code}): {str(e)}'
            else:
                error_msg = f'Network error: {str(e)}'
            
            return {
                'success': False,
                'error': error_msg,
                'response': None,
                'fallback': True,
                'suggestions': self._generate_local_suggestions(role, query, context)
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Unexpected error: {str(e)}',
                'response': None,
                'fallback': True,
                'suggestions': self._generate_local_suggestions(role, query, context)
            }
    
    def _save_to_memory(self, role: str, query: str, response: str, context: Optional[Dict] = None):
        """Save conversation to memory"""
        conversation_id = f"{role}_conversation"
        if conversation_id not in self.conversation_history:
            self.conversation_history[conversation_id] = []
        
        # Limit conversation history to last 20 exchanges
        if len(self.conversation_history[conversation_id]) >= 40:
            self.conversation_history[conversation_id] = self.conversation_history[conversation_id][-30:]
        
        self.conversation_history[conversation_id].append({"role": "user", "content": query})
        self.conversation_history[conversation_id].append({"role": "assistant", "content": response})
        
        # Save to long-term memory (key insights only)
        if len(response) > 100:  # Only save substantial responses
            self.long_term_memory.append({
                'role': role,
                'query': query[:200],
                'response_summary': response[:500],
                'context_keys': list(context.keys()) if context else [],
                'timestamp': datetime.now().isoformat()
            })
            
            # Limit long-term memory
            if len(self.long_term_memory) > 50:
                self.long_term_memory = self.long_term_memory[-40:]
    
    def _parse_agentic_actions(self, response: str) -> List[Dict]:
        """Parse response for potential agentic actions (tool execution, scans, etc.)"""
        actions = []
        
        # Look for code blocks that might be commands
        import re
        code_blocks = re.findall(r'```(?:bash|shell|cmd)?\n(.*?)```', response, re.DOTALL)
        
        for block in code_blocks:
            block = block.strip()
            # Identify potential tool commands
            if any(tool in block.lower() for tool in ['nmap', 'masscan', 'gobuster', 'nikto', 'sqlmap', ' nuclei']):
                actions.append({
                    'type': 'command',
                    'command': block,
                    'requires_confirmation': True,
                    'description': 'Security tool execution detected'
                })
        
        # Look for explicit action markers
        action_markers = re.findall(r'\[ACTION:(.*?)\]', response)
        for marker in action_markers:
            try:
                action_data = json.loads(marker.strip())
                action_data['requires_confirmation'] = True
                actions.append(action_data)
            except json.JSONDecodeError:
                continue
        
        return actions
    
    def execute_agentic_action(self, action: Dict, confirmed: bool = False) -> Dict[str, Any]:
        """Execute an agentic action if confirmed by user"""
        if not self.config.auto_execute and not confirmed:
            return {
                'success': False,
                'requires_confirmation': True,
                'action': action,
                'message': 'User confirmation required before execution'
            }
        
        if action.get('type') == 'command' and self.execution_callback:
            try:
                result = self.execution_callback(action.get('command'))
                return {
                    'success': True,
                    'result': result,
                    'action': action
                }
            except Exception as e:
                return {
                    'success': False,
                    'error': str(e),
                    'action': action
                }
        
        return {
            'success': False,
            'error': 'Unknown action type or no executor configured',
            'action': action
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
