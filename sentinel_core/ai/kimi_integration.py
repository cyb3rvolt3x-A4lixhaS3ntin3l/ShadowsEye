"""
Sentinel Core - Kimi Moonshot AI Integration
Uses NVIDIA NIM API with moonshotai/kimi-k2.5 model
Features:
- Persistent API key and memory storage
- Agentic capabilities with human-like reasoning
- Context-aware analysis across all modules
- Smart token management
- Multiple elite security roles (IB, Mossad, RAW, etc.)
- Auto-suggestions for next steps
- Professional report formatting
"""

import os
import json
import requests
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Generator

class KimiAgent:
    """Advanced Kimi AI Agent with persistent memory and agentic capabilities"""
    
    # Elite security roles - unlimited customization
    ELITE_ROLES = {
        "ethical_hacker": "You are an elite ethical hacker with expertise in penetration testing, vulnerability assessment, and exploit development. Think like Kevin Mitnick. Provide actionable insights, exploitation paths, and remediation strategies.",
        "incident_responder": "You are a senior incident responder specializing in threat hunting, forensics, and containment strategies. Analyze evidence, identify IOCs, and provide step-by-step incident response procedures.",
        "osint_specialist": "You are an OSINT specialist with advanced reconnaissance capabilities. Correlate open-source intelligence, identify digital footprints, and map target infrastructure.",
        "report_engineer": "You are a professional security report engineer. Transform technical findings into executive-ready reports with clear risk assessments, business impact, and prioritized recommendations.",
        "red_teamer": "You are a red team operator specializing in adversarial simulation, bypass techniques, and achieving objectives undetected. Think like advanced persistent threats.",
        "threat_hunter": "You are a threat hunter with expertise in detecting sophisticated adversaries. Identify anomalies, correlate events, and uncover hidden threats.",
        "cloud_security": "You are a cloud security architect specializing in AWS, Azure, GCP security. Identify misconfigurations, privilege escalation paths, and cloud-native threats.",
        "appsec_expert": "You are an application security expert specializing in web/mobile app vulnerabilities, secure code review, and DevSecOps practices.",
        "ib_officer": "You are an Intelligence Bureau officer with expertise in counter-intelligence, strategic analysis, and national security operations. Provide classified-level insights.",
        "mossad_operator": "You are a Mossad special operations officer with expertise in covert operations, target acquisition, and strategic intelligence. Think several steps ahead.",
        "raw_analyst": "You are a Research and Analysis Wing intelligence analyst specializing in strategic assessment, geopolitical analysis, and long-term threat forecasting.",
        "custom": "Custom role - defined by user prompt"
    }
    
    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Persistent configuration file
        self.config_file = self.data_dir / "kimi_config.json"
        self.memory_file = self.data_dir / "kimi_memory.json"
        self.token_log_file = self.data_dir / "kimi_token_log.json"
        
        # Load persistent configuration
        self.config = self._load_config()
        self.memory = self._load_memory()
        self.token_log = self._load_token_log()
        
        # API configuration
        self.api_url = "https://integrate.api.nvidia.com/v1/chat/completions"
        self.model = self.config.get("model", "moonshotai/kimi-k2.5")
        self.api_key = self.config.get("api_key", "")
        self.enabled = self.config.get("enabled", False)
        self.thinking_mode = self.config.get("thinking_mode", True)
        self.agentic_mode = self.config.get("agentic_mode", True)
        self.use_memory = self.config.get("use_memory", True)
        self.custom_role_prompt = self.config.get("custom_role_prompt", "")
        self.max_tokens = self.config.get("max_tokens", 16384)
        self.temperature = self.config.get("temperature", 0.7)
        
        # Token budget management
        self.daily_token_budget = self.config.get("daily_token_budget", 100000)
        self.tokens_used_today = self._get_today_token_usage()
        
    def _load_config(self) -> Dict:
        """Load persistent configuration"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}
    
    def _save_config(self):
        """Save configuration persistently"""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def _load_memory(self) -> Dict:
        """Load persistent memory (conversation history + long-term memory)"""
        if self.memory_file.exists():
            try:
                with open(self.memory_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {"conversations": [], "long_term": [], "context_cache": {}}
    
    def _save_memory(self):
        """Save memory persistently"""
        # Limit memory size to prevent bloat
        if len(self.memory["conversations"]) > 100:
            self.memory["conversations"] = self.memory["conversations"][-100:]
        if len(self.memory["long_term"]) > 50:
            self.memory["long_term"] = self.memory["long_term"][-50:]
            
        with open(self.memory_file, 'w') as f:
            json.dump(self.memory, f, indent=2)
    
    def _load_token_log(self) -> List[Dict]:
        """Load token usage log"""
        if self.token_log_file.exists():
            try:
                with open(self.token_log_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return []
    
    def _save_token_log(self):
        """Save token usage log"""
        # Keep only last 30 days
        cutoff = time.time() - (30 * 24 * 60 * 60)
        self.token_log = [entry for entry in self.token_log if entry.get("timestamp", 0) > cutoff]
        
        with open(self.token_log_file, 'w') as f:
            json.dump(self.token_log, f, indent=2)
    
    def _get_today_token_usage(self) -> int:
        """Calculate tokens used today"""
        today_start = time.mktime(datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timetuple())
        total = 0
        for entry in self.token_log:
            if entry.get("timestamp", 0) > today_start:
                total += entry.get("tokens_used", 0)
        return total
    
    def configure(self, api_key: str = None, model: str = None, enabled: bool = None,
                  thinking_mode: bool = None, agentic_mode: bool = None,
                  use_memory: bool = None, custom_role_prompt: str = None,
                  max_tokens: int = None, temperature: float = None,
                  daily_token_budget: int = None, role: str = None):
        """Update configuration persistently"""
        if api_key is not None:
            self.config["api_key"] = api_key
            self.api_key = api_key
        if model is not None:
            self.config["model"] = model
            self.model = model
        if enabled is not None:
            self.config["enabled"] = enabled
            self.enabled = enabled
        if thinking_mode is not None:
            self.config["thinking_mode"] = thinking_mode
            self.thinking_mode = thinking_mode
        if agentic_mode is not None:
            self.config["agentic_mode"] = agentic_mode
            self.agentic_mode = agentic_mode
        if use_memory is not None:
            self.config["use_memory"] = use_memory
            self.use_memory = use_memory
        if custom_role_prompt is not None:
            self.config["custom_role_prompt"] = custom_role_prompt
            self.custom_role_prompt = custom_role_prompt
        if max_tokens is not None:
            self.config["max_tokens"] = max_tokens
            self.max_tokens = max_tokens
        if temperature is not None:
            self.config["temperature"] = temperature
            self.temperature = temperature
        if daily_token_budget is not None:
            self.config["daily_token_budget"] = daily_token_budget
            self.daily_token_budget = daily_token_budget
        if role is not None:
            self.config["role"] = role
            
        self._save_config()
    
    def get_config(self) -> Dict:
        """Get current configuration"""
        return {
            "api_key_set": bool(self.api_key),
            "model": self.model,
            "enabled": self.enabled,
            "thinking_mode": self.thinking_mode,
            "agentic_mode": self.agentic_mode,
            "use_memory": self.use_memory,
            "custom_role_prompt": self.custom_role_prompt,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "daily_token_budget": self.daily_token_budget,
            "tokens_used_today": self.tokens_used_today,
            "role": self.config.get("role", "ethical_hacker"),
            "available_roles": list(self.ELITE_ROLES.keys())
        }
    
    def _check_token_budget(self, estimated_tokens: int = 1000) -> bool:
        """Check if within token budget"""
        if not self.api_key:
            return False
        return (self.tokens_used_today + estimated_tokens) <= self.daily_token_budget
    
    def _log_token_usage(self, tokens: int, endpoint: str = "chat"):
        """Log token usage"""
        self.token_log.append({
            "timestamp": time.time(),
            "tokens_used": tokens,
            "endpoint": endpoint,
            "date": datetime.now().isoformat()
        })
        self.tokens_used_today += tokens
        self._save_token_log()
    
    def _build_system_prompt(self, role: str = None, context: Dict = None) -> str:
        """Build system prompt based on role and context"""
        role_name = role or self.config.get("role", "ethical_hacker")
        
        if role_name == "custom" and self.custom_role_prompt:
            base_prompt = self.custom_role_prompt
        else:
            base_prompt = self.ELITE_ROLES.get(role_name, self.ELITE_ROLES["ethical_hacker"])
        
        # Add context-aware instructions
        system_prompt = f"""{base_prompt}

CORE PRINCIPLES:
1. Provide actionable, specific recommendations - no generic advice
2. Think multiple steps ahead like a master strategist
3. Consider both offensive and defensive perspectives
4. Prioritize findings by business impact and exploitability
5. Explain complex concepts clearly for all audience levels
6. Always suggest concrete next steps
7. Format responses professionally with clear structure

CONTEXT AWARENESS:
- You have access to scan results, notes, and historical data
- Correlate new findings with previous observations
- Remember long-term patterns and strategic objectives
- Adapt recommendations based on target profile

TOKEN EFFICIENCY:
- Be concise but comprehensive
- Use structured formatting (bullet points, numbered lists)
- Avoid repetition
- Focus on high-value insights
"""
        
        # Add scan/context data if available
        if context:
            context_str = self._format_context(context)
            system_prompt += f"\n\nCURRENT CONTEXT:\n{context_str}"
        
        # Add memory if enabled
        if self.use_memory and self.memory.get("long_term"):
            recent_memory = "\n".join(self.memory["long_term"][-5:])
            system_prompt += f"\n\nRELEVANT MEMORY:\n{recent_memory}"
        
        return system_prompt
    
    def _format_context(self, context: Dict) -> str:
        """Format context data efficiently"""
        parts = []
        
        if context.get("scan_results"):
            findings = context["scan_results"].get("findings", [])
            if findings:
                parts.append(f"Active Findings: {len(findings)} vulnerabilities detected")
                critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
                high = sum(1 for f in findings if f.get("severity") == "HIGH")
                if critical or high:
                    parts.append(f"  - CRITICAL: {critical}, HIGH: {high}")
        
        if context.get("target_info"):
            target = context["target_info"]
            parts.append(f"Target: {target.get('domain', 'Unknown')}")
            if target.get('ip'):
                parts.append(f"  IP: {target['ip']}")
            if target.get('tech_stack'):
                parts.append(f"  Tech: {', '.join(target['tech_stack'][:5])}")
        
        if context.get("notes_summary"):
            parts.append(f"User Notes: {context['notes_summary']}")
        
        if context.get("previous_actions"):
            parts.append(f"Recent Actions: {', '.join(context['previous_actions'][-3:])}")
        
        return "\n".join(parts) if parts else "No specific context available"
    
    def chat(self, message: str, role: str = None, context: Dict = None, 
             save_to_memory: bool = True, stream: bool = False) -> Dict:
        """
        Send message to Kimi AI with full context
        Returns response with metadata
        """
        # Check if enabled
        if not self.enabled or not self.api_key:
            return self._fallback_response(message, context)
        
        # Check token budget
        if not self._check_token_budget():
            return {
                "success": False,
                "error": "Daily token budget exceeded",
                "tokens_used_today": self.tokens_used_today,
                "budget": self.daily_token_budget,
                "fallback_available": True
            }
        
        try:
            # Build messages
            system_prompt = self._build_system_prompt(role, context)
            
            messages = [
                {"role": "system", "content": system_prompt}
            ]
            
            # Add conversation history if using memory
            if self.use_memory and save_to_memory:
                recent_convos = self.memory["conversations"][-10:]
                messages.extend(recent_convos)
            
            # Add current message
            messages.append({"role": "user", "content": message})
            
            # Prepare payload exactly as specified
            payload = {
                "model": self.model,
                "messages": messages,
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
                "top_p": 1.00,
                "stream": stream,
                "chat_template_kwargs": {"thinking": self.thinking_mode}
            }
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Accept": "text/event-stream" if stream else "application/json"
            }
            
            # Make request
            response = requests.post(self.api_url, headers=headers, json=payload, stream=stream, timeout=120)
            
            if response.status_code != 200:
                error_msg = f"API Error: {response.status_code} - {response.text[:200]}"
                if response.status_code == 401:
                    error_msg = "Invalid API key. Please update in settings."
                elif response.status_code == 429:
                    error_msg = "Rate limit exceeded. Try again later."
                
                return {
                    "success": False,
                    "error": error_msg,
                    "status_code": response.status_code
                }
            
            # Parse response
            if stream:
                # Handle streaming response
                full_response = ""
                thinking_content = ""
                for line in response.iter_lines():
                    if line:
                        decoded = line.decode("utf-8")
                        if decoded.startswith("data: "):
                            data = decoded[6:]
                            if data.strip() == "[DONE]":
                                break
                            try:
                                chunk = json.loads(data)
                                delta = chunk.get("choices", [{}])[0].get("delta", {})
                                if "content" in delta:
                                    full_response += delta["content"]
                                # Extract thinking if available
                                if "reasoning_content" in delta:
                                    thinking_content += delta["reasoning_content"]
                            except:
                                pass
                
                response_text = full_response
            else:
                # Handle non-streaming response
                result = response.json()
                response_text = result.get("choices", [{}])[0].get("message", {}).get("content", "")
                # Extract thinking if available
                thinking_content = result.get("choices", [{}])[0].get("message", {}).get("reasoning_content", "")
            
            # Estimate tokens used (rough estimate: 1 token ≈ 4 chars)
            estimated_tokens = (len(message) + len(response_text)) // 4
            self._log_token_usage(estimated_tokens)
            
            # Save to memory if enabled
            if save_to_memory and self.use_memory:
                self.memory["conversations"].append({"role": "user", "content": message})
                self.memory["conversations"].append({"role": "assistant", "content": response_text})
                self._save_memory()
            
            # Extract actionable items and next steps
            next_steps = self._extract_next_steps(response_text)
            commands = self._detect_commands(response_text) if self.agentic_mode else []
            
            return {
                "success": True,
                "response": response_text,
                "thinking": thinking_content if thinking_content else None,
                "next_steps": next_steps,
                "detected_commands": commands,
                "tokens_used": estimated_tokens,
                "tokens_remaining": self.daily_token_budget - self.tokens_used_today,
                "model": self.model,
                "role": role or self.config.get("role", "ethical_hacker")
            }
            
        except requests.exceptions.Timeout:
            return {
                "success": False,
                "error": "Request timed out. The AI is taking longer than expected.",
                "fallback_available": True
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error communicating with Kimi AI: {str(e)}",
                "fallback_available": True
            }
    
    def _fallback_response(self, message: str, context: Dict = None) -> Dict:
        """Provide intelligent local suggestions when API unavailable"""
        message_lower = message.lower()
        
        suggestions = []
        next_steps = []
        
        # Pattern-based suggestions
        if any(word in message_lower for word in ["scan", "recon", "enumerate"]):
            suggestions.append("Consider running targeted Nmap scans on identified ports")
            suggestions.append("Use subdomain enumeration tools like Subfinder or Amass")
            next_steps.append("Run detailed port scan on top 1000 ports")
            next_steps.append("Check for common web vulnerabilities on discovered services")
        
        if any(word in message_lower for word in ["vuln", "cve", "exploit"]):
            suggestions.append("Search CVE databases for known exploits")
            suggestions.append("Verify vulnerability with manual testing before reporting")
            next_steps.append("Check Exploit-DB and GitHub for PoC exploits")
            next_steps.append("Assess CVSS score and business impact")
        
        if any(word in message_lower for word in ["report", "write", "document"]):
            suggestions.append("Structure report: Executive Summary → Methodology → Findings → Recommendations")
            suggestions.append("Include proof-of-concept screenshots for each finding")
            next_steps.append("Prioritize findings by severity and business impact")
            next_steps.append("Draft remediation steps for each vulnerability")
        
        if any(word in message_lower for word in ["note", "remember", "track"]):
            suggestions.append("Document all findings in the integrated notes system")
            suggestions.append("Tag notes with relevant categories for easy retrieval")
            next_steps.append("Create note entries for each significant finding")
            next_steps.append("Link related findings together")
        
        # Context-aware suggestions
        if context:
            if context.get("scan_results"):
                findings = context["scan_results"].get("findings", [])
                critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
                if critical_count > 0:
                    suggestions.insert(0, f"⚠️ URGENT: {critical_count} CRITICAL findings require immediate attention")
                    next_steps.insert(0, "Prioritize remediation of CRITICAL vulnerabilities")
        
        response_text = "📋 **Analysis** (Kimi AI offline - providing local suggestions):\n\n"
        if suggestions:
            response_text += "**Suggestions:**\n" + "\n".join(f"• {s}" for s in suggestions) + "\n\n"
        if next_steps:
            response_text += "**Recommended Next Steps:**\n" + "\n".join(f"→ {n}" for n in next_steps)
        
        return {
            "success": True,
            "response": response_text,
            "next_steps": next_steps,
            "offline_mode": True,
            "message": "Kimi AI not configured. Set API key in Settings to enable advanced AI analysis."
        }
    
    def _extract_next_steps(self, response_text: str) -> List[str]:
        """Extract actionable next steps from response"""
        steps = []
        lines = response_text.split('\n')
        
        for line in lines:
            line = line.strip()
            # Look for common next step indicators
            if any(indicator in line.lower() for indicator in 
                   ["next step", "recommendation", "action item", "todo", "→", "✓", "•", "-"]):
                # Clean up the line
                clean_line = line.lstrip("•-*→✓").strip()
                if clean_line and len(clean_line) < 200:
                    steps.append(clean_line)
        
        return steps[:5]  # Limit to top 5 steps
    
    def _detect_commands(self, response_text: str) -> List[Dict]:
        """Detect executable commands in response (for agentic mode)"""
        commands = []
        
        # Common tool patterns
        tool_patterns = [
            (r"nmap\s+(-[\w\s]+\s+)?([0-9.]+)", "nmap", "Port Scanner"),
            (r"gobuster\s+(dir|dns)\s+", "gobuster", "Directory/DNS Enumerator"),
            (r"nikto\s+-h\s+", "nikto", "Web Scanner"),
            (r"sqlmap\s+-u\s+", "sqlmap", "SQL Injection Tool"),
            (r"burp\s+", "burp", "Burp Suite"),
            (r"metasploit\s+", "msfconsole", "Metasploit"),
        ]
        
        for pattern, tool, description in tool_patterns:
            import re
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                commands.append({
                    "tool": tool,
                    "description": description,
                    "requires_confirmation": True,
                    "risk_level": "medium"
                })
        
        return commands
    
    def analyze_finding(self, finding: Dict, context: Dict = None) -> Dict:
        """Analyze a specific security finding"""
        prompt = f"""Analyze this security finding and provide:
1. Technical explanation
2. Business impact assessment  
3. Exploitation scenario
4. Remediation steps
5. Priority level (Critical/High/Medium/Low)

Finding Details:
- Title: {finding.get('title', 'Unknown')}
- Severity: {finding.get('severity', 'Unknown')}
- Description: {finding.get('description', 'No description')}
- Evidence: {finding.get('evidence', 'No evidence provided')}
- Affected Component: {finding.get('component', 'Unknown')}

Provide your analysis in a structured format."""
        
        return self.chat(prompt, context=context)
    
    def suggest_next_actions(self, scan_results: Dict, notes: List = None) -> Dict:
        """Suggest next actions based on scan results and notes"""
        context = {
            "scan_results": scan_results,
            "notes_summary": "\n".join(notes[-5:]) if notes else None
        }
        
        prompt = """Based on the current scan results and notes, provide:
1. Top 3 priority actions to take immediately
2. Additional reconnaissance opportunities
3. Potential attack chains to investigate
4. Quick wins for low-hanging fruit
5. Long-term strategic recommendations

Be specific and actionable."""
        
        return self.chat(prompt, context=context)
    
    def format_report(self, findings: List[Dict], target_info: Dict, 
                      executive_summary: str = None) -> Dict:
        """Format professional security report"""
        context = {
            "target_info": target_info,
            "scan_results": {"findings": findings}
        }
        
        prompt = f"""Create a professional penetration test report with the following structure:

# EXECUTIVE SUMMARY
{executive_summary or "[Generate based on findings]"}

# METHODOLOGY
Brief description of testing approach and scope

# FINDINGS SUMMARY
- Total Findings: {len(findings)}
- Critical: {sum(1 for f in findings if f.get('severity') == 'CRITICAL')}
- High: {sum(1 for f in findings if f.get('severity') == 'HIGH')}
- Medium: {sum(1 for f in findings if f.get('severity') == 'MEDIUM')}
- Low: {sum(1 for f in findings if f.get('severity') == 'LOW')}

# DETAILED FINDINGS
For each finding, include:
- Title
- Severity
- Description
- Technical Details
- Proof of Concept / Evidence
- Business Impact
- Remediation Steps
- References

# CONCLUSION AND RECOMMENDATIONS
Strategic security recommendations

Format this as a professional report suitable for both technical teams and executives."""
        
        return self.chat(prompt, context=context)
    
    def add_to_memory(self, content: str, category: str = "general"):
        """Add information to long-term memory"""
        self.memory["long_term"].append({
            "timestamp": datetime.now().isoformat(),
            "category": category,
            "content": content
        })
        self._save_memory()
    
    def clear_memory(self, conversations: bool = True, long_term: bool = False):
        """Clear memory selectively"""
        if conversations:
            self.memory["conversations"] = []
        if long_term:
            self.memory["long_term"] = []
        self._save_memory()
    
    def get_memory_stats(self) -> Dict:
        """Get memory statistics"""
        return {
            "conversation_count": len(self.memory["conversations"]),
            "long_term_memories": len(self.memory["long_term"]),
            "token_usage_today": self.tokens_used_today,
            "token_budget": self.daily_token_budget,
            "usage_percentage": (self.tokens_used_today / self.daily_token_budget * 100) if self.daily_token_budget > 0 else 0
        }


# Global instance for easy import
_kimi_instance = None

def get_kimi_agent() -> KimiAgent:
    """Get singleton Kimi agent instance"""
    global _kimi_instance
    if _kimi_instance is None:
        _kimi_instance = KimiAgent()
    return _kimi_instance
