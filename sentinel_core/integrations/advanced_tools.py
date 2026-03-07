"""
SENTINEL CORE - ADVANCED TOOL INTEGRATION LAYER
Integrates with 20+ elite tools found in Kali/Parrot OS for maximum reconnaissance and exploitation capability.
Auto-detects tools and exposes unified interfaces.
"""
import subprocess
import shutil
import json
import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

@dataclass
class ToolDefinition:
    name: str
    command: str
    description: str
    category: str  # recon, vuln, exploit, post, network
    args_template: List[str]
    output_format: str  # text, json, xml

class AdvancedToolRegistry:
    def __init__(self):
        self.tools: Dict[str, ToolDefinition] = {}
        self.available_tools: Dict[str, str] = {}  # name -> path
        self._discover_tools()
        self._register_elite_tools()

    def _discover_tools(self):
        """Scan system PATH for known security tools"""
        known_tools = [
            "amass", "subfinder", "assetfinder", "httpx", "nuclei", "naabu",
            "dnsrecon", "theHarvester", "maltego", "recon-ng", "sherlock",
            "holehe", "maigret", "whatweb", "wafw00f", "nmap", "masscan",
            "gobuster", "dirb", "ffuf", "burpsuite", "zap", "sqlmap",
            "hydra", "john", "hashcat", "aircrack-ng", "wireshark", "tshark",
            "binwalk", "strings", "exiftool", "steghide", "volatility",
            "ghidra", "radare2", "metasploit", "msfconsole", "searchsploit",
            "netcat", "socat", "curl", "wget", "git", "docker"
        ]
        
        for tool in known_tools:
            path = shutil.which(tool)
            if path:
                self.available_tools[tool] = path

    def _register_elite_tools(self):
        """Register detailed definitions for elite tools"""
        self.tools = {
            "amass": ToolDefinition(
                name="Amass",
                command="amass",
                description="In-depth Attack Surface Mapping and Asset Discovery",
                category="recon",
                args_template=["enum", "-d", "{target}", "-passive", "-timeout", "2"],
                output_format="text"
            ),
            "subfinder": ToolDefinition(
                name="Subfinder",
                command="subfinder",
                description="Fast passive subdomain enumeration tool",
                category="recon",
                args_template=["-d", "{target}", "-silent", "-all"],
                output_format="text"
            ),
            "httpx": ToolDefinition(
                name="HTTPX",
                command="httpx",
                description="Fast and multi-purpose HTTP toolkit",
                category="recon",
                args_template=["-u", "{target}", "-title", "-tech-detect", "-status-code", "-json"],
                output_format="json"
            ),
            "nuclei": ToolDefinition(
                name="Nuclei",
                command="nuclei",
                description="Fast and customizable vulnerability scanner",
                category="vuln",
                args_template=["-u", "{target}", "-t", "critical,high", "-json", "-silent"],
                output_format="json"
            ),
            "naabu": ToolDefinition(
                name="Naabu",
                command="naabu",
                description="Fast port scanning written in Go",
                category="network",
                args_template=["-host", "{target}", "-port", "80,443,8080,8443,22,21,3306,5432", "-json"],
                output_format="json"
            ),
            "dnsrecon": ToolDefinition(
                name="DNSRecon",
                command="dnsrecon",
                description="DNS Enumeration Suite",
                category="recon",
                args_template=["-d", "{target}", "-t", "std,axfr", "--json"],
                output_format="json"
            ),
            "theHarvester": ToolDefinition(
                name="theHarvester",
                command="theHarvester",
                description="E-mails, subdomains and names harvester",
                category="recon",
                args_template=["-d", "{target}", "-b", "google,linkedin,bing", "-f", "json"],
                output_format="json"
            ),
            "whatweb": ToolDefinition(
                name="WhatWeb",
                command="whatweb",
                description="Next generation web scanner",
                category="recon",
                args_template=["{target}", "--json"],
                output_format="json"
            ),
            "wafw00f": ToolDefinition(
                name="WAFW00F",
                command="wafw00f",
                description="Web Application Firewall Fingerprinting Tool",
                category="recon",
                args_template=["{target}", "-f", "json"],
                output_format="json"
            ),
            "nmap": ToolDefinition(
                name="Nmap",
                command="nmap",
                description="Network exploration tool and security / port scanner",
                category="network",
                args_template=["-sV", "-sC", "-oJ", "-", "{target}"],
                output_format="json"
            ),
            "gobuster": ToolDefinition(
                name="Gobuster",
                command="gobuster",
                description="Directory/File & DNS busting tool",
                category="recon",
                args_template=["dir", "-u", "{target}", "-w", "/usr/share/wordlists/dirb/common.txt", "-q"],
                output_format="text"
            ),
            "ffuf": ToolDefinition(
                name="FFUF",
                command="ffuf",
                description="Fast web fuzzer written in Go",
                category="recon",
                args_template=["-u", "{target}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt", "-j"],
                output_format="json"
            ),
            "sqlmap": ToolDefinition(
                name="SQLMap",
                command="sqlmap",
                description="Automatic SQL injection and database takeover tool",
                category="exploit",
                args_template=["-u", "{target}", "--batch", "--technique=BEUSTQ"],
                output_format="text"
            ),
            "searchsploit": ToolDefinition(
                name="SearchSploit",
                command="searchsploit",
                description="Command line search tool for Exploit-DB",
                category="vuln",
                args_template=["--json", "{target}"],
                output_format="json"
            ),
            "sherlock": ToolDefinition(
                name="Sherlock",
                command="sherlock",
                description="Hunt down social media accounts by username",
                category="recon",
                args_template=["{target}", "--json"],
                output_format="json"
            ),
            "maigret": ToolDefinition(
                name="Maigret",
                command="maigret",
                description="Collect a dossier on a person by username",
                category="recon",
                args_template=["{target}", "-a", "--json"],
                output_format="json"
            ),
            "exiftool": ToolDefinition(
                name="ExifTool",
                command="exiftool",
                description="Read/write meta information in files",
                category="post",
                args_template=["-json", "{target}"],
                output_format="json"
            ),
            "binwalk": ToolDefinition(
                name="Binwalk",
                command="binwalk",
                description="Analyze binary files for embedded files/code",
                category="post",
                args_template=["-e", "{target}"],
                output_format="text"
            ),
            "jwt_tool": ToolDefinition(
                name="JWT Tool",
                command="jwt_tool",
                description="JSON Web Token manipulation and auditing",
                category="exploit",
                args_template=["{target}"],
                output_format="text"
            ),
            "aquatone": ToolDefinition(
                name="Aquatone",
                command="aquatone",
                description="Tool for Visual Inspection of Websites",
                category="recon",
                args_template=["-domains", "{input_file}", "-out", "{output_dir}"],
                output_format="html"
            )
        }

    def is_available(self, tool_name: str) -> bool:
        return tool_name.lower() in [t.lower() for t in self.available_tools.keys()]

    def get_available_tools_by_category(self, category: str) -> List[Dict]:
        result = []
        for name, tool in self.tools.items():
            if tool.category == category and self.is_available(name):
                result.append({
                    "name": tool.name,
                    "command": tool.command,
                    "description": tool.description,
                    "installed": True
                })
        return result

    def execute_tool(self, tool_name: str, target: str, custom_args: List[str] = None, timeout: int = 120) -> Dict[str, Any]:
        """Execute a registered tool with the given target"""
        if tool_name not in self.tools:
            return {"error": f"Tool {tool_name} not registered", "success": False}
        
        tool_def = self.tools[tool_name]
        
        if not self.is_available(tool_name):
            return {"error": f"Tool {tool_name} not found in system PATH", "success": False}
        
        # Build command
        cmd = [tool_def.command]
        
        # Process args template
        args = []
        for arg in tool_def.args_template:
            processed = arg.replace("{target}", target)
            if processed != arg or custom_args is None:
                args.append(processed)
        
        if custom_args:
            args.extend(custom_args)
        
        full_cmd = cmd + args
        
        try:
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={**os.environ, "NO_COLOR": "1"}
            )
            
            output = result.stdout
            if tool_def.output_format == "json":
                try:
                    # Try to parse JSON output if applicable
                    if output.strip().startswith('{') or output.strip().startswith('['):
                        output = json.loads(output)
                except json.JSONDecodeError:
                    pass
            
            return {
                "success": result.returncode == 0,
                "tool": tool_name,
                "command": " ".join(full_cmd),
                "output": output,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Timeout", "tool": tool_name}
        except Exception as e:
            return {"success": False, "error": str(e), "tool": tool_name}

    def run_recon_chain(self, target: str) -> Dict[str, Any]:
        """Run a comprehensive reconnaissance chain using all available tools"""
        results = {}
        
        # Phase 1: Subdomain Enumeration
        subdomain_tools = ["amass", "subfinder", "assetfinder"]
        results["subdomains"] = []
        for tool in subdomain_tools:
            if self.is_available(tool):
                res = self.execute_tool(tool, target)
                if res["success"]:
                    results["subdomains"].append({"tool": tool, "output": res["output"]})
        
        # Phase 2: Port Scanning
        port_tools = ["naabu", "nmap"]
        results["ports"] = []
        for tool in port_tools:
            if self.is_available(tool):
                res = self.execute_tool(tool, target)
                if res["success"]:
                    results["ports"].append({"tool": tool, "output": res["output"]})
        
        # Phase 3: Tech Stack & WAF
        tech_tools = ["whatweb", "wafw00f", "httpx"]
        results["tech_stack"] = []
        for tool in tech_tools:
            if self.is_available(tool):
                res = self.execute_tool(tool, target)
                if res["success"]:
                    results["tech_stack"].append({"tool": tool, "output": res["output"]})
        
        # Phase 4: Vulnerability Scanning (Light)
        vuln_tools = ["nuclei"]
        results["vulnerabilities"] = []
        for tool in vuln_tools:
            if self.is_available(tool):
                # Use only critical templates for speed
                res = self.execute_tool(tool, target, custom_args=["-t", "critical"])
                if res["success"]:
                    results["vulnerabilities"].append({"tool": tool, "output": res["output"]})
        
        return results

# Singleton
registry = AdvancedToolRegistry()
