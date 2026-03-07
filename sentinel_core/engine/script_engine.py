"""
SENTINEL CORE - DYNAMIC SCRIPT ENGINE ("GOD MODE")
Allows execution of custom Python scripts, chaining of native tools, and real-time data injection.
Designed for elite operators to extend capabilities on the fly.
"""
import importlib.util
import sys
import os
import uuid
import json
import subprocess
from typing import Dict, Any, List, Optional
from datetime import datetime
import traceback

class SentinelScriptContext:
    """
    The secure context provided to user scripts.
    Gives access to internal tools, database, and external APIs without exposing raw internals.
    """
    def __init__(self, case_id: str, target: str, api_session=None):
        self.case_id = case_id
        self.target = target
        self.session_id = str(uuid.uuid4())
        self.results = []
        self.entities = []  # Format: {"type": "IP", "value": "1.2.3.4", "meta": {}}
        self.logs = []
        self.api_session = api_session

    def log(self, message: str, level: str = "INFO"):
        entry = {"timestamp": datetime.utcnow().isoformat(), "level": level, "message": message}
        self.logs.append(entry)
        print(f"[{level}] {message}")

    def add_entity(self, etype: str, value: str, confidence: int = 80, source: str = "custom_script", meta: dict = None):
        entity = {
            "id": str(uuid.uuid4()),
            "type": etype.upper(),
            "value": value,
            "confidence": confidence,
            "source": source,
            "meta": meta or {},
            "created_at": datetime.utcnow().isoformat()
        }
        self.entities.append(entity)
        self.log(f"Discovered Entity: {etype} -> {value}", "SUCCESS")
        return entity

    def run_tool(self, command: List[str], timeout: int = 60) -> Dict[str, Any]:
        """Safely execute a system tool (e.g., amass, nuclei)"""
        self.log(f"Executing tool: {' '.join(command)}")
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={**os.environ, "NO_COLOR": "1"} # Disable colors for parsing
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Timeout", "stdout": "", "stderr": "Execution timed out"}
        except Exception as e:
            return {"success": False, "error": str(e), "stdout": "", "stderr": ""}

    def http_get(self, url: str, headers: dict = None) -> Dict:
        # Placeholder for internal request helper
        import requests
        try:
            r = requests.get(url, headers=headers, timeout=10)
            return {"status": r.status_code, "body": r.text, "headers": dict(r.headers)}
        except Exception as e:
            return {"error": str(e)}

class DynamicModuleEngine:
    def __init__(self, storage_path: str = "user_modules"):
        self.storage_path = storage_path
        os.makedirs(storage_path, exist_ok=True)
        self.builtin_templates = self._load_builtin_templates()

    def _load_builtin_templates(self) -> Dict[str, str]:
        """Elite pre-built scripts for common high-value operations"""
        return {
            "subdomain_bruteforce_extreme": '''
def run(ctx):
    ctx.log("Starting Extreme Subdomain Enumeration...", "INIT")
    
    # Chain: Amass -> Subfinder -> Assetfinder
    tools = [
        ["amass", "enum", "-d", ctx.target, "-passive", "-timeout", "2"],
        ["subfinder", "-d", ctx.target, "-silent"],
        ["assetfinder", "--subs-only", ctx.target]
    ]
    
    found_subs = set()
    for cmd in tools:
        res = ctx.run_tool(cmd, timeout=30)
        if res["success"]:
            for line in res["stdout"].splitlines():
                if ctx.target in line:
                    found_subs.add(line.strip())
    
    for sub in found_subs:
        ctx.add_entity("DOMAIN", sub, confidence=90, source="multi-tool-chain")
    
    ctx.log(f"Enumeration complete. Found {len(found_subs)} subdomains.", "SUCCESS")
    return {"count": len(found_subs), "entities": ctx.entities}
''',
            "vuln_scan_nuclei_critical": '''
def run(ctx):
    ctx.log("Launching Nuclei Critical Vulnerability Scan...", "INIT")
    
    # Run nuclei with critical templates only
    cmd = ["nuclei", "-u", ctx.target, "-t", "critical", "-json", "-silent"]
    res = ctx.run_tool(cmd, timeout=120)
    
    if res["success"]:
        for line in res["stdout"].splitlines():
            try:
                vuln = json.loads(line)
                ctx.add_entity("VULNERABILITY", vuln.get("template-id"), 
                               confidence=95, source="nuclei", 
                               meta={"severity": vuln.get("info", {}).get("severity"), "url": vuln.get("matched-at")})
            except json.JSONDecodeError:
                continue
    
    ctx.log("Vulnerability scan complete.", "SUCCESS")
    return {"entities": ctx.entities}
''',
            "ip_recon_asn_bgp": '''
def run(ctx):
    ctx.log("Performing BGP/ASN Intelligence...", "INIT")
    # Use whois and bgp tools if available, else mock logic for demo
    cmd = ["whois", ctx.target]
    res = ctx.run_tool(cmd, timeout=20)
    
    if res["success"]:
        output = res["stdout"]
        # Simple regex extraction for ASN (demo logic)
        import re
        asns = re.findall(r"AS\d+", output)
        for asn in set(asns):
            ctx.add_entity("ASN", asn, confidence=85, source="whois-parse")
            
    ctx.log("ASN Recon complete.", "SUCCESS")
    return {"entities": ctx.entities}
'''
        }

    def save_user_script(self, name: str, code: str, author: str) -> str:
        """Save a custom script uploaded by the user"""
        filename = f"{name}.py"
        filepath = os.path.join(self.storage_path, filename)
        
        # Add metadata header
        header = f'''
# SENTINEL CUSTOM MODULE
# Name: {name}
# Author: {author}
# Created: {datetime.utcnow().isoformat()}
'''
        with open(filepath, "w") as f:
            f.write(header + code)
        
        self.log(f"Custom module '{name}' saved by {author}")
        return filename

    def execute_script(self, script_name: str, code: Optional[str], case_id: str, target: str) -> Dict:
        """
        Dynamically load and execute a script (either from file or raw code string).
        Provides the SentinelScriptContext to the script.
        """
        context = SentinelScriptContext(case_id, target)
        
        try:
            # Determine source
            if code:
                script_code = code
                module_name = f"dynamic_{uuid.uuid4().hex}"
            else:
                # Load from file
                filepath = os.path.join(self.storage_path, script_name)
                if not os.path.exists(filepath):
                    # Check builtins
                    if script_name in self.builtin_templates:
                        script_code = self.builtin_templates[script_name]
                        module_name = f"builtin_{script_name}"
                    else:
                        raise FileNotFoundError(f"Script {script_name} not found")
                else:
                    with open(filepath, "r") as f:
                        script_code = f.read()
                    module_name = f"user_{script_name.replace('.py', '')}"

            # Create module spec
            spec = importlib.util.spec_from_loader(module_name, loader=None)
            module = importlib.util.module_from_spec(spec)
            
            # Inject context as 'ctx' global
            module.ctx = context
            
            # Execute
            exec(script_code, module.__dict__)
            
            # Look for 'run' function
            if hasattr(module, "run"):
                result = module.run(context)
                return {
                    "status": "success",
                    "result": result,
                    "entities": context.entities,
                    "logs": context.logs
                }
            else:
                raise Exception("Script must define a 'run(ctx)' function")

        except Exception as e:
            error_trace = traceback.format_exc()
            context.log(f"Execution failed: {str(e)}", "ERROR")
            return {
                "status": "failed",
                "error": str(e),
                "traceback": error_trace,
                "logs": context.logs
            }

    def log(self, msg):
        print(f"[ENGINE] {msg}")

# Singleton instance
engine = DynamicModuleEngine()
