"""
Sentinel Core - Elite Cybersecurity Intelligence Platform
ShadowEye Launcher - Automatic Module Registration & System Initialization
"""

import os
import sys
import json
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/shadowseye.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('ShadowEye')

class ShadowEyeLauncher:
    """Elite launcher for Sentinel Core - Auto-registers all OSINT modules"""
    
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.config_dir = os.path.join(self.base_dir, 'config')
        self.db_dir = os.path.join(self.base_dir, 'db')
        self.evidence_dir = os.path.join(self.base_dir, 'evidence')
        self.user_modules_dir = os.path.join(self.base_dir, 'user_modules')
        self.logs_dir = os.path.join(self.base_dir, 'logs')
        
        # Ensure all directories exist
        self._ensure_directories()
        
        # Registered OSINT modules
        self.osint_modules = [
            {'name': 'DNS Enumeration', 'file': 'dns_module.py', 'api_required': False},
            {'name': 'WHOIS Lookup', 'file': 'whois_module.py', 'api_required': False},
            {'name': 'SSL Analysis', 'file': 'ssl_module.py', 'api_required': False},
            {'name': 'Certificate Transparency', 'file': 'crtsh_module.py', 'api_required': False},
            {'name': 'Shodan Search', 'file': 'shodan_module.py', 'api_required': True},
            {'name': 'VirusTotal Analysis', 'file': 'virustotal_module.py', 'api_required': True},
            {'name': 'Wayback Machine', 'file': 'wayback_module.py', 'api_required': False},
            {'name': 'Hunter.io', 'file': 'hunter_module.py', 'api_required': True},
        ]
        
        # Integrated Kali/Parrot tools
        self.kali_tools = [
            'nmap', 'whois', 'dig', 'nslookup', 'sslscan', 'testssl.sh',
            'theharvester', 'subfinder', 'amass', 'httpx', 'nuclei', 'nikto',
            'sqlmap', 'gobuster', 'dirb', 'wfuzz', 'masscan', 'zap', 'burpsuite',
            'metasploit', 'mimikatz', 'john', 'hashcat', 'wireshark', 'tcpdump'
        ]
        
    def _ensure_directories(self):
        """Create all required directories"""
        dirs = [self.config_dir, self.db_dir, self.evidence_dir, 
                self.user_modules_dir, self.logs_dir]
        for d in dirs:
            os.makedirs(d, exist_ok=True)
            logger.info(f"✓ Directory ensured: {d}")
    
    def initialize_settings(self):
        """Initialize settings.json with defaults"""
        settings_file = os.path.join(self.config_dir, 'settings.json')
        default_settings = {
            'nvidia_api_key': '',
            'shodan_api_key': '',
            'virustotal_api_key': '',
            'hunter_api_key': '',
            'ai_model': 'moonshotai/kimi-k2.5',
            'agentic_mode': True,
            'theme': 'dark',
            'token_budget_daily': 100000,
            'token_budget_used': 0,
            'last_reset': datetime.now().isoformat()
        }
        
        if not os.path.exists(settings_file):
            with open(settings_file, 'w') as f:
                json.dump(default_settings, f, indent=2)
            logger.info("✓ Settings initialized")
        else:
            logger.info("✓ Settings already exist")
        
        return settings_file
    
    def register_modules(self):
        """Register all OSINT modules in the registry"""
        registry_file = os.path.join(self.base_dir, 'engine', 'module_registry.json')
        registry = {
            'modules': {},
            'last_updated': datetime.now().isoformat(),
            'total_modules': len(self.osint_modules)
        }
        
        for module in self.osint_modules:
            module_path = os.path.join(self.base_dir, 'modules', module['file'])
            if os.path.exists(module_path):
                registry['modules'][module['name']] = {
                    'file': module['file'],
                    'api_required': module['api_required'],
                    'status': 'registered',
                    'registered_at': datetime.now().isoformat()
                }
                logger.info(f"✓ Module registered: {module['name']}")
            else:
                logger.warning(f"✗ Module file not found: {module['file']}")
        
        with open(registry_file, 'w') as f:
            json.dump(registry, f, indent=2)
        
        logger.info(f"✓ Module registry updated: {len(registry['modules'])} modules")
        return registry
    
    def check_kali_tools(self):
        """Check availability of Kali/Parrot tools"""
        import shutil
        available = []
        missing = []
        
        for tool in self.kali_tools:
            if shutil.which(tool):
                available.append(tool)
            else:
                missing.append(tool)
        
        logger.info(f"✓ Available tools: {len(available)}/{len(self.kali_tools)}")
        if missing:
            logger.info(f"ℹ Missing tools (optional): {', '.join(missing[:5])}...")
        
        return {'available': available, 'missing': missing}
    
    def initialize_database(self):
        """Initialize SQLite database schema"""
        from models.intelligence import init_db
        init_db()
        logger.info("✓ Database initialized")
    
    def launch(self):
        """Full system launch sequence"""
        print("=" * 60)
        print("🛡️  SENTINEL CORE - ShadowEye Launcher")
        print("=" * 60)
        
        # Step 1: Directories
        print("\n[1/5] Setting up directories...")
        self._ensure_directories()
        
        # Step 2: Settings
        print("[2/5] Initializing settings...")
        self.initialize_settings()
        
        # Step 3: Modules
        print("[3/5] Registering OSINT modules...")
        self.register_modules()
        
        # Step 4: Tools
        print("[4/5] Checking Kali/Parrot tools...")
        self.check_kali_tools()
        
        # Step 5: Database
        print("[5/5] Initializing database...")
        self.initialize_database()
        
        print("\n" + "=" * 60)
        print("✅ SYSTEM READY - Starting Flask application...")
        print("=" * 60)
        
        return True


if __name__ == '__main__':
    launcher = ShadowEyeLauncher()
    launcher.launch()
