#!/usr/bin/env python3
"""
ShadowEye - Elite Sentinel Core Launcher
Developed by Syed Abrar (Alias: Cyb3rvolt3x)
© SentinelReign.com - All Rights Reserved

Advanced OSINT Platform for:
- RAW, MOSSAD, IB Intelligence Agencies
- Military Cyber Commands  
- Elite Ethical Hackers & Bug Bounty Hunters
- Professional SOC Teams

This is the premier choice for nation-state level reconnaissance.
"""

import os
import sys
import socket
import webbrowser
from datetime import datetime

# Banner
BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                         🛡️  SHADOW EYE LAUNCHER  🛡️                           ║
║                     Sentinel Core Elite OSINT Platform                        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Developer: Syed Abrar (Cyb3rvolt3x)                                         ║
║  Organization: SentinelReign.com                                             ║
║  Classification: ELITE TIER                                                  ║
║  Authorized Use: Intelligence Agencies, Military, Ethical Hackers Only       ║
╚══════════════════════════════════════════════════════════════════════════════╝

🎯 DESIGNED FOR:
   • RAW / MOSSAD / IB Intelligence Operations
   • Military Cyber Warfare Commands
   • Elite Bug Bounty Hunters
   • Advanced Persistent Threat (APT) Analysis
   • Nation-State Reconnaissance

⚡ FEATURES:
   • 20+ Integrated Kali/Parrot Tools
   • Dynamic Python Script Engine (GOD MODE)
   • Maltego-Style Graph Analysis
   • Automated Report Generation (HTML/STIX/JSON/PDF)
   • Multi-Worker Async Execution
   • Custom Tool Integration
   • Chain of Custody Evidence Tracking

"""

def check_port_available(port):
    """Check if a port is available"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('0.0.0.0', port))
        sock.close()
        return True
    except:
        return False

def get_ip_address():
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "localhost"

def main():
    print(BANNER)
    
    # Configuration
    HOST = '0.0.0.0'
    PORT = 5001
    
    # Get absolute path to app directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(current_dir)
    
    print(f"[+] Working Directory: {current_dir}")
    print(f"[+] Database Path: {os.path.join(current_dir, 'db', 'sentinel.db')}")
    
    # Check port availability
    if not check_port_available(PORT):
        print(f"[!] Port {PORT} is already in use.")
        response = input("Do you want to use port 5002 instead? (y/n): ")
        if response.lower() == 'y':
            PORT = 5002
        else:
            print("[!] Please free up port 5001 and try again.")
            sys.exit(1)
    
    print(f"\n[+] Starting ShadowEye on http://0.0.0.0:{PORT}")
    print(f"[+] Local Access: http://localhost:{PORT}")
    print(f"[+] Network Access: http://{get_ip_address()}:{PORT}")
    
    # Try to open browser
    try:
        webbrowser.open(f'http://localhost:{PORT}')
        print("[+] Opening web browser...")
    except:
        pass
    
    print("\n" + "="*70)
    print("DEFAULT CREDENTIALS:")
    print("  Username: admin")
    print("  Password: admin123")
    print("="*70)
    print("\n⚠️  SECURITY NOTICE:")
    print("   Change default credentials immediately after first login!")
    print("   This platform is for AUTHORIZED security research only.")
    print("="*70)
    print("\n[Starting Server...]")
    print("-"*70)
    
    # Import and run the app
    from app import app, init_db, register_builtin_modules, registry, task_queue
    from integrations.advanced_tools import registry as tool_registry
    from engine.script_engine import engine as script_engine
    from integrations.kali_tools import kali_tools
    
    # Initialize database
    init_db()
    
    # Register builtin modules
    register_builtin_modules()
    
    # Register additional elite modules
    from modules.shodan_module import run_shodan_search
    from modules.virustotal_module import run_virustotal_scan
    from modules.wayback_module import search_wayback_machine
    from modules.hunter_module import run_hunter_search
    
    # Shodan Module
    from engine.module_registry import ModuleMetadata
    shodan_meta = ModuleMetadata(
        module_id='shodan',
        name='Shodan Search',
        description='IoT device and service discovery via Shodan',
        version='2.0.0',
        author='Syed Abrar (Cyb3rvolt3x)',
        category='recon'
    ).set_input_schema({
        'target': {'type': 'string', 'required': True, 'description': 'IP, domain, or search query'}
    }).set_output_schema({
        'results': {'type': 'array'},
        'total': {'type': 'integer'}
    }).require_secrets(['SHODAN_API_KEY']).set_timeout(60).set_retries(2)
    
    registry.register(shodan_meta, run_shodan_search)
    
    # VirusTotal Module
    vt_meta = ModuleMetadata(
        module_id='virustotal',
        name='VirusTotal Analysis',
        description='Malware and URL reputation checking',
        version='2.0.0',
        author='Syed Abrar (Cyb3rvolt3x)',
        category='threat_intel'
    ).set_input_schema({
        'target': {'type': 'string', 'required': True, 'description': 'File hash, URL, domain, or IP'}
    }).set_output_schema({
        'detections': {'type': 'integer'},
        'total_engines': {'type': 'integer'},
        'report': {'type': 'object'}
    }).require_secrets(['VIRUSTOTAL_API_KEY']).set_timeout(45).set_retries(3)
    
    registry.register(vt_meta, run_virustotal_scan)
    
    # Wayback Machine Module
    wayback_meta = ModuleMetadata(
        module_id='wayback',
        name='Wayback Machine Archive',
        description='Historical website snapshots and subdomains',
        version='2.0.0',
        author='Syed Abrar (Cyb3rvolt3x)',
        category='recon'
    ).set_input_schema({
        'target': {'type': 'string', 'required': True, 'description': 'Domain name'}
    }).set_output_schema({
        'snapshots': {'type': 'array'},
        'subdomains': {'type': 'array'}
    }).set_timeout(90).set_retries(2)
    
    registry.register(wayback_meta, search_wayback_machine)
    
    # Hunter.io Module
    hunter_meta = ModuleMetadata(
        module_id='hunter',
        name='Hunter.io Email Finder',
        description='Professional email address discovery',
        version='2.0.0',
        author='Syed Abrar (Cyb3rvolt3x)',
        category='recon'
    ).set_input_schema({
        'target': {'type': 'string', 'required': True, 'description': 'Domain name'}
    }).set_output_schema({
        'emails': {'type': 'array'},
        'sources': {'type': 'array'}
    }).require_secrets(['HUNTER_API_KEY']).set_timeout(60).set_retries(2)
    
    registry.register(hunter_meta, run_hunter_search)
    
    # Register module executors with task queue
    for module_id, module_data in registry.modules.items():
        if module_data['executor']:
            task_queue.register_executor(module_id, module_data['executor'])
    
    # Register advanced tool executors
    def full_recon_executor(target):
        """Execute full reconnaissance chain - expects string target"""
        return tool_registry.run_recon_chain(target)
    
    task_queue.register_executor('full_recon_chain', full_recon_executor)
    
    def kali_comprehensive_executor(target):
        """Execute comprehensive Kali tools scan - expects string target"""
        return kali_tools.run_comprehensive_recon(target)
    
    task_queue.register_executor('kali_comprehensive', kali_comprehensive_executor)
    
    # Start async workers
    task_queue.start_workers(num_workers=5)
    
    # Register result callback to save results to DB
    import sqlite3
    import json
    from app import DATABASE
    
    def on_task_complete(task):
        """Save completed task results to database"""
        if task.result or task.error:
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            
            metadata = {
                'task_id': task.task_id,
                'status': task.status.value,
                'started_at': task.started_at,
                'completed_at': task.completed_at,
                'retry_count': task.retry_count,
                'module_version': registry.get_module(task.module_id)['metadata'].version if registry.get_module(task.module_id) else 'unknown'
            }
            
            if task.result:
                metadata['result'] = task.result
            if task.error:
                metadata['error'] = task.error
            
            c.execute("""
                INSERT INTO entities (case_id, entity_type, value, metadata) 
                VALUES (?, ?, ?, ?)
            """, (task.case_id, f'module_result_{task.module_id}', 
                  f'{task.module_id}: {task.target}', json.dumps(metadata)))
            
            conn.commit()
            conn.close()
    
    task_queue.on_result(on_task_complete)
    
    print("\n" + "="*70)
    print("🛡️  SENTINEL CORE - ELITE OSINT PLATFORM INITIALIZED")
    print("="*70)
    print(f"[*] Developer: Syed Abrar (Cyb3rvolt3x)")
    print(f"[*] Organization: SentinelReign.com")
    print(f"[*] Module execution engine: ACTIVE")
    print(f"[*] Task queue workers: 5 (parallel)")
    print(f"[*] Circuit breakers: ENABLED")
    print(f"[*] Dynamic script engine: READY (GOD MODE)")
    print(f"[*] Advanced tool integration: {len(tool_registry.tools)} TOOLS")
    print(f"[*] Report generator: HTML/STIX/JSON/PDF")
    print(f"[*] Available Kali tools: {', '.join(kali_tools.get_available_tools()) or 'None detected'}")
    print(f"[*] Registered modules: {len(registry.modules)}")
    print(f"[*] Script templates: {len(script_engine.builtin_templates)}")
    print("-"*70)
    print("📖 QUICK START:")
    print("   1. Access web UI: http://localhost:" + str(PORT))
    print("   2. Login: admin / admin123")
    print("   3. Create a case and run recon chains")
    print("   4. Execute custom scripts via API")
    print("   5. Generate Maltego-style reports")
    print("-"*70)
    print("⚡ API ENDPOINTS:")
    print("   POST /api/script/execute    - Run custom Python scripts")
    print("   POST /api/script/save       - Save custom scripts")
    print("   GET  /api/scripts/templates - List builtin templates")
    print("   POST /api/tool/execute      - Execute single tool")
    print("   POST /api/recon/full-chain  - Full recon automation")
    print("   GET  /api/report/generate   - Generate reports")
    print("   GET  /api/graph/visualize   - Graph visualization data")
    print("="*70)
    print("\n🌐 WATERMARK: SentinelReign.com | Dev: Syed Abrar (Cyb3rvolt3x)")
    print("="*70)
    print("\n[Server Running - Press Ctrl+C to Stop]\n")
    
    try:
        app.run(debug=False, host=HOST, port=PORT, threaded=True)
    except KeyboardInterrupt:
        print("\n\n[!] Shutting down ShadowEye...")
    finally:
        task_queue.stop_workers()
        print("[+] Workers stopped. Goodbye!")

if __name__ == '__main__':
    main()
