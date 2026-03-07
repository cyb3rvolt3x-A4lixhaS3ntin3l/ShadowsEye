"""
Script Engine - Dynamic script execution for custom tools
Supports Bash, Python, PHP, NodeJS with sandboxing
"""

import subprocess
import tempfile
import os
import json
from datetime import datetime
from typing import Dict, Any, Optional, List


class ScriptEngine:
    """Execute custom scripts safely with output capture"""
    
    ALLOWED_COMMANDS = [
        'nmap', 'dig', 'whois', 'nslookup', 'host', 'ping', 'traceroute',
        'curl', 'wget', 'grep', 'awk', 'sed', 'cat', 'head', 'tail',
        'sort', 'uniq', 'wc', 'find', 'ls', 'stat', 'file', 'strings',
        'python3', 'php', 'node', 'bash', 'sh', 'echo', 'printf'
    ]
    
    def __init__(self, working_dir: str = None, timeout: int = 60):
        self.working_dir = working_dir or tempfile.gettempdir()
        self.default_timeout = timeout
        self.execution_history: List[Dict] = []
        
    def execute(self, 
                command: str, 
                language: str = 'bash',
                input_data: str = None,
                timeout: int = None,
                env_vars: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Execute a command/script
        
        Args:
            command: Command or script to execute
            language: Script language (bash, python, php, nodejs)
            input_data: Optional stdin input
            timeout: Execution timeout in seconds
            env_vars: Environment variables to set
            
        Returns:
            Dictionary with stdout, stderr, return_code, execution_time
        """
        result = {
            'command': command,
            'language': language,
            'status': 'pending',
            'stdout': '',
            'stderr': '',
            'return_code': None,
            'execution_time': 0,
            'started_at': datetime.utcnow().isoformat(),
            'completed_at': None,
            'error': None
        }
        
        timeout = timeout or self.default_timeout
        
        try:
            # Validate command
            if not self._validate_command(command, language):
                result['error'] = 'Command contains disallowed operations'
                result['status'] = 'blocked'
                return result
            
            # Prepare execution
            if language == 'bash':
                cmd = ['bash', '-c', command]
            elif language == 'python':
                cmd = ['python3', '-c', command]
            elif language == 'php':
                cmd = ['php', '-r', command]
            elif language == 'nodejs':
                cmd = ['node', '-e', command]
            else:
                result['error'] = f'Unsupported language: {language}'
                result['status'] = 'failed'
                return result
            
            # Set up environment
            env = os.environ.copy()
            if env_vars:
                env.update(env_vars)
            
            # Execute
            start_time = datetime.utcnow()
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE if input_data else None,
                cwd=self.working_dir,
                env=env,
                text=True
            )
            
            try:
                stdout, stderr = process.communicate(
                    input=input_data,
                    timeout=timeout
                )
                
                end_time = datetime.utcnow()
                
                result['status'] = 'completed'
                result['stdout'] = stdout
                result['stderr'] = stderr
                result['return_code'] = process.returncode
                result['execution_time'] = (end_time - start_time).total_seconds()
                result['completed_at'] = end_time.isoformat()
                
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                
                result['status'] = 'timeout'
                result['stdout'] = stdout
                result['stderr'] = stderr
                result['error'] = f'Execution timed out after {timeout}s'
                result['completed_at'] = datetime.utcnow().isoformat()
                
        except Exception as e:
            result['status'] = 'failed'
            result['error'] = str(e)
            result['completed_at'] = datetime.utcnow().isoformat()
        
        # Store in history
        self.execution_history.append(result)
        if len(self.execution_history) > 100:
            self.execution_history = self.execution_history[-100:]
        
        return result
    
    def _validate_command(self, command: str, language: str) -> bool:
        """Validate command against security policy"""
        # Check for dangerous patterns
        dangerous_patterns = [
            'rm -rf /', 'mkfs', 'dd if=/dev/zero', ':(){ :|:& };:',
            'chmod 777 /', 'chown -R', 'sudo', 'su ', '> /dev/',
            '/etc/passwd', '/etc/shadow', 'eval(', 'exec(',
            '__import__', 'os.system', 'subprocess.call'
        ]
        
        command_lower = command.lower()
        for pattern in dangerous_patterns:
            if pattern in command_lower:
                return False
        
        # For bash, check first command
        if language == 'bash':
            first_word = command.split()[0] if command.split() else ''
            if first_word not in self.ALLOWED_COMMANDS:
                # Allow paths to scripts in allowed directories
                if not (first_word.startswith('./') or first_word.startswith('/tmp/')):
                    return False
        
        return True
    
    def execute_script_file(self, 
                           file_path: str, 
                           args: List[str] = None,
                           timeout: int = None) -> Dict[str, Any]:
        """Execute a script file"""
        if not os.path.exists(file_path):
            return {
                'status': 'failed',
                'error': f'Script file not found: {file_path}'
            }
        
        # Determine language from extension
        ext_map = {
            '.sh': 'bash',
            '.py': 'python',
            '.php': 'php',
            '.js': 'nodejs'
        }
        
        ext = os.path.splitext(file_path)[1].lower()
        language = ext_map.get(ext, 'bash')
        
        cmd = [file_path] + (args or [])
        
        return self.execute(
            ' '.join(cmd),
            language=language,
            timeout=timeout
        )
    
    def create_temp_script(self, content: str, language: str = 'bash') -> str:
        """Create a temporary script file"""
        ext_map = {'bash': '.sh', 'python': '.py', 'php': '.php', 'nodejs': '.js'}
        ext = ext_map.get(language, '.sh')
        
        fd, path = tempfile.mkstemp(suffix=ext, dir=self.working_dir)
        try:
            with os.fdopen(fd, 'w') as f:
                if language == 'bash':
                    f.write('#!/bin/bash\n')
                elif language == 'python':
                    f.write('#!/usr/bin/env python3\n')
                elif language == 'php':
                    f.write('<?php\n')
                f.write(content)
            os.chmod(path, 0o755)
        except Exception:
            os.unlink(path)
            raise
        
        return path
    
    def get_execution_history(self, limit: int = 10) -> List[Dict]:
        """Get recent execution history"""
        return self.execution_history[-limit:]
    
    def clear_history(self):
        """Clear execution history"""
        self.execution_history = []


# Global script engine instance
global_script_engine = ScriptEngine()


def run_command(command: str, language: str = 'bash', **kwargs) -> Dict:
    """Helper to run a command"""
    return global_script_engine.execute(command, language, **kwargs)
