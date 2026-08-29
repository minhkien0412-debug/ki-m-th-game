"""
Code Analyst Module
Analyze source code if repository is available
"""

from typing import Dict, Any, List, Optional
from pathlib import Path
import re


class CodeAnalyst:
    """Analyze source code for security issues"""
    
    # Security-sensitive patterns
    SENSITIVE_PATTERNS = {
        'hardcoded_secrets': [
            r'(?i)(api[_-]?key|apikey)\s*=\s*[\'"][^\'"]+[\'"]',
            r'(?i)(password|passwd|pwd)\s*=\s*[\'"][^\'"]+[\'"]',
            r'(?i)(secret|secret[_-]?key)\s*=\s*[\'"][^\'"]+[\'"]',
            r'(?i)(token|auth[_-]?token)\s*=\s*[\'"][^\'"]+[\'"]',
        ],
        'sql_queries': [
            r'(?i)SELECT\s+.+\s+FROM\s+',
            r'(?i)INSERT\s+INTO\s+',
            r'(?i)UPDATE\s+.+\s+SET\s+',
            r'(?i)DELETE\s+FROM\s+',
        ],
        'file_operations': [
            r'(?i)fopen\s*\(',
            r'(?i)file_get_contents\s*\(',
            r'(?i)readFile\s*\(',
            r'(?i)writeFile\s*\(',
        ],
        'command_execution': [
            r'(?i)exec\s*\(',
            r'(?i)system\s*\(',
            r'(?i)shell_exec\s*\(',
            r'(?i)popen\s*\(',
        ],
        'crypto_weaknesses': [
            r'(?i)md5\s*\(',
            r'(?i)sha1\s*\(',
            r'(?i)des\s*\(',
            r'(?i)rand\s*\(\s*\)',
        ]
    }
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.workspace_dir = Path(config.get('state', {}).get('workspace', 'state/workspace'))
        self._ensure_workspace()
    
    def _ensure_workspace(self):
        """Ensure workspace directory exists"""
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze a single file for security issues"""
        results = {
            'file': file_path,
            'issues': [],
            'stats': {
                'lines': 0,
                'functions': 0,
                'classes': 0,
            }
        }
        
        path = Path(file_path)
        if not path.exists():
            return results
        
        try:
            content = path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return results
        
        lines = content.split('\n')
        results['stats']['lines'] = len(lines)
        
        # Count functions and classes
        results['stats']['functions'] = len(re.findall(r'\bdef\s+\w+|\bfunction\s+\w+', content))
        results['stats']['classes'] = len(re.findall(r'\bclass\s+\w+', content))
        
        # Search for sensitive patterns
        for category, patterns in self.SENSITIVE_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.MULTILINE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    results['issues'].append({
                        'category': category,
                        'pattern': pattern,
                        'line': line_num,
                        'snippet': match.group(0)[:100],
                        'severity': self._get_severity(category)
                    })
        
        return results
    
    def _get_severity(self, category: str) -> str:
        """Get severity level for issue category"""
        severity_map = {
            'hardcoded_secrets': 'high',
            'sql_queries': 'medium',
            'file_operations': 'medium',
            'command_execution': 'critical',
            'crypto_weaknesses': 'high',
        }
        return severity_map.get(category, 'info')
    
    def analyze_directory(self, dir_path: str, extensions: List[str] = None) -> Dict[str, Any]:
        """Analyze all files in a directory"""
        if extensions is None:
            extensions = ['.py', '.js', '.php', '.java', '.rb', '.go', '.c', '.cpp']
        
        results = {
            'directory': dir_path,
            'files_analyzed': 0,
            'total_issues': 0,
            'issues_by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'file_results': []
        }
        
        path = Path(dir_path)
        if not path.exists():
            return results
        
        for ext in extensions:
            for file_path in path.rglob(f'*{ext}'):
                file_result = self.analyze_file(str(file_path))
                if file_result['issues']:
                    results['files_analyzed'] += 1
                    results['total_issues'] += len(file_result['issues'])
                    
                    for issue in file_result['issues']:
                        severity = issue.get('severity', 'info')
                        results['issues_by_severity'][severity] += 1
                    
                    results['file_results'].append(file_result)
        
        return results
    
    def clone_repo(self, repo_url: str, target_dir: str) -> bool:
        """Clone a repository for analysis (if git is available)"""
        import subprocess
        
        try:
            result = subprocess.run(
                ['git', 'clone', '--depth', '1', repo_url, target_dir],
                capture_output=True,
                text=True,
                timeout=300
            )
            return result.returncode == 0
        except Exception:
            return False
