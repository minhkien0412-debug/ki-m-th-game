"""
Scope Engine Module
Define and validate target scope (hosts, paths, parameters)
"""

from typing import List, Dict, Any, Tuple, Optional, Set
import fnmatch
from urllib.parse import urlparse


class ScopeEngine:
    """Manage and validate target scope"""
    
    def __init__(self, config: Dict[str, Any]):
        self.target_config = config.get('target', {})
        self.allowed_hosts: List[str] = self.target_config.get('allowed_hosts', [])
        self.allowed_paths: List[str] = self.target_config.get('allowed_paths', [])
        self.blocked_paths: List[str] = self.target_config.get('blocked_paths', [])
        self.blocked_parameters: List[str] = self.target_config.get('blocked_parameters', [])
        self.base_url: str = self.target_config.get('base_url', '')
    
    def is_host_in_scope(self, host: str) -> bool:
        """Check if host is within allowed scope"""
        host = host.lower().split(':')[0]  # Remove port
        
        for allowed in self.allowed_hosts:
            allowed = allowed.lower()
            
            # Exact match
            if host == allowed:
                return True
            
            # Wildcard subdomain match (*.example.com)
            if allowed.startswith('*.'):
                base_domain = allowed[2:]
                if host.endswith('.' + base_domain) or host == base_domain:
                    return True
            
            # Glob pattern match
            if fnmatch.fnmatch(host, allowed):
                return True
        
        return False
    
    def is_path_in_scope(self, path: str) -> Tuple[bool, Optional[str]]:
        """
        Check if path is within allowed scope
        Returns: (is_allowed, reason_if_blocked)
        """
        if not path.startswith('/'):
            path = '/' + path
        
        # Check blocked paths first
        for blocked in self.blocked_paths:
            if self._match_pattern(path, blocked):
                return False, f"Path matches blocked pattern: {blocked}"
        
        # If no allowed_paths defined, all non-blocked paths are allowed
        if not self.allowed_paths:
            return True, None
        
        # Check if path matches any allowed pattern
        for allowed in self.allowed_paths:
            if self._match_pattern(path, allowed):
                return True, None
        
        return False, "Path not in allowed list"
    
    def _match_pattern(self, path: str, pattern: str) -> bool:
        """Match path against pattern (supports * wildcard)"""
        if pattern.endswith('*'):
            prefix = pattern[:-1]
            return path.startswith(prefix)
        elif pattern.startswith('*'):
            suffix = pattern[1:]
            return path.endswith(suffix)
        else:
            return path == pattern
    
    def is_parameter_allowed(self, param_name: str) -> bool:
        """Check if parameter is allowed (not in blocked list)"""
        param_lower = param_name.lower()
        for blocked in self.blocked_parameters:
            if blocked.lower() in param_lower:
                return False
        return True
    
    def is_url_in_scope(self, url: str) -> Tuple[bool, Optional[str]]:
        """
        Full URL scope validation
        Returns: (is_in_scope, reason_if_not)
        """
        try:
            parsed = urlparse(url)
        except Exception as e:
            return False, f"Invalid URL: {str(e)}"
        
        # Check scheme
        if parsed.scheme not in ['http', 'https']:
            return False, f"Unsupported scheme: {parsed.scheme}"
        
        # Check host
        if not self.is_host_in_scope(parsed.netloc):
            return False, f"Host out of scope: {parsed.netloc}"
        
        # Check path
        path_allowed, reason = self.is_path_in_scope(parsed.path)
        if not path_allowed:
            return False, reason
        
        return True, None
    
    def get_scope_summary(self) -> Dict[str, Any]:
        """Get summary of current scope configuration"""
        return {
            'base_url': self.base_url,
            'allowed_hosts_count': len(self.allowed_hosts),
            'allowed_hosts': self.allowed_hosts,
            'allowed_paths_count': len(self.allowed_paths),
            'allowed_paths': self.allowed_paths,
            'blocked_paths_count': len(self.blocked_paths),
            'blocked_paths': self.blocked_paths,
            'blocked_parameters_count': len(self.blocked_parameters),
            'blocked_parameters': self.blocked_parameters,
        }
    
    def normalize_url(self, url: str) -> str:
        """Normalize URL for consistent comparison"""
        parsed = urlparse(url)
        
        # Lowercase scheme and host
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        
        # Normalize path
        path = parsed.path
        if not path:
            path = '/'
        
        # Remove trailing slashes except for root
        while path != '/' and path.endswith('/'):
            path = path[:-1]
        
        # Rebuild URL
        normalized = f"{scheme}://{netloc}{path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        
        return normalized
    
    def extract_base_domain(self, host: str) -> str:
        """Extract base domain from host (removes subdomains)"""
        host = host.split(':')[0]  # Remove port
        parts = host.split('.')
        
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return host
    
    def is_subdomain_of(self, host: str, domain: str) -> bool:
        """Check if host is a subdomain of domain"""
        host = host.lower().split(':')[0]
        domain = domain.lower()
        
        if host == domain:
            return True
        
        if host.endswith('.' + domain):
            return True
        
        return False
