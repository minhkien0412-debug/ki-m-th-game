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
        host = host.lower().rstrip('.')
        
        for allowed in self.allowed_hosts:
            allowed = allowed.lower().rstrip('.')
            
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
            if self._matches_blocked_pattern(path, blocked):
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
        """Match path against an allow pattern (supports * wildcard)"""
        if pattern.endswith('*'):
            prefix = pattern[:-1]
            return path.startswith(prefix)
        elif pattern.startswith('*'):
            suffix = pattern[1:]
            return path.endswith(suffix)
        else:
            return path == pattern

    @staticmethod
    def _matches_blocked_pattern(path: str, pattern: str) -> bool:
        """Match a path against a block pattern conservatively.

        Case-insensitive, and a directory pattern like ``/admin/*`` also blocks
        the bare ``/admin`` and ``/admin/`` so the blocklist cannot be dodged
        with a missing slash or a change of case.
        """
        p = path.lower()
        pat = pattern.lower()
        if pat.endswith('/*'):
            base = pat[:-2]
            return p == base or p.startswith(base + '/')
        if pat.endswith('*'):
            return p.startswith(pat[:-1])
        if pat.startswith('*'):
            return p.endswith(pat[1:])
        return p == pat
    
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
        if parsed.username is not None or parsed.password is not None:
            return False, "User information is not allowed in target URLs"

        hostname = (parsed.hostname or '').lower().rstrip('.')
        if not hostname or not self.is_host_in_scope(hostname):
            return False, f"Host out of scope: {hostname or parsed.netloc}"
        
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
        """Normalize URL for consistent comparison.

        Delegates to :class:`Canonicalizer` so scope comparison and the request
        gate share one normalization implementation (correct IPv6 bracketing,
        port handling, and ``.``/``..`` resolution) instead of drifting apart.
        """
        from .canonicalizer import Canonicalizer

        return Canonicalizer(
            self.allowed_hosts, self.allowed_paths, self.blocked_paths
        ).normalize_url(url)

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
