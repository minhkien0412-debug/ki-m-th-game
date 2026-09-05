"""
Canonicalizer Module
Normalize URLs, validate safe paths, and ensure consistent formatting
"""

import re
from urllib.parse import urlparse, urljoin, quote
from typing import Optional, List, Tuple


class Canonicalizer:
    """Normalize and validate URLs for safe testing"""
    
    def __init__(self, allowed_hosts: List[str], allowed_paths: List[str], blocked_paths: List[str]):
        self.allowed_hosts = allowed_hosts
        self.allowed_paths = allowed_paths
        self.blocked_paths = blocked_paths
    
    def normalize_url(self, url: str) -> str:
        """Normalize URL to canonical form"""
        parsed = urlparse(url)
        
        # Lowercase scheme and host
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or '').lower().rstrip('.')
        if not hostname:
            return ''
        try:
            port = parsed.port
        except ValueError:
            return ''
        netloc = f"[{hostname}]" if ':' in hostname else hostname
        if port:
            netloc = f"{netloc}:{port}"
        
        # Normalize path
        path = self._normalize_path(parsed.path)
        
        # Rebuild URL
        normalized = f"{scheme}://{netloc}{path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        if parsed.fragment:
            normalized += f"#{parsed.fragment}"
        
        return normalized
    
    def _normalize_path(self, path: str) -> str:
        """Normalize path by removing redundant slashes and resolving . and .."""
        # Remove multiple slashes
        path = re.sub(r'/+', '/', path)
        
        # Resolve relative path components
        segments = path.split('/')
        resolved = []
        for segment in segments:
            if segment == '..':
                if resolved and resolved[-1] != '':
                    resolved.pop()
            elif segment != '.':
                resolved.append(segment)
        
        normalized = '/'.join(resolved)
        if not normalized.startswith('/'):
            normalized = '/' + normalized
        
        return normalized
    
    def is_host_allowed(self, host: str) -> bool:
        """Check if host is in allowed list (supports wildcards)"""
        host = host.lower().rstrip('.')
        for allowed in self.allowed_hosts:
            allowed = allowed.lower().rstrip('.')
            if allowed.startswith('*.'):
                # Wildcard subdomain match
                base_domain = allowed[2:]
                if host.endswith('.' + base_domain) or host == base_domain:
                    return True
            elif host == allowed:
                return True
        return False
    
    def is_path_allowed(self, path: str) -> Tuple[bool, Optional[str]]:
        """
        Check if path is allowed
        Returns: (is_allowed, reason_if_blocked)
        """
        path = self._normalize_path(path)

        # Check blocked paths first
        for blocked in self.blocked_paths:
            if self._matches_blocked_pattern(path, blocked):
                return False, f"Path matches blocked pattern: {blocked}"

        # Check allowed paths
        if not self.allowed_paths:
            return True, None

        for allowed in self.allowed_paths:
            if self._match_path_pattern(path, allowed):
                return True, None

        return False, "Path not in allowed list"

    def _match_path_pattern(self, path: str, pattern: str) -> bool:
        """Match path against an allow pattern (supports trailing * wildcard)."""
        if pattern.endswith('*'):
            prefix = pattern[:-1]
            return path.startswith(prefix)
        return path == pattern

    @staticmethod
    def _matches_blocked_pattern(path: str, pattern: str) -> bool:
        """Match a path against a block pattern conservatively.

        A blocklist must not be trivially side-stepped, so matching is
        case-insensitive and a directory pattern such as ``/admin/*`` also
        blocks the bare ``/admin`` (and ``/admin/``), while still leaving
        unrelated siblings like ``/administrator`` allowed.
        """
        p = path.lower()
        pat = pattern.lower()
        if pat.endswith('/*'):
            base = pat[:-2]
            return p == base or p.startswith(base + '/')
        if pat.endswith('*'):
            return p.startswith(pat[:-1])
        return p == pat
    
    def validate_url(self, url: str) -> Tuple[bool, Optional[str]]:
        """
        Full URL validation
        Returns: (is_valid, error_message)
        """
        try:
            parsed = urlparse(url)
        except Exception as e:
            return False, f"Invalid URL format: {str(e)}"
        
        if not parsed.scheme or not parsed.hostname:
            return False, "URL missing scheme or host"

        if parsed.username is not None or parsed.password is not None:
            return False, "User information is not allowed in target URLs"

        try:
            parsed.port
        except ValueError:
            return False, "Invalid URL port"
        
        if parsed.scheme not in ['http', 'https']:
            return False, f"Unsupported scheme: {parsed.scheme}"
        
        # Check host
        hostname = parsed.hostname.lower().rstrip('.')
        if not self.is_host_allowed(hostname):
            return False, f"Host not allowed: {hostname}"
        
        # Check path
        path_allowed, reason = self.is_path_allowed(parsed.path)
        if not path_allowed:
            return False, reason
        
        return True, None
    
    def sanitize_parameter(self, value: str, param_name: str, blocked_params: List[str]) -> str:
        """Sanitize parameter value, redact if sensitive"""
        if param_name.lower() in [p.lower() for p in blocked_params]:
            return "[REDACTED]"
        return value
    
    def build_safe_url(self, base_url: str, relative_path: str) -> Optional[str]:
        """Build a safe URL from base and relative path"""
        try:
            full_url = urljoin(base_url, relative_path)
            is_valid, error = self.validate_url(full_url)
            if is_valid:
                return self.normalize_url(full_url)
            return None
        except Exception:
            return None
