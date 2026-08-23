"""
Target Request Gate Module
Safe request gateway with multiple security checks
"""

import requests
from typing import Dict, Any, Optional, Tuple
from .dns_ip_gate import DNSIPGate
from .canonicalizer import Canonicalizer
from .secret_redactor import SecretRedactor


class TargetRequestGate:
    """Safety gate for making HTTP requests to targets"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.rate_limit = config.get('rate_limit', {})
        target_config = config.get('target', {})
        
        # Initialize safety components
        self.dns_gate = DNSIPGate()
        self.canonicalizer = Canonicalizer(
            allowed_hosts=target_config.get('allowed_hosts', []),
            allowed_paths=target_config.get('allowed_paths', []),
            blocked_paths=target_config.get('blocked_paths', [])
        )
        self.redactor = SecretRedactor()
        
        # Session for connection pooling
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberArmy-Security-Scanner/10.7.15 (Authorized Testing)'
        })
    
    def validate_before_request(self, url: str) -> Tuple[bool, Optional[str]]:
        """Validate URL before making request"""
        # Check scope
        is_valid, error = self.canonicalizer.validate_url(url)
        if not is_valid:
            return False, f"Scope violation: {error}"
        
        # Check DNS/IP safety
        is_safe, error = self.dns_gate.validate_url(url)
        if not is_safe:
            return False, f"DNS/IP safety check failed: {error}"
        
        return True, None
    
    def make_request(self, url: str, method: str = 'GET', 
                    headers: Optional[Dict[str, str]] = None,
                    params: Optional[Dict[str, Any]] = None,
                    data: Optional[Any] = None,
                    timeout: int = 30,
                    allow_redirects: bool = True) -> Optional[requests.Response]:
        """Make a safe HTTP request through the gate"""
        
        # Pre-request validation
        is_valid, error = self.validate_before_request(url)
        if not is_valid:
            print(f"[GATE BLOCKED] {error}")
            return None
        
        # Normalize URL
        url = self.canonicalizer.normalize_url(url)
        
        # Prepare headers (redact sensitive info)
        safe_headers = headers or {}
        safe_headers = self.redactor.redact_headers(safe_headers)
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=safe_headers,
                params=params,
                data=data,
                timeout=timeout,
                allow_redirects=allow_redirects
            )
            return response
        except requests.exceptions.RequestException as e:
            print(f"[REQUEST ERROR] {str(e)}")
            return None
        except Exception as e:
            print(f"[UNEXPECTED ERROR] {str(e)}")
            return None
    
    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Safe GET request"""
        return self.make_request(url, method='GET', **kwargs)
    
    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Safe POST request"""
        return self.make_request(url, method='POST', **kwargs)
    
    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Safe HEAD request"""
        return self.make_request(url, method='HEAD', **kwargs)
    
    def options(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Safe OPTIONS request"""
        return self.make_request(url, method='OPTIONS', **kwargs)
    
    def close(self):
        """Close the session"""
        self.session.close()
