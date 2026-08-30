"""
Secret Redactor Module
Hide sensitive information in logs and evidence
"""

import re
from typing import List, Dict, Any, Optional


class SecretRedactor:
    """Redact sensitive information from logs and evidence"""
    
    # Patterns for common secrets
    PATTERNS = {
        'api_key': r'(?i)(?P<prefix>(?:api[_-]?key|apikey)\s*[:=]\s*[\'"]?)[a-zA-Z0-9_\-]{20,}[\'"]?',
        'password': r'(?i)(?P<prefix>(?:password|passwd|pwd)\s*[:=]\s*[\'"]?)[^\s\'"]+[\'"]?',
        'secret': r'(?i)(?P<prefix>(?:secret|secret[_-]?key)\s*[:=]\s*[\'"]?)[a-zA-Z0-9_\-]{16,}[\'"]?',
        'token': r'(?i)(?P<prefix>(?:token|auth[_-]?token|access[_-]?token)\s*[:=]\s*[\'"]?)[a-zA-Z0-9_\-\.]{20,}[\'"]?',
        'bearer': r'(?i)(?P<prefix>bearer\s+)[a-zA-Z0-9_\-\.]{20,}',
        'basic_auth': r'(?i)(?P<prefix>basic\s+)[a-zA-Z0-9+/=]{20,}',
        'jwt': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
        'private_key': r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA )?PRIVATE KEY-----',
        'github_token': r'gh[pousr]_[A-Za-z0-9_]{36,}',
        'aws_key': r'(?i)(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}',
        'aws_secret': r'(?i)(?P<prefix>aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*[\'"]?)[a-zA-Z0-9/+=]{40}[\'"]?',
        'credit_card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
    }
    
    def __init__(self, custom_patterns: Optional[Dict[str, str]] = None):
        self.patterns = {**self.PATTERNS}
        if custom_patterns:
            self.patterns.update(custom_patterns)
        
        # Compile regex patterns
        self.compiled_patterns = {}
        for name, pattern in self.patterns.items():
            try:
                self.compiled_patterns[name] = re.compile(pattern)
            except re.error:
                print(f"Warning: Invalid regex pattern for {name}")
    
    def redact(self, text: str, replacement: str = "[REDACTED]") -> str:
        """Redact all sensitive information from text"""
        result = text
        
        for name, regex in self.compiled_patterns.items():
            def replace_secret(match):
                prefix = match.groupdict().get('prefix')
                return f"{prefix}{replacement}" if prefix else replacement

            result = regex.sub(replace_secret, result)
        
        return result
    
    def redact_dict(self, data: Dict[str, Any], blocked_keys: Optional[List[str]] = None) -> Dict[str, Any]:
        """Redact sensitive information from dictionary"""
        if blocked_keys is None:
            blocked_keys = ['password', 'secret', 'token', 'key', 'auth', 'api_key', 'credential']
        
        result = {}
        for key, value in data.items():
            key_lower = key.lower()
            
            # Check if key matches blocked keys
            if any(blocked in key_lower for blocked in blocked_keys):
                result[key] = "[REDACTED]"
            elif isinstance(value, str):
                # Redact sensitive patterns in string values
                result[key] = self.redact(value)
            elif isinstance(value, dict):
                result[key] = self.redact_dict(value, blocked_keys)
            elif isinstance(value, list):
                result[key] = [
                    self.redact_dict(item, blocked_keys) if isinstance(item, dict)
                    else self.redact(item) if isinstance(item, str)
                    else item
                    for item in value
                ]
            else:
                result[key] = value
        
        return result
    
    def redact_url(self, url: str) -> str:
        """Redact sensitive query parameters from URL"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        blocked_params = ['password', 'secret', 'token', 'key', 'auth', 'api_key', 'credential']
        
        redacted_params = {}
        for param, values in query_params.items():
            if any(blocked in param.lower() for blocked in blocked_params):
                redacted_params[param] = ['[REDACTED]']
            else:
                redacted_params[param] = values
        
        # Rebuild URL with redacted params
        new_query = urlencode(redacted_params, doseq=True)
        new_parsed = parsed._replace(query=new_query)
        
        return urlunparse(new_parsed)
    
    def redact_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Redact sensitive HTTP headers"""
        sensitive_headers = [
            'authorization',
            'cookie',
            'set-cookie',
            'x-api-key',
            'x-auth-token',
            'proxy-authorization',
        ]
        
        result = {}
        for header, value in headers.items():
            if header.lower() in sensitive_headers:
                result[header] = "[REDACTED]"
            else:
                result[header] = value
        
        return result
    
    def redact_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive information from HTTP request data"""
        redacted = request_data.copy()
        
        # Redact URL
        if 'url' in redacted:
            redacted['url'] = self.redact_url(redacted['url'])
        
        # Redact headers
        if 'headers' in redacted:
            redacted['headers'] = self.redact_headers(redacted['headers'])
        
        # Redact body
        if 'body' in redacted and isinstance(redacted['body'], str):
            redacted['body'] = self.redact(redacted['body'])
        elif 'json' in redacted and isinstance(redacted['json'], dict):
            redacted['json'] = self.redact_dict(redacted['json'])
        
        return redacted
    
    def redact_response(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive information from HTTP response data"""
        redacted = response_data.copy()
        
        # Redact headers
        if 'headers' in redacted:
            redacted['headers'] = self.redact_headers(redacted['headers'])
        
        # Redact body
        if 'body' in redacted and isinstance(redacted['body'], str):
            redacted['body'] = self.redact(redacted['body'])
        elif 'json' in redacted and isinstance(redacted['json'], dict):
            redacted['json'] = self.redact_dict(redacted['json'])
        
        return redacted
