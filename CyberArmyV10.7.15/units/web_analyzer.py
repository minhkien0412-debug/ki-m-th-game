"""
Web Analyzer Module
Analyze HTML, extract endpoints and forms
"""

from typing import Dict, Any, List, Optional, Set
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse


class WebAnalyzer:
    """Analyze web pages for security testing targets"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.analysis_config = config.get('analysis', {})
        self.extract_forms = self.analysis_config.get('extract_forms', True)
        self.extract_endpoints = self.analysis_config.get('extract_endpoints', True)
        
        # Patterns for finding URLs and endpoints
        self.url_pattern = re.compile(
            r'(?:href|src|action|data-url)=["\']([^"\']+?)["\']',
            re.IGNORECASE
        )
        self.js_url_pattern = re.compile(
            r'["\'](/[^"\']*?)[\"\']|url\([\'"]?([^\'")]+)[\'"]?\)',
            re.IGNORECASE
        )
    
    def analyze_html(self, html_content: str, base_url: str) -> Dict[str, Any]:
        """Analyze HTML content and extract information"""
        results = {
            'forms': [],
            'links': [],
            'scripts': [],
            'endpoints': set(),
            'inputs': [],
        }
        
        try:
            soup = BeautifulSoup(html_content, 'lxml')
        except Exception:
            return results
        
        # Extract forms
        if self.extract_forms:
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                # Get absolute URL for action
                if form_data['action']:
                    form_data['action'] = urljoin(base_url, form_data['action'])
                
                # Extract input fields
                for input_field in form.find_all(['input', 'select', 'textarea']):
                    input_info = {
                        'name': input_field.get('name', ''),
                        'type': input_field.get('type', 'text'),
                        'required': input_field.has_attr('required')
                    }
                    form_data['inputs'].append(input_info)
                
                results['forms'].append(form_data)
        
        # Extract links
        for link in soup.find_all('a', href=True):
            href = link.get('href', '')
            if href and not href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                full_url = urljoin(base_url, href)
                results['links'].append(full_url)
                results['endpoints'].add(full_url)
        
        # Extract scripts
        for script in soup.find_all('script', src=True):
            src = script.get('src', '')
            if src:
                full_url = urljoin(base_url, src)
                results['scripts'].append(full_url)
        
        # Extract inputs outside forms
        for input_field in soup.find_all('input'):
            input_info = {
                'name': input_field.get('name', ''),
                'type': input_field.get('type', 'text'),
                'form_action': None
            }
            # Try to find parent form
            parent_form = input_field.find_parent('form')
            if parent_form:
                action = parent_form.get('action', '')
                if action:
                    input_info['form_action'] = urljoin(base_url, action)
            
            results['inputs'].append(input_info)
        
        # Convert set to list for JSON serialization
        results['endpoints'] = list(results['endpoints'])
        
        return results
    
    def extract_endpoints_from_text(self, text: str, base_url: str) -> List[str]:
        """Extract potential endpoints from text/JS content"""
        endpoints = set()
        
        # Find URLs in text
        matches = self.js_url_pattern.findall(text)
        for match in matches:
            url = match[0] or match[1]
            if url and len(url) < 200:
                # Clean up the URL
                url = url.strip().rstrip(';,')
                if url.startswith('/'):
                    full_url = urljoin(base_url, url)
                    endpoints.add(full_url)
                elif url.startswith(('http://', 'https://')):
                    endpoints.add(url)
        
        return list(endpoints)
    
    def get_sensitive_paths(self, endpoints: List[str]) -> List[str]:
        """Identify potentially sensitive paths"""
        sensitive_patterns = [
            '/admin', '/api/', '/auth/', '/login', '/logout',
            '/register', '/password', '/reset', '/token',
            '/config', '/settings', '/profile', '/account',
            '/upload', '/download', '/file', '/export',
            '/debug', '/test', '/backup', '/.git', '/.env'
        ]
        
        sensitive = []
        for endpoint in endpoints:
            parsed = urlparse(endpoint)
            path = parsed.path.lower()
            
            for pattern in sensitive_patterns:
                if pattern in path:
                    sensitive.append(endpoint)
                    break
        
        return sensitive
