"""
API Analyzer Module
Classify endpoints into labels (REST, GraphQL, etc.)
"""

from typing import Dict, Any, List, Optional
from urllib.parse import urlparse


class APIAnalyzer:
    """Analyze and classify API endpoints"""
    
    # Common API patterns
    REST_PATTERNS = ['/api/', '/v1/', '/v2/', '/rest/']
    GRAPHQL_PATTERNS = ['/graphql', '/graph', '/query']
    RPC_PATTERNS = ['/rpc/', '/method/', '/call/']
    WEBSOCKET_PATTERNS = ['/ws/', '/socket/', '/realtime/']
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    def classify_endpoint(self, url: str) -> Dict[str, Any]:
        """Classify an endpoint by type"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        classification = {
            'url': url,
            'type': 'unknown',
            'labels': [],
            'confidence': 0.0
        }
        
        # Check for REST API
        for pattern in self.REST_PATTERNS:
            if pattern in path:
                classification['type'] = 'REST'
                classification['labels'].append('rest-api')
                classification['confidence'] = 0.8
                break
        
        # Check for GraphQL
        for pattern in self.GRAPHQL_PATTERNS:
            if pattern in path:
                classification['type'] = 'GraphQL'
                classification['labels'].append('graphql')
                classification['confidence'] = 0.9
                break
        
        # Check for RPC
        for pattern in self.RPC_PATTERNS:
            if pattern in path:
                classification['type'] = 'RPC'
                classification['labels'].append('rpc')
                classification['confidence'] = 0.7
                break
        
        # Check for WebSocket
        for pattern in self.WEBSOCKET_PATTERNS:
            if pattern in path:
                classification['labels'].append('websocket')
                classification['confidence'] = max(classification['confidence'], 0.7)
        
        # Add additional labels based on path content
        if '/auth/' in path or '/login' in path or '/token' in path:
            classification['labels'].append('authentication')
        
        if '/user/' in path or '/profile' in path or '/account' in path:
            classification['labels'].append('user-management')
        
        if '/admin/' in path or '/manage/' in path:
            classification['labels'].append('admin')
        
        if '/upload' in path or '/file' in path:
            classification['labels'].append('file-handling')
        
        if '/payment' in path or '/checkout' in path or '/order' in path:
            classification['labels'].append('financial')
        
        return classification
    
    def analyze_endpoints(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Analyze multiple endpoints"""
        results = []
        for url in urls:
            result = self.classify_endpoint(url)
            results.append(result)
        return results
    
    def get_endpoints_by_label(self, analyzed_endpoints: List[Dict[str, Any]], 
                               label: str) -> List[str]:
        """Filter endpoints by label"""
        matching = []
        for endpoint in analyzed_endpoints:
            if label in endpoint.get('labels', []):
                matching.append(endpoint['url'])
        return matching
    
    def get_risky_endpoints(self, analyzed_endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify potentially risky endpoints"""
        risky_labels = ['admin', 'authentication', 'file-handling', 'financial']
        risky = []
        
        for endpoint in analyzed_endpoints:
            endpoint_labels = endpoint.get('labels', [])
            if any(label in endpoint_labels for label in risky_labels):
                risky.append(endpoint)
        
        return risky
