"""
Validation Context Module
Context for validators to send requests safely
"""

from typing import Dict, Any, Optional


class ValidationContext:
    """Context object for safe validation operations"""
    
    def __init__(self, mission_id: str, config: Dict[str, Any]):
        self.mission_id = mission_id
        self.config = config
        self.data: Dict[str, Any] = {}
        self.requests_made: int = 0
        self.max_requests: int = config.get('rate_limit', {}).get('requests_per_minute', 100)
    
    def set(self, key: str, value: Any):
        """Set context data"""
        self.data[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get context data"""
        return self.data.get(key, default)
    
    def can_make_request(self) -> bool:
        """Check if we can make another request (respect rate limits)"""
        return self.requests_made < self.max_requests
    
    def record_request(self):
        """Record that a request was made"""
        self.requests_made += 1
    
    def get_summary(self) -> Dict[str, Any]:
        """Get context summary"""
        return {
            'mission_id': self.mission_id,
            'data_keys': list(self.data.keys()),
            'requests_made': self.requests_made,
            'max_requests': self.max_requests,
            'can_continue': self.can_make_request()
        }
