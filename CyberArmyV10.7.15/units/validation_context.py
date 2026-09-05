"""
Validation Context Module
Context for validators to send requests safely
"""

from typing import Dict, Any, List, Optional


class ValidationContext:
    """Context object for safe validation operations"""
    
    def __init__(self, mission_id: str, config: Dict[str, Any]):
        self.mission_id = mission_id
        self.config = config
        self.data: Dict[str, Any] = {}
        self.requests_made: int = 0
        self.max_requests: int = config.get('rate_limit', {}).get('requests_per_minute', 100)
        # Passive validators analyze evidence that was already collected. These
        # hold the observed HTTP exchanges and any test markers the tool itself
        # injected earlier, so no validator ever needs to generate new traffic.
        self.responses: List[Dict[str, Any]] = []
        self.sent_markers: List[str] = []

    def add_response(self, record: Dict[str, Any]):
        """Record one already-collected HTTP exchange for passive analysis.

        Expected keys (all optional except ``url``): ``url``, ``method``,
        ``status`` (int), ``request_headers`` (dict), ``response_headers``
        (dict), ``body`` (str).
        """
        if isinstance(record, dict) and record.get('url'):
            self.responses.append(record)

    def add_responses(self, records: Any):
        """Record several collected exchanges at once."""
        for record in records or []:
            self.add_response(record)

    def mark_sent(self, marker: str):
        """Remember a test marker the tool injected, for reflection analysis."""
        if marker and marker not in self.sent_markers:
            self.sent_markers.append(marker)

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
