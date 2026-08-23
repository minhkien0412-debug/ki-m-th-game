"""
Candidate Rules Engine Module
Generate candidates from observations
"""

from typing import Dict, Any, List, Optional


class CandidateRulesEngine:
    """Generate testing candidates from observations"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    def generate_candidates(self, observations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate candidates from collected observations"""
        candidates = []
        
        for obs in observations:
            # Generate candidates based on observation type
            if obs.get('type') == 'endpoint':
                candidates.extend(self._endpoint_candidates(obs))
            elif obs.get('type') == 'form':
                candidates.extend(self._form_candidates(obs))
            elif obs.get('type') == 'api':
                candidates.extend(self._api_candidates(obs))
        
        return candidates
    
    def _endpoint_candidates(self, observation: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate candidates from endpoint observation"""
        candidates = []
        url = observation.get('url', '')
        
        # Candidate: Check for authentication requirement
        candidates.append({
            'type': 'auth_check',
            'target': url,
            'priority': 'medium',
            'description': 'Check if endpoint requires authentication'
        })
        
        # Candidate: Check for sensitive data exposure
        if any(s in url.lower() for s in ['/user/', '/profile/', '/account/']):
            candidates.append({
                'type': 'data_exposure',
                'target': url,
                'priority': 'high',
                'description': 'Check for sensitive data exposure'
            })
        
        return candidates
    
    def _form_candidates(self, observation: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate candidates from form observation"""
        candidates = []
        form = observation.get('form', {})
        
        # Candidate: Input validation check
        inputs = form.get('inputs', [])
        for input_field in inputs:
            if input_field.get('type') in ['text', 'password', 'email']:
                candidates.append({
                    'type': 'input_validation',
                    'target': form.get('action', ''),
                    'field': input_field.get('name', ''),
                    'priority': 'medium',
                    'description': f"Validate input handling for field: {input_field.get('name', '')}"
                })
        
        return candidates
    
    def _api_candidates(self, observation: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate candidates from API observation"""
        candidates = []
        api_info = observation.get('api', {})
        
        # Candidate: API version check
        if '/v1/' in observation.get('url', ''):
            candidates.append({
                'type': 'api_version',
                'target': observation.get('url', ''),
                'priority': 'low',
                'description': 'Check for newer API versions'
            })
        
        # Candidate: Rate limiting check
        candidates.append({
            'type': 'rate_limit',
            'target': observation.get('url', ''),
            'priority': 'medium',
            'description': 'Check for rate limiting implementation'
        })
        
        return candidates
    
    def prioritize_candidates(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort candidates by priority"""
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        return sorted(candidates, key=lambda x: priority_order.get(x.get('priority', 'low'), 4))
