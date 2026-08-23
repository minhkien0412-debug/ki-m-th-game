"""Reflection Validator - Checks for reflected input (SAFE)"""
from typing import Dict, Any
from .base import BaseValidator


class ReflectionValidator(BaseValidator):
    """Check for reflected input safely"""
    
    name = "reflection"
    description = "Checks if user input is reflected in response (passive only)"
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.test_payloads = [
            "<CyberArmyTest123>",
            "CyberArmyXSS456",
        ]
    
    def is_safe(self) -> bool:
        """This validator is SAFE - only passive checking"""
        return True
    
    def validate(self, context: Any) -> Dict[str, Any]:
        """
        Check if any previously injected test payloads are reflected
        This is PASSIVE - we only check existing responses
        """
        findings = []
        
        # In a real implementation, this would check stored responses
        # for reflections of known test payloads
        
        return {
            'findings': findings,
            'metadata': {
                'checked': len(findings),
                'payloads_tested': 0  # Passive, no new requests
            }
        }
