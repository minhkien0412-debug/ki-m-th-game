"""Manual Review Validator"""
from typing import Dict, Any
from .base import BaseValidator


class ManualReviewValidator(BaseValidator):
    """Flag items for manual review"""
    
    name = "manual_review"
    description = "Flags potentially interesting items for human review"
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
    
    def is_safe(self) -> bool:
        """This validator is SAFE - only creates candidates"""
        return True
    
    def validate(self, context: Any) -> Dict[str, Any]:
        """
        Create candidates for manual review based on observations
        """
        findings = []
        
        # Would flag:
        # - Unusual response codes
        # - Interesting endpoints
        # - Potential hidden functionality
        
        return {
            'findings': findings,
            'metadata': {
                'items_flagged': len(findings)
            }
        }
