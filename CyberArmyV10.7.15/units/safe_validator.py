"""
Safe Validator Module
Registry of safe validators with contract enforcement
"""

from typing import Dict, Any, List, Optional, Type
from .validators.base import BaseValidator


class SafeValidator:
    """Registry and manager for safe validators"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.validators: Dict[str, BaseValidator] = {}
        self.validation_config = config.get('validation', {})
        self.safe_only = self.validation_config.get('safe_validators_only', True)
    
    def register_validator(self, name: str, validator: BaseValidator):
        """Register a validator"""
        if self.safe_only and not validator.is_safe():
            print(f"[VALIDATOR] Skipping unsafe validator: {name}")
            return
        
        self.validators[name] = validator
        print(f"[VALIDATOR] Registered: {name} (safe={validator.is_safe()})")
    
    def get_validator(self, name: str) -> Optional[BaseValidator]:
        """Get a registered validator by name"""
        return self.validators.get(name)
    
    def get_all_validators(self) -> List[str]:
        """Get list of all registered validator names"""
        return list(self.validators.keys())
    
    def run_validation(self, validator_name: str, context: Any) -> Dict[str, Any]:
        """Run a specific validator"""
        validator = self.get_validator(validator_name)
        if not validator:
            return {
                'success': False,
                'error': f'Validator not found: {validator_name}',
                'findings': []
            }
        
        try:
            result = validator.validate(context)
            return {
                'success': True,
                'validator': validator_name,
                'findings': result.get('findings', []),
                'metadata': result.get('metadata', {})
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'findings': []
            }
    
    def run_all_validators(self, context: Any) -> List[Dict[str, Any]]:
        """Run all registered validators"""
        results = []
        for name in self.validators:
            result = self.run_validation(name, context)
            results.append(result)
        return results
