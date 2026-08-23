"""Base Validator Module"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class BaseValidator(ABC):
    """Base class for all validators"""
    
    name = "base"
    description = "Base validator"
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    @abstractmethod
    def validate(self, context: Any) -> Dict[str, Any]:
        """Perform validation and return results"""
        pass
    
    def is_safe(self) -> bool:
        """Indicate if this validator is safe to run automatically"""
        return True
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get validator metadata"""
        return {
            'name': self.name,
            'description': self.description,
            'is_safe': self.is_safe()
        }
