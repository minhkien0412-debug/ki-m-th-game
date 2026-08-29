"""
Config Validator Module
Validate YAML configuration files
"""

import yaml
from typing import Dict, Any, List, Tuple, Optional
from pathlib import Path


class ConfigValidator:
    """Validate CyberArmy configuration files"""
    
    REQUIRED_SECTIONS = ['target', 'policy', 'rate_limit']
    
    TARGET_FIELDS = {
        'name': str,
        'base_url': str,
        'allowed_hosts': list,
    }
    
    POLICY_FIELDS = {
        'raw_file': str,
        'manifest_file': str,
        'required_hash': str,
        'acknowledged': bool,
    }
    
    RATE_LIMIT_FIELDS = {
        'requests_per_second': (int, float),
        'requests_per_minute': (int, float),
    }
    
    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []
    
    def validate_file(self, config_path: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Validate configuration file and return parsed config"""
        self.errors = []
        self.warnings = []
        
        path = Path(config_path)
        if not path.exists():
            self.errors.append(f"Configuration file not found: {config_path}")
            return False, None
        
        try:
            with open(path, 'r') as f:
                config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            self.errors.append(f"YAML parsing error: {str(e)}")
            return False, None
        except Exception as e:
            self.errors.append(f"Error reading config file: {str(e)}")
            return False, None
        
        if not isinstance(config, dict):
            self.errors.append("Configuration must be a YAML dictionary")
            return False, None
        
        # Validate structure
        is_valid = self.validate_structure(config)
        
        if is_valid:
            return True, config
        else:
            return False, None
    
    def validate_structure(self, config: Dict[str, Any]) -> bool:
        """Validate configuration structure"""
        # Check required sections
        for section in self.REQUIRED_SECTIONS:
            if section not in config:
                self.errors.append(f"Missing required section: {section}")
        
        if self.errors:
            return False
        
        # Validate target section
        if 'target' in config:
            self._validate_section(config['target'], self.TARGET_FIELDS, 'target')
        
        # Validate policy section
        if 'policy' in config:
            self._validate_section(config['policy'], self.POLICY_FIELDS, 'policy')
        
        # Validate rate_limit section
        if 'rate_limit' in config:
            self._validate_section(config['rate_limit'], self.RATE_LIMIT_FIELDS, 'rate_limit')
        
        # Additional validations
        self._validate_urls(config)
        self._validate_paths(config)
        
        return len(self.errors) == 0
    
    def _validate_section(self, section: Dict[str, Any], fields: Dict[str, Any], section_name: str):
        """Validate a configuration section"""
        for field, expected_type in fields.items():
            if field not in section:
                self.warnings.append(f"Missing optional field in {section_name}: {field}")
                continue
            
            value = section[field]
            if not isinstance(value, expected_type):
                self.errors.append(
                    f"Invalid type for {section_name}.{field}: expected {expected_type}, got {type(value)}"
                )
    
    def _validate_urls(self, config: Dict[str, Any]):
        """Validate URL formats"""
        from urllib.parse import urlparse
        
        if 'target' in config and 'base_url' in config['target']:
            url = config['target']['base_url']
            try:
                parsed = urlparse(url)
                if parsed.scheme not in ['http', 'https']:
                    self.errors.append(f"Invalid scheme in base_url: {url}")
                if not parsed.netloc:
                    self.errors.append(f"Invalid base_url (missing host): {url}")
            except Exception as e:
                self.errors.append(f"Invalid base_url format: {url} - {str(e)}")
    
    def _validate_paths(self, config: Dict[str, Any]):
        """Validate that referenced files exist"""
        if 'policy' in config:
            policy = config['policy']
            
            # Check raw_file exists
            if 'raw_file' in policy:
                raw_path = Path(policy['raw_file'])
                if not raw_path.exists():
                    self.warnings.append(f"Policy raw file not found: {raw_path}")
            
            # Check manifest_file exists
            if 'manifest_file' in policy:
                manifest_path = Path(policy['manifest_file'])
                if not manifest_path.exists():
                    self.warnings.append(f"Policy manifest file not found: {manifest_path}")
    
    def validate_acknowledgment(self, config: Dict[str, Any]) -> bool:
        """Check if policy has been acknowledged"""
        if 'policy' not in config:
            return False
        
        return config['policy'].get('acknowledged', False)
    
    def check_kill_switch(self, config: Dict[str, Any]) -> bool:
        """Check if kill switch is enabled"""
        if 'policy' not in config:
            return True  # Default to safe state
        
        return config['policy'].get('kill_switch_enabled', True)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get validation summary"""
        return {
            'valid': len(self.errors) == 0,
            'error_count': len(self.errors),
            'warning_count': len(self.warnings),
            'errors': self.errors,
            'warnings': self.warnings,
        }
