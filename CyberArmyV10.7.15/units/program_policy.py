"""
Program Policy Module
Verify raw/manifest/hash and authorization gate
"""

import json
import hashlib
from typing import Dict, Any, Optional, Tuple
from pathlib import Path


class ProgramPolicy:
    """Authorization gate for program policy verification"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.policy_config = config.get('policy', {})
        self.raw_file = self.policy_config.get('raw_file', '')
        self.manifest_file = self.policy_config.get('manifest_file', '')
        self.required_hash = self.policy_config.get('required_hash', '')
        self.acknowledged = self.policy_config.get('acknowledged', False)
        self.kill_switch_enabled = self.policy_config.get('kill_switch_enabled', True)
        
        self._raw_policy: Optional[Dict[str, Any]] = None
        self._manifest: Optional[Dict[str, Any]] = None
        self._verification_cache: Dict[str, Any] = {}
    
    def load_raw_policy(self) -> Tuple[bool, Optional[str]]:
        """Load raw policy file"""
        if self._raw_policy:
            return True, None
        
        raw_path = Path(self.raw_file)
        if not raw_path.exists():
            return False, f"Raw policy file not found: {self.raw_file}"
        
        try:
            with open(raw_path, 'r') as f:
                self._raw_policy = json.load(f)
            return True, None
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON in raw policy: {str(e)}"
        except Exception as e:
            return False, f"Error loading raw policy: {str(e)}"
    
    def load_manifest(self) -> Tuple[bool, Optional[str]]:
        """Load manifest file"""
        if self._manifest:
            return True, None
        
        manifest_path = Path(self.manifest_file)
        if not manifest_path.exists():
            return False, f"Manifest file not found: {self.manifest_file}"
        
        try:
            with open(manifest_path, 'r') as f:
                self._manifest = json.load(f)
            return True, None
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON in manifest: {str(e)}"
        except Exception as e:
            return False, f"Error loading manifest: {str(e)}"
    
    def verify_policy_hash(self) -> Tuple[bool, Optional[str]]:
        """Verify raw policy file hash"""
        success, error = self.load_raw_policy()
        if not success:
            return False, error
        
        raw_path = Path(self.raw_file)
        try:
            with open(raw_path, 'rb') as f:
                content = f.read()
            
            actual_hash = hashlib.sha256(content).hexdigest()
            
            # Handle hash format
            expected_hash = self.required_hash
            if expected_hash.startswith('sha256:'):
                expected_hash = expected_hash[7:]
            
            if actual_hash != expected_hash:
                return False, f"Hash verification failed. Expected: {expected_hash}, Got: {actual_hash}"
            
            self._verification_cache['hash_verified'] = True
            self._verification_cache['hash_value'] = actual_hash
            return True, None
            
        except Exception as e:
            return False, f"Error verifying hash: {str(e)}"
    
    def verify_manifest_integrity(self) -> Tuple[bool, Optional[str]]:
        """Verify manifest integrity against raw policy"""
        success, error = self.load_manifest()
        if not success:
            return False, error
        
        success, error = self.load_raw_policy()
        if not success:
            return False, error
        
        # Get hash from manifest
        manifest_hash = self._manifest.get('source_hash', '')
        if not manifest_hash:
            return False, "Manifest missing source_hash"
        
        # Extract hash value
        if manifest_hash.startswith('sha256:'):
            manifest_hash_value = manifest_hash[7:]
        else:
            manifest_hash_value = manifest_hash
        
        # Calculate actual hash
        raw_path = Path(self.raw_file)
        with open(raw_path, 'rb') as f:
            actual_hash = hashlib.sha256(f.read()).hexdigest()
        
        if actual_hash != manifest_hash_value:
            return False, "Manifest hash does not match raw policy"
        
        self._verification_cache['manifest_verified'] = True
        return True, None
    
    def check_authorization(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Full authorization gate check
        Returns: (is_authorized, details)
        """
        details = {
            'authorized': False,
            'checks': {
                'policy_loaded': False,
                'manifest_loaded': False,
                'hash_verified': False,
                'manifest_integrity_verified': False,
                'acknowledged': False,
                'kill_switch_disabled': False,
            },
            'errors': [],
            'warnings': [],
        }
        
        # Check kill switch first (safety first)
        if self.kill_switch_enabled:
            details['errors'].append("Kill switch is ENABLED - operations blocked")
            details['checks']['kill_switch_disabled'] = False
            return False, details
        
        details['checks']['kill_switch_disabled'] = True
        
        # Load and verify policy
        success, error = self.load_raw_policy()
        if not success:
            details['errors'].append(error)
            return False, details
        details['checks']['policy_loaded'] = True
        
        # Load manifest
        success, error = self.load_manifest()
        if not success:
            details['warnings'].append(error)  # Manifest is optional but recommended
        else:
            details['checks']['manifest_loaded'] = True
        
        # Verify hash
        success, error = self.verify_policy_hash()
        if not success:
            details['errors'].append(error)
        else:
            details['checks']['hash_verified'] = True
        
        # Verify manifest integrity (if manifest exists)
        if details['checks']['manifest_loaded']:
            success, error = self.verify_manifest_integrity()
            if not success:
                details['errors'].append(error)
            else:
                details['checks']['manifest_integrity_verified'] = True
        
        # Check acknowledgment
        if not self.acknowledged:
            details['errors'].append("Policy has NOT been acknowledged")
            details['warnings'].append("User must acknowledge policy before proceeding")
        else:
            details['checks']['acknowledged'] = True
        
        # Final authorization decision
        all_checks_passed = all([
            details['checks']['policy_loaded'],
            details['checks']['hash_verified'],
            details['checks']['acknowledged'],
            details['checks']['kill_switch_disabled'],
        ])
        
        details['authorized'] = all_checks_passed
        return all_checks_passed, details
    
    def get_scope(self) -> Dict[str, Any]:
        """Get scope from loaded policy"""
        if not self._raw_policy:
            self.load_raw_policy()
        
        if self._raw_policy:
            return self._raw_policy.get('scope', {})
        return {}
    
    def get_rules(self) -> Dict[str, Any]:
        """Get rules from loaded policy"""
        if not self._raw_policy:
            self.load_raw_policy()
        
        if self._raw_policy:
            return self._raw_policy.get('rules', {})
        return {}
    
    def reset(self):
        """Clear cached data"""
        self._raw_policy = None
        self._manifest = None
        self._verification_cache = {}
