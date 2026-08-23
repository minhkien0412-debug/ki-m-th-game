"""
Policy Engine Module
Evaluate policies and contracts for authorization
"""

import json
import hashlib
from typing import Dict, Any, Optional, Tuple
from pathlib import Path


class PolicyEngine:
    """Evaluate and enforce security policies"""
    
    def __init__(self, policy_config: Dict[str, Any]):
        self.raw_file = policy_config.get('raw_file', '')
        self.manifest_file = policy_config.get('manifest_file', '')
        self.required_hash = policy_config.get('required_hash', '')
        self.acknowledged = policy_config.get('acknowledged', False)
        self.kill_switch_enabled = policy_config.get('kill_switch_enabled', True)
        
        self.raw_policy: Optional[Dict[str, Any]] = None
        self.manifest: Optional[Dict[str, Any]] = None
    
    def load_policy(self) -> Tuple[bool, Optional[str]]:
        """Load and validate policy files"""
        # Load raw policy
        raw_path = Path(self.raw_file)
        if not raw_path.exists():
            return False, f"Raw policy file not found: {self.raw_file}"
        
        try:
            with open(raw_path, 'r') as f:
                self.raw_policy = json.load(f)
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON in raw policy: {str(e)}"
        except Exception as e:
            return False, f"Error loading raw policy: {str(e)}"
        
        # Load manifest
        manifest_path = Path(self.manifest_file)
        if not manifest_path.exists():
            return False, f"Manifest file not found: {self.manifest_file}"
        
        try:
            with open(manifest_path, 'r') as f:
                self.manifest = json.load(f)
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON in manifest: {str(e)}"
        except Exception as e:
            return False, f"Error loading manifest: {str(e)}"
        
        return True, None
    
    def verify_hash(self) -> Tuple[bool, Optional[str]]:
        """Verify policy file hash matches expected value"""
        if not self.raw_policy:
            return False, "Policy not loaded"
        
        if not self.required_hash:
            return False, "No required hash configured"
        
        # Read raw file content
        raw_path = Path(self.raw_file)
        try:
            with open(raw_path, 'rb') as f:
                content = f.read()
        except Exception as e:
            return False, f"Error reading policy file: {str(e)}"
        
        # Calculate hash
        if self.required_hash.startswith('sha256:'):
            expected_hash = self.required_hash[7:]  # Remove prefix
            actual_hash = hashlib.sha256(content).hexdigest()
        else:
            expected_hash = self.required_hash
            actual_hash = hashlib.sha256(content).hexdigest()
        
        if actual_hash != expected_hash:
            return False, f"Hash mismatch! Expected: {expected_hash}, Got: {actual_hash}"
        
        return True, None
    
    def verify_manifest_integrity(self) -> Tuple[bool, Optional[str]]:
        """Verify manifest matches raw policy"""
        if not self.manifest or not self.raw_policy:
            return False, "Policy or manifest not loaded"
        
        # Check if manifest source_hash matches raw file
        manifest_hash = self.manifest.get('source_hash', '')
        if not manifest_hash:
            return False, "Manifest missing source_hash"
        
        # Read raw file and calculate hash
        raw_path = Path(self.raw_file)
        try:
            with open(raw_path, 'rb') as f:
                content = f.read()
            actual_hash = hashlib.sha256(content).hexdigest()
            
            # Extract hash from manifest (remove sha256: prefix if present)
            if manifest_hash.startswith('sha256:'):
                manifest_hash_value = manifest_hash[7:]
            else:
                manifest_hash_value = manifest_hash
            
            if actual_hash != manifest_hash_value:
                return False, "Manifest hash does not match raw policy file"
        
        except Exception as e:
            return False, f"Error verifying manifest: {str(e)}"
        
        return True, None
    
    def check_acknowledgment(self) -> bool:
        """Check if policy has been acknowledged"""
        return self.acknowledged
    
    def check_kill_switch(self) -> bool:
        """Check if kill switch is active (blocks all operations)"""
        return self.kill_switch_enabled
    
    def evaluate_policy(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Full policy evaluation
        Returns: (is_authorized, evaluation_details)
        """
        details = {
            'policy_loaded': False,
            'hash_verified': False,
            'manifest_verified': False,
            'acknowledged': False,
            'kill_switch_active': False,
            'errors': [],
        }
        
        # Load policy
        success, error = self.load_policy()
        if not success:
            details['errors'].append(error)
            return False, details
        details['policy_loaded'] = True
        
        # Verify hash
        success, error = self.verify_hash()
        if not success:
            details['errors'].append(error)
        else:
            details['hash_verified'] = True
        
        # Verify manifest integrity
        success, error = self.verify_manifest_integrity()
        if not success:
            details['errors'].append(error)
        else:
            details['manifest_verified'] = True
        
        # Check acknowledgment
        details['acknowledged'] = self.check_acknowledgment()
        
        # Check kill switch
        details['kill_switch_active'] = self.check_kill_switch()
        
        # Authorization decision
        is_authorized = (
            details['policy_loaded'] and
            details['hash_verified'] and
            details['manifest_verified'] and
            details['acknowledged'] and
            not details['kill_switch_active']
        )
        
        return is_authorized, details
    
    def get_scope_from_policy(self) -> Dict[str, Any]:
        """Extract scope configuration from policy"""
        if not self.raw_policy:
            return {}
        
        return self.raw_policy.get('scope', {})
    
    def get_rules_from_policy(self) -> Dict[str, Any]:
        """Extract rules from policy"""
        if not self.raw_policy:
            return {}
        
        return self.raw_policy.get('rules', {})
