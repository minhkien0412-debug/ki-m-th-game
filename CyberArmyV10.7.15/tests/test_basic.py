"""
Basic Tests for CyberArmy V10.7.15
"""

import unittest
from pathlib import Path


class TestConfigValidator(unittest.TestCase):
    """Test configuration validator"""
    
    def test_config_file_exists(self):
        """Test that config.yaml exists"""
        config_path = Path('config.yaml')
        self.assertTrue(config_path.exists())
    
    def test_policy_files_exist(self):
        """Test that policy files exist"""
        raw_policy = Path('policies/raw/banco_plata_policy.json')
        manifest = Path('policies/manifest/banco_plata_manifest.json')
        
        self.assertTrue(raw_policy.exists())
        self.assertTrue(manifest.exists())


class TestCanonicalizer(unittest.TestCase):
    """Test URL canonicalizer"""
    
    def test_normalize_url(self):
        """Test URL normalization"""
        from units.canonicalizer import Canonicalizer
        
        canon = Canonicalizer(
            allowed_hosts=['example.com'],
            allowed_paths=['/api/*'],
            blocked_paths=[]
        )
        
        normalized = canon.normalize_url('https://EXAMPLE.COM/API/test')
        self.assertEqual(normalized, 'https://example.com/API/test')
    
    def test_host_allowed(self):
        """Test host allowlist"""
        from units.canonicalizer import Canonicalizer
        
        canon = Canonicalizer(
            allowed_hosts=['*.example.com', 'test.com'],
            allowed_paths=[],
            blocked_paths=[]
        )
        
        self.assertTrue(canon.is_host_allowed('sub.example.com'))
        self.assertTrue(canon.is_host_allowed('example.com'))
        self.assertTrue(canon.is_host_allowed('test.com'))
        self.assertFalse(canon.is_host_allowed('evil.com'))


class TestScopeEngine(unittest.TestCase):
    """Test scope engine"""
    
    def test_scope_validation(self):
        """Test scope validation"""
        from units.scope_engine import ScopeEngine
        
        config = {
            'target': {
                'allowed_hosts': ['example.com'],
                'allowed_paths': ['/api/*'],
                'blocked_paths': ['/admin/*']
            }
        }
        
        engine = ScopeEngine(config)
        
        in_scope, reason = engine.is_url_in_scope('https://example.com/api/test')
        self.assertTrue(in_scope)
        
        out_of_scope, reason = engine.is_url_in_scope('https://evil.com/api/test')
        self.assertFalse(out_of_scope)


if __name__ == '__main__':
    unittest.main()
