"""
Integration Tests for CyberArmy V10.7.15
"""

import unittest
from pathlib import Path
import yaml


class TestMissionFlow(unittest.TestCase):
    """Test complete mission flow"""
    
    def setUp(self):
        """Set up test fixtures"""
        with open('config.yaml', 'r') as f:
            self.config = yaml.safe_load(f)
    
    def test_mission_creation(self):
        """Test mission creation and storage"""
        from units.mission_store import MissionStore
        
        store = MissionStore('state/test_mission_store.sqlite')
        mission_id = store.create_mission('Test Target', 'https://test.com')
        
        self.assertTrue(mission_id.startswith('MISSION-'))
        
        # Retrieve mission
        mission = store.get_mission(mission_id)
        self.assertIsNotNone(mission)
        self.assertEqual(mission['target_name'], 'Test Target')
    
    def test_finding_management(self):
        """Test finding creation and retrieval"""
        from units.finding_engine import FindingEngine
        
        engine = FindingEngine({})
        
        finding_id = engine.create_finding(
            finding_type='xss',
            title='Test XSS Finding',
            severity='high',
            url='https://test.com/page',
            description='Test description'
        )
        
        self.assertTrue(finding_id.startswith('FINDING-'))
        
        finding = engine.get_finding(finding_id)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'high')
    
    def test_report_generation(self):
        """Test report generation"""
        from units.report_generator import ReportGenerator
        
        gen = ReportGenerator({'reporting': {'output_dir': 'state/reports'}})
        
        findings = [
            {
                'id': 'TEST-001',
                'type': 'xss',
                'title': 'Test Finding',
                'severity': 'high',
                'status': 'new',
                'url': 'https://test.com'
            }
        ]
        
        report = gen.generate_report({'mission_id': 'TEST'}, findings)
        
        self.assertIn('CyberArmy Security Assessment Report', report)
        self.assertIn('Test Finding', report)


if __name__ == '__main__':
    unittest.main()
