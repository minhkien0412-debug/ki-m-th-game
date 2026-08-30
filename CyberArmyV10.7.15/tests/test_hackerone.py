"""Tests for the fail-closed HackerOne workflow."""

import unittest
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from units.hackerone_engagement import EngagementError, HackerOneEngagement
from units.hackerone_report import HackerOneReportBuilder
from units.hackerone_runner import HackerOneRunner


def valid_config():
    return {
        'hackerone': {
            'enabled': True,
            'program_handle': 'playstation',
            'policy_url': 'https://hackerone.com/playstation/policy_scopes',
            'researcher_handle': 'ethical-researcher',
            'acknowledged_current_policy': True,
            'human_in_the_loop': True,
            'scope_reviewed_at': datetime.now(timezone.utc).isoformat(),
            'scope_max_age_days': 1,
            'scope_assets': [
                {
                    'type': 'domain',
                    'identifier': 'in-scope.example',
                    'eligible_for_submission': True,
                    'allowed_actions': ['passive_recon', 'reporting'],
                },
                {
                    'type': 'domain',
                    'identifier': '*.in-scope.example',
                    'eligible_for_submission': True,
                    'allowed_actions': [
                        'passive_recon', 'http_get', 'http_head',
                        'manual_validation', 'reporting',
                    ],
                },
                {
                    'type': 'url',
                    'identifier': 'https://exact.example/api',
                    'eligible_for_submission': True,
                    'allowed_actions': ['http_get', 'http_head', 'reporting'],
                },
                {
                    'type': 'hardware',
                    'identifier': 'PlayStation Test Device',
                    'eligible_for_submission': True,
                    'allowed_actions': ['manual_validation', 'reporting'],
                },
            ],
        }
    }


class TestHackerOneEngagement(unittest.TestCase):
    def test_valid_profile_and_domain_boundary(self):
        engagement = HackerOneEngagement(valid_config())
        valid, errors, _ = engagement.validate_profile()

        self.assertTrue(valid, errors)
        self.assertIsNotNone(engagement.find_scope_asset('https://api.in-scope.example/path'))
        self.assertIsNone(engagement.find_scope_asset('https://evilin-scope.example/path'))
        self.assertFalse(
            HackerOneEngagement._domain_matches('in-scope.example', '*.in-scope.example')
        )

    def test_url_scope_is_limited_to_origin_and_path(self):
        engagement = HackerOneEngagement(valid_config())

        self.assertIsNotNone(engagement.find_scope_asset('https://exact.example/api/v1'))
        self.assertIsNone(engagement.find_scope_asset('https://exact.example/admin'))
        self.assertIsNone(engagement.find_scope_asset('http://exact.example/api'))

    def test_hardware_requires_an_exact_scope_name(self):
        engagement = HackerOneEngagement(valid_config())

        asset = engagement.authorize('manual_validation', 'PlayStation Test Device')
        self.assertEqual(asset['type'], 'hardware')
        with self.assertRaises(EngagementError):
            engagement.authorize('manual_validation', 'PlayStation Device')

    def test_stale_scope_blocks_every_action(self):
        config = valid_config()
        config['hackerone']['scope_reviewed_at'] = (
            datetime.now(timezone.utc) - timedelta(days=2)
        ).isoformat()

        with self.assertRaisesRegex(EngagementError, 'stale'):
            HackerOneEngagement(config).authorize(
                'http_get', 'https://api.in-scope.example/path'
            )

    def test_dangerous_and_unknown_actions_are_blocked(self):
        engagement = HackerOneEngagement(valid_config())

        with self.assertRaisesRegex(EngagementError, 'always forbidden'):
            engagement.authorize('dos', 'https://api.in-scope.example/path')
        with self.assertRaisesRegex(EngagementError, 'not allowlisted'):
            engagement.authorize('sql_injection', 'https://api.in-scope.example/path')

    def test_profile_rejects_forbidden_actions_even_when_configured(self):
        config = valid_config()
        config['hackerone']['scope_assets'][0]['allowed_actions'].append('dos')

        valid, errors, _ = HackerOneEngagement(config).validate_profile()

        self.assertFalse(valid)
        self.assertTrue(any('forbidden action: dos' in error for error in errors))


class TestHackerOneReport(unittest.TestCase):
    def finding(self):
        return {
            'title': 'Confirmed authorization boundary issue',
            'asset': 'https://api.in-scope.example/path',
            'weakness': 'CWE-862: Missing Authorization',
            'suggested_severity': 'medium',
            'summary': 'A test account can access an object it does not own.',
            'steps_to_reproduce': ['Create two owned test accounts.', 'Request the object as account B.'],
            'observed_result': 'Account B receives account A data.',
            'expected_result': 'The request should be denied.',
            'impact': 'An attacker could read another account object.',
            'evidence': ['api_key=abcdefghijklmnopqrstuvwxyz123456'],
            'remediation': 'Check object ownership on every request.',
            'manual_validation_confirmed': True,
            'contains_third_party_data': False,
        }

    def test_report_requires_manual_confirmation(self):
        finding = self.finding()
        finding['manual_validation_confirmed'] = False

        valid, errors = HackerOneReportBuilder(valid_config()).validate_finding(finding)

        self.assertFalse(valid)
        self.assertIn('manual_validation_confirmed must be true', errors)

    def test_report_is_redacted_and_never_submitted(self):
        report = HackerOneReportBuilder(valid_config()).build_markdown(self.finding())

        self.assertIn('api_key=[REDACTED]', report)
        self.assertNotIn('abcdefghijklmnopqrstuvwxyz123456', report)
        self.assertIn('submit it manually through HackerOne', report)

    def test_report_rejects_multiline_raw_evidence(self):
        finding = self.finding()
        finding['evidence'] = ['raw response\nwith production data']

        valid, errors = HackerOneReportBuilder(valid_config()).validate_finding(finding)

        self.assertFalse(valid)
        self.assertIn(
            'Evidence items must be short, single-line sanitized references', errors
        )


class TestHackerOneRunner(unittest.TestCase):
    def test_passive_recon_filters_every_result_against_scope(self):
        runner = HackerOneRunner(valid_config())
        fake_recon = Mock()
        fake_recon.run_passive_recon.return_value = {
            'subdomains': [
                'api.in-scope.example',
                'evilin-scope.example',
                'out-of-scope.example',
            ]
        }

        with patch('units.hackerone_runner.ReconEngine', return_value=fake_recon):
            result = runner.passive_recon('in-scope.example')

        self.assertEqual(result['in_scope_subdomains'], ['api.in-scope.example'])
        fake_recon.close.assert_called_once_with()

    def test_head_observation_collects_no_body_and_redacts_headers(self):
        response = Mock()
        response.status_code = 302
        response.headers = {
            'Set-Cookie': 'session=very-secret',
            'Location': 'https://api.in-scope.example/next?token=abcdefghijklmnopqrstuvwxyz',
        }
        fake_gate = Mock()
        fake_gate.head.return_value = response

        with tempfile.TemporaryDirectory() as temp_dir:
            config = valid_config()
            config['hackerone']['observation_output_dir'] = temp_dir
            runner = HackerOneRunner(config)
            with patch('units.hackerone_runner.TargetRequestGate', return_value=fake_gate):
                result = runner.observe_head('https://api.in-scope.example/path')

            self.assertTrue(Path(result['saved_to']).exists())

        self.assertEqual(result['headers']['Set-Cookie'], '[REDACTED]')
        self.assertNotIn('abcdefghijklmnopqrstuvwxyz', result['headers']['Location'])
        self.assertFalse(result['body_collected'])
        self.assertFalse(result['redirect_followed'])
        fake_gate.head.assert_called_once_with(
            'https://api.in-scope.example/path', timeout=10, allow_redirects=False
        )
        fake_gate.close.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
