"""Regression tests for safety boundaries and secret handling."""

import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

from units.canonicalizer import Canonicalizer
from units.dns_ip_gate import DNSIPGate
from units.secret_redactor import SecretRedactor
from units.target_request_gate import TargetRequestGate


class FakeResponse:
    def __init__(self, status_code=200, location=None):
        self.status_code = status_code
        self.headers = {}
        if location is not None:
            self.headers['Location'] = location
        self.is_redirect = status_code in (301, 302, 303, 307, 308) and location is not None
        self.closed = False

    def close(self):
        self.closed = True


class TestAuthorizationBoundary(unittest.TestCase):
    def test_scan_stops_when_policy_is_not_authorized(self):
        result = subprocess.run(
            [sys.executable, 'command_center.py', '--config', 'config.yaml', '--scan'],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn('[BLOCKED]', result.stdout)
        self.assertNotIn('Mission ID:', result.stdout)


class TestHostValidation(unittest.TestCase):
    def setUp(self):
        self.canonicalizer = Canonicalizer(['*.example.com'], [], [])

    def test_wildcard_does_not_match_suffix_without_label_boundary(self):
        self.assertFalse(self.canonicalizer.is_host_allowed('evilexample.com'))
        self.assertTrue(self.canonicalizer.is_host_allowed('api.example.com'))
        self.assertTrue(self.canonicalizer.is_host_allowed('example.com'))

    def test_url_userinfo_is_rejected(self):
        valid, reason = self.canonicalizer.validate_url(
            'https://example.com@evilexample.com/path'
        )

        self.assertFalse(valid)
        self.assertIn('User information is not allowed', reason)

    def test_invalid_port_is_rejected(self):
        valid, reason = self.canonicalizer.validate_url(
            'https://example.com:not-a-port/path'
        )

        self.assertFalse(valid)
        self.assertEqual(reason, 'Invalid URL port')


class TestDNSIPGate(unittest.TestCase):
    def test_non_global_and_ipv4_mapped_loopback_addresses_are_blocked(self):
        gate = DNSIPGate()

        self.assertTrue(gate.is_private_ip('100.64.0.1'))
        self.assertTrue(gate.is_private_ip('::ffff:127.0.0.1'))
        self.assertFalse(gate.is_private_ip('8.8.8.8'))


class TestSecretRedaction(unittest.TestCase):
    def setUp(self):
        self.redactor = SecretRedactor()

    def test_patterns_without_capture_groups_do_not_crash(self):
        result = self.redactor.redact('JWT eyJabc.eyJdef.signature')
        self.assertEqual(result, 'JWT [REDACTED]')

    def test_bearer_prefix_is_preserved(self):
        result = self.redactor.redact('Bearer abcdefghijklmnopqrstuvwxyz1234')
        self.assertEqual(result, 'Bearer [REDACTED]')


class TestRequestGate(unittest.TestCase):
    def setUp(self):
        self.gate = TargetRequestGate({
            'target': {
                'allowed_hosts': ['example.com', 'example.net'],
                'allowed_paths': [],
                'blocked_paths': [],
            },
            'rate_limit': {
                'requests_per_second': 5,
                'requests_per_minute': 100,
                'concurrent_connections': 2,
            },
        })
        self.addCleanup(self.gate.close)

    def test_authorization_header_is_sent_to_initial_target(self):
        response = FakeResponse()
        self.gate.session.request = Mock(return_value=response)
        self.gate.validate_before_request = Mock(return_value=(True, None))

        returned = self.gate.get(
            'https://example.com/path',
            headers={'Authorization': 'Bearer real-secret'},
        )

        self.assertIs(returned, response)
        sent_headers = self.gate.session.request.call_args.kwargs['headers']
        self.assertEqual(sent_headers['Authorization'], 'Bearer real-secret')

    def test_redirect_is_blocked_when_new_target_fails_validation(self):
        redirect = FakeResponse(302, 'https://blocked.example/private')
        self.gate.session.request = Mock(return_value=redirect)
        self.gate.validate_before_request = Mock(side_effect=[
            (True, None),
            (False, 'Host not allowed'),
        ])

        returned = self.gate.get('https://example.com/path')

        self.assertIsNone(returned)
        self.assertTrue(redirect.closed)
        self.assertEqual(self.gate.session.request.call_count, 1)

    def test_sensitive_headers_are_removed_on_cross_host_redirect(self):
        redirect = FakeResponse(302, 'https://example.net/next')
        final = FakeResponse()
        self.gate.session.request = Mock(side_effect=[redirect, final])
        self.gate.validate_before_request = Mock(return_value=(True, None))

        returned = self.gate.get(
            'https://example.com/start',
            headers={'authorization': 'Bearer real-secret', 'X-Test': 'ok'},
        )

        self.assertIs(returned, final)
        redirected_headers = self.gate.session.request.call_args_list[1].kwargs['headers']
        self.assertNotIn('authorization', redirected_headers)
        self.assertEqual(redirected_headers['X-Test'], 'ok')

    def test_each_request_passes_through_rate_limiter(self):
        self.gate.session.request = Mock(return_value=FakeResponse())
        self.gate.validate_before_request = Mock(return_value=(True, None))

        with patch.object(self.gate, '_wait_for_rate_limit') as limiter:
            self.gate.get('https://example.com/path')

        limiter.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
